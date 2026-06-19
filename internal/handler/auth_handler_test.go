package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func SetupRouter(t *testing.T) (*gin.Engine, *AuthHandler) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	// mock OAuth service or pass nil if not needed for these tests
	authHandler := NewAuthHandler(authService, nil, nil)

	t.Cleanup(func() { mr.Close() }) // Ensure mr is closed after tests in this Setup config

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(gin.Recovery())

	// Register routes manually or use a helper that doesn't require full server setup
	// For testing, we just register what we need
	return r, authHandler
}

func TestAuthHandler_Register(t *testing.T) {
	r, h := SetupRouter(t)
	r.POST("/api/auth/register", h.Register)

	reqBody := dto.RegisterRequest{
		Email:     "api_test@example.com",
		Password:  "Password123!",
		FirstName: "API",
		LastName:  "Test",
	}
	body, _ := json.Marshal(reqBody)

	req, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	// Assert response body contains success
}

func TestAuthHandler_Login(t *testing.T) {
	r, h := SetupRouter(t)
	r.POST("/api/auth/register", h.Register)
	r.POST("/api/auth/login", h.Login)

	// 1. Register first
	regBody := dto.RegisterRequest{
		Email:     "login_api@example.com",
		Password:  "Password123!",
		FirstName: "Login",
		LastName:  "Test",
	}
	b, _ := json.Marshal(regBody)
	regReq, _ := http.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBuffer(b))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	r.ServeHTTP(regW, regReq)
	assert.Equal(t, http.StatusCreated, regW.Code)

	// 2. Login
	loginBody := dto.LoginRequest{
		Email:    "login_api@example.com",
		Password: "Password123!",
	}
	b2, _ := json.Marshal(loginBody)
	req, _ := http.NewRequest(http.MethodPost, "/api/auth/login", bytes.NewBuffer(b2))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	// Check for token
	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	assert.NotEmpty(t, data["accessToken"])
}

// TODO: Add tests for Protected Routes using middleware

func TestAuthHandler_GetSessions_CurrentSessionFlag(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	authHandler := NewAuthHandler(authService, nil, nil)

	cfg := &config.Config{
		JWT: config.JWTConfig{
			AccessSecret:  "secret",
			RefreshSecret: "refresh-secret",
		},
	}
	tokenService := service.NewTokenService(cfg)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cacheService := service.NewCacheService(rdb)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuthMiddleware(tokenService, cacheService))

	r.GET("/api/auth/sessions", authHandler.GetSessions)

	// Create user
	regReq := &dto.RegisterRequest{
		Email:     "sessions@example.com",
		Password:  "Password123!",
		FirstName: "Session",
		LastName:  "Test",
	}

	_, err := authService.Register(regReq)
	assert.NoError(t, err)

	// Create a session via login
	loginResp, err := authService.Login(
		&dto.LoginRequest{
			Email:    "sessions@example.com",
			Password: "Password123!",
		},
		"127.0.0.1",
		"test-agent",
	)

	assert.NoError(t, err)

	claims, err := tokenService.ValidateAccessToken(loginResp.AccessToken)
	assert.NoError(t, err)

	expectedSessionID := claims.SessionID

	// Call sessions endpoint using the access token
	req, _ := http.NewRequest(
		http.MethodGet,
		"/api/auth/sessions",
		nil,
	)

	req.Header.Set(
		"Authorization",
		"Bearer "+loginResp.AccessToken,
	)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	data := resp["data"].([]interface{})

	foundExpectedSession := false

	for _, item := range data {
		session := item.(map[string]interface{})

		sessionID := session["id"].(string)
		isCurrent := session["isCurrent"].(bool)

		if sessionID == expectedSessionID {
			assert.True(t, isCurrent, "expected session used by request token to be current")
			foundExpectedSession = true
		}
	}

	assert.True(t, foundExpectedSession, "expected session ID not found in response")

}

func TestAuthHandler_GetSessions_NoSessionIDInContext(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	authHandler := NewAuthHandler(authService, nil, nil)

	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Register user
	regReq := &dto.RegisterRequest{
		Email:     "nosession@example.com",
		Password:  "Password123!",
		FirstName: "No",
		LastName:  "Session",
	}

	user, err := authService.Register(regReq)
	assert.NoError(t, err)

	userID := user.ID

	// Intentionally set only userID, not sessionID
	r.GET("/api/auth/sessions", func(c *gin.Context) {
		c.Set("userID", userID)
		authHandler.GetSessions(c)
	})

	// Create a session
	_, err = authService.Login(
		&dto.LoginRequest{
			Email:    regReq.Email,
			Password: regReq.Password,
		},
		"127.0.0.1",
		"test-agent",
	)
	assert.NoError(t, err)

	req, _ := http.NewRequest(
		http.MethodGet,
		"/api/auth/sessions",
		nil,
	)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)

	data := resp["data"].([]interface{})
	assert.NotEmpty(t, data, "expected at least one session after login")

	for _, item := range data {
		session := item.(map[string]interface{})

		assert.False(
			t,
			session["isCurrent"].(bool),
			"expected no session to be marked current when sessionID is missing",
		)
	}
}

func TestAuthHandler_OAuthRedirectFlow(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	clientRepo := repository.NewOAuthClientRepository(db)
	codeRepo := repository.NewAuthorizationCodeRepository(db)
	tokenRepo := repository.NewOAuthTokenRepository(db)
	consentRepo := repository.NewUserConsentRepository(db)
	configRepo := repository.NewOAuthProviderConfigRepository(db)
	cfg := &config.Config{}
	tokenService := service.NewTokenService(cfg)
	oauthProviderService := service.NewOAuthProviderService(
		clientRepo, codeRepo, tokenRepo, consentRepo, configRepo, tokenService, cfg,
	)

	client, _, err := oauthProviderService.CreateClient("Test Client", []string{"http://localhost:5173/callback"}, []string{"read:profile"}, "user-1", true)
	assert.NoError(t, err)

	h := NewAuthHandler(authService, nil, oauthProviderService)
	gin.SetMode(gin.TestMode)

	executeReq := func(r *gin.Engine, path string) *httptest.ResponseRecorder {
		req, _ := http.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	t.Run("storeOAuthRedirect stores valid URI", func(t *testing.T) {
		r := gin.New()
		r.GET("/test-store", func(c *gin.Context) {
			err := h.storeOAuthRedirect(c, client.ClientID, "http://localhost:5173/callback")
			if err != nil {
				c.Status(http.StatusBadRequest)
			} else {
				c.Status(http.StatusOK)
			}
		})

		w := executeReq(r, "/test-store")

		assert.Equal(t, http.StatusOK, w.Code)
		cookieFound := false
		for _, c := range w.Result().Cookies() {
			if c.Name == "oauth_redirect" {
				val, _ := url.QueryUnescape(c.Value)
				assert.Equal(t, "http://localhost:5173/callback", val)
				cookieFound = true
			}
		}
		assert.True(t, cookieFound)
	})

	t.Run("storeOAuthRedirect rejects invalid URI", func(t *testing.T) {
		r := gin.New()
		r.GET("/test-store", func(c *gin.Context) {
			err := h.storeOAuthRedirect(c, client.ClientID, "http://attacker.com/callback")
			if err != nil {
				c.Status(http.StatusBadRequest)
			} else {
				c.Status(http.StatusOK)
			}
		})

		w := executeReq(r, "/test-store")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("completeOAuthLogin with valid cookie redirects", func(t *testing.T) {
		r := gin.New()
		r.GET("/test-complete", func(c *gin.Context) {
			c.Request.AddCookie(&http.Cookie{
				Name:  "oauth_redirect",
				Value: "http://localhost:5173/callback",
			})
			resp := &dto.LoginResponse{AccessToken: "acc123", RefreshToken: "ref123"}
			h.completeOAuthLogin(c, resp, client.ClientID)
		})

		w := executeReq(r, "/test-complete")

		assert.Equal(t, http.StatusFound, w.Code)
		loc := w.Header().Get("Location")
		parsed, _ := url.Parse(loc)
		assert.Equal(t, "http://localhost:5173/callback", parsed.Scheme+"://"+parsed.Host+parsed.Path)
		assert.Equal(t, "acc123", parsed.Query().Get("access_token"))
		assert.Equal(t, "ref123", parsed.Query().Get("refresh_token"))
	})

	t.Run("completeOAuthLogin invalidates bad cookie", func(t *testing.T) {
		r := gin.New()
		r.GET("/test-complete", func(c *gin.Context) {
			c.Request.AddCookie(&http.Cookie{
				Name:  "oauth_redirect",
				Value: "http://attacker.com/bad",
			})
			resp := &dto.LoginResponse{AccessToken: "acc123", RefreshToken: "ref123"}
			h.completeOAuthLogin(c, resp, client.ClientID)
		})

		w := executeReq(r, "/test-complete")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("completeOAuthLogin blocks non-http scheme", func(t *testing.T) {
		r := gin.New()
		r.GET("/test-complete", func(c *gin.Context) {
			c.Request.AddCookie(&http.Cookie{
				Name:  "oauth_redirect",
				Value: "javascript:alert(1)",
			})
			resp := &dto.LoginResponse{AccessToken: "acc123"}
			h.completeOAuthLogin(c, resp, client.ClientID)
		})

		w := executeReq(r, "/test-complete")
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("completeOAuthLogin fallback to JSON", func(t *testing.T) {
		r := gin.New()
		r.GET("/test-complete", func(c *gin.Context) {
			resp := &dto.LoginResponse{AccessToken: "acc123"}
			h.completeOAuthLogin(c, resp, client.ClientID)
		})

		w := executeReq(r, "/test-complete")

		assert.Equal(t, http.StatusOK, w.Code)
		var b map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &b)
		assert.True(t, b["success"].(bool))
	})
}

func TestAuthHandler_GetAuditLogs(t *testing.T) {
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	authHandler := NewAuthHandler(authService, nil, nil)

	gin.SetMode(gin.TestMode)

	user, err := authService.Register(&dto.RegisterRequest{
		Email:     "audit_logs@example.com",
		Password:  "Password123!",
		FirstName: "Audit",
		LastName:  "Logs",
	})

	assert.NoError(t, err)

	tests := []struct {
		name       string
		userID     interface{}
		query      string
		wantStatus int
	}{
		{
			name:       "should return unauthorized when userID is missing",
			userID:     nil,
			query:      "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "should return unauthorized when userID type is invalid",
			userID:     12345,
			query:      "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "should return audit logs with default pagination",
			userID:     user.ID,
			query:      "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "should return audit logs with custom pagination",
			userID:     user.ID,
			query:      "?page=2&limit=5",
			wantStatus: http.StatusOK,
		},
		{
			name:       "should return bad request for invalid page",
			userID:     user.ID,
			query:      "?page=abc",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "should return bad request for invalid limit",
			userID:     user.ID,
			query:      "?limit=abc",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "should use default page when page is less than one",
			userID:     user.ID,
			query:      "?page=-1",
			wantStatus: http.StatusOK,
		},
		{
			name:       "should use default limit when limit is less than one",
			userID:     user.ID,
			query:      "?limit=-5",
			wantStatus: http.StatusOK,
		},
		{
			name:       "should cap limit when it exceeds maximum value",
			userID:     user.ID,
			query:      "?limit=200",
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()

			r.GET("/api/auth/audit-logs", func(c *gin.Context) {
				if tt.userID != nil {
					c.Set("userID", tt.userID)
				}

				authHandler.GetAuditLogs(c)
			})

			req, err := http.NewRequest(
				http.MethodGet,
				"/api/auth/audit-logs"+tt.query,
				nil,
			)

			assert.NoError(t, err)

			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)

			if tt.wantStatus == http.StatusOK {
				var response map[string]interface{}

				err := json.Unmarshal(w.Body.Bytes(), &response)

				assert.NoError(t, err)
				assert.True(t, response["success"].(bool))
				assert.NotNil(t, response["data"])
			}
		})
	}
}
