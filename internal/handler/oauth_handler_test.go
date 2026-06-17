package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
        "testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
        "golang.org/x/crypto/bcrypt"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
        "github.com/lib/pq"
)

func setupOAuthUserInfoRouter(t *testing.T) (*gin.Engine, *repository.UserRepository, *repository.OAuthTokenRepository) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewOAuthTokenRepository(db)
	oauthProviderService := service.NewOAuthProviderService(
		repository.NewOAuthClientRepository(db),
		repository.NewAuthorizationCodeRepository(db),
		tokenRepo,
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(&config.Config{
			JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		}),
		&config.Config{},
	)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/oauth/userinfo", handler.NewOAuthHandler(oauthProviderService, userRepo).UserInfo)

	return r, userRepo, tokenRepo
}

func createOAuthAccessToken(t *testing.T, tokenRepo *repository.OAuthTokenRepository, userID string, scopes []string) string {
	token := "oauth-token-" + uuid.NewString()
	err := tokenRepo.Create(&models.OAuthAccessToken{
		ID:        uuid.NewString(),
		Token:     token,
		ClientID:  uuid.NewString(),
		UserID:    userID,
		Scopes:    models.StringArray(scopes),
		ExpiresAt: time.Now().Add(time.Hour),
	})
	require.NoError(t, err)
	return token
}

func performUserInfoRequest(r *gin.Engine, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestNewOAuthHandlerPanicsWithoutUserRepository(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	tokenRepo := repository.NewOAuthTokenRepository(db)
	oauthProviderService := service.NewOAuthProviderService(
		repository.NewOAuthClientRepository(db),
		repository.NewAuthorizationCodeRepository(db),
		tokenRepo,
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(&config.Config{
			JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		}),
		&config.Config{},
	)

	require.Panics(t, func() {
		handler.NewOAuthHandler(oauthProviderService, nil)
	})
}

func TestOAuthAccessTokenScopesSerializeAsJSONInSQLite(t *testing.T) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	tokenRepo := repository.NewOAuthTokenRepository(db)
	token := createOAuthAccessToken(t, tokenRepo, uuid.NewString(), []string{"read:profile", "read:email"})

	var storedScopes string
	require.NoError(t, db.Table("oauth_access_tokens").Select("scopes").Where("token = ?", token).Scan(&storedScopes).Error)
	assert.JSONEq(t, `["read:profile","read:email"]`, storedScopes)
}

func TestOAuthHandler_UserInfoReturnsUserFields(t *testing.T) {
	r, userRepo, tokenRepo := setupOAuthUserInfoRouter(t)

	user := &models.User{
		Email:         "oauth-user@example.com",
		PasswordHash:  "hash",
		FirstName:     "OAuth",
		LastName:      "User",
		EmailVerified: true,
		ProfileImage:  "https://example.com/avatar.png",
	}
	require.NoError(t, userRepo.Create(user))

	token := createOAuthAccessToken(t, tokenRepo, user.ID, []string{"read:profile", "read:email"})
	w := performUserInfoRequest(r, token)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, user.ID, response["sub"])
	assert.Equal(t, user.Email, response["email"])
	assert.Equal(t, true, response["email_verified"])
	assert.Equal(t, "OAuth User", response["name"])
	assert.Equal(t, user.FirstName, response["given_name"])
	assert.Equal(t, user.LastName, response["family_name"])
	assert.Equal(t, user.ProfileImage, response["picture"])
	assert.ElementsMatch(t, []interface{}{"read:profile", "read:email"}, response["scopes"])
}

func TestOAuthHandler_UserInfoOmitsEmailFieldsWithoutEmailScope(t *testing.T) {
	r, userRepo, tokenRepo := setupOAuthUserInfoRouter(t)

	user := &models.User{
		Email:         "oauth-profile@example.com",
		PasswordHash:  "hash",
		FirstName:     "Profile",
		LastName:      "Only",
		EmailVerified: true,
		ProfileImage:  "https://example.com/profile.png",
	}
	require.NoError(t, userRepo.Create(user))

	token := createOAuthAccessToken(t, tokenRepo, user.ID, []string{"read:profile"})
	w := performUserInfoRequest(r, token)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, user.ID, response["sub"])
	assert.Equal(t, "Profile Only", response["name"])
	assert.Equal(t, user.FirstName, response["given_name"])
	assert.Equal(t, user.LastName, response["family_name"])
	assert.Equal(t, user.ProfileImage, response["picture"])
	assert.NotContains(t, response, "email")
	assert.NotContains(t, response, "email_verified")
	assert.ElementsMatch(t, []interface{}{"read:profile"}, response["scopes"])
}

func TestOAuthHandler_UserInfoOmitsProfileFieldsWithoutProfileScope(t *testing.T) {
	r, userRepo, tokenRepo := setupOAuthUserInfoRouter(t)

	user := &models.User{
		Email:         "oauth-email@example.com",
		PasswordHash:  "hash",
		FirstName:     "Email",
		LastName:      "Only",
		EmailVerified: true,
		ProfileImage:  "https://example.com/email.png",
	}
	require.NoError(t, userRepo.Create(user))

	token := createOAuthAccessToken(t, tokenRepo, user.ID, []string{"read:email"})
	w := performUserInfoRequest(r, token)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, user.ID, response["sub"])
	assert.Equal(t, user.Email, response["email"])
	assert.Equal(t, true, response["email_verified"])
	assert.NotContains(t, response, "name")
	assert.NotContains(t, response, "given_name")
	assert.NotContains(t, response, "family_name")
	assert.NotContains(t, response, "picture")
	assert.ElementsMatch(t, []interface{}{"read:email"}, response["scopes"])
}

func TestOAuthHandler_UserInfoKeepsEmailVerifiedWhenEmailIsEmpty(t *testing.T) {
	r, userRepo, tokenRepo := setupOAuthUserInfoRouter(t)

	user := &models.User{
		PasswordHash:        "hash",
		FirstName:           "Email",
		LastName:            "Verified",
		EmailVerified:       true,
		OAuthProvider:       "local",
		FailedLoginAttempts: 0,
	}
	require.NoError(t, userRepo.Create(user))

	token := createOAuthAccessToken(t, tokenRepo, user.ID, []string{"read:email"})
	w := performUserInfoRequest(r, token)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, user.ID, response["sub"])
	assert.NotContains(t, response, "email")
	assert.Equal(t, true, response["email_verified"])
}

func TestOAuthHandler_UserInfoReturnsOnlyBaseFieldsWithoutScopes(t *testing.T) {
	r, userRepo, tokenRepo := setupOAuthUserInfoRouter(t)

	user := &models.User{
		Email:         "oauth-base@example.com",
		PasswordHash:  "hash",
		FirstName:     "Base",
		LastName:      "Only",
		EmailVerified: true,
		ProfileImage:  "https://example.com/base.png",
	}
	require.NoError(t, userRepo.Create(user))

	token := createOAuthAccessToken(t, tokenRepo, user.ID, []string{})
	w := performUserInfoRequest(r, token)

	assert.Equal(t, http.StatusOK, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, user.ID, response["sub"])
	scopes, exists := response["scopes"]
	assert.True(t, exists)
	if scopes != nil {
		assert.Empty(t, scopes)
	}
	assert.NotContains(t, response, "email")
	assert.NotContains(t, response, "email_verified")
	assert.NotContains(t, response, "name")
	assert.NotContains(t, response, "given_name")
	assert.NotContains(t, response, "family_name")
	assert.NotContains(t, response, "picture")
}

func TestOAuthHandler_UserInfoHandlesMissingUser(t *testing.T) {
	r, _, tokenRepo := setupOAuthUserInfoRouter(t)

	token := createOAuthAccessToken(t, tokenRepo, uuid.NewString(), []string{"read:profile", "read:email"})
	w := performUserInfoRequest(r, token)

	assert.Equal(t, http.StatusNotFound, w.Code)

	var response map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "user_not_found", response["error"])
}

func TestOAuthHandler_UserInfo_ErrorCases(t *testing.T) {
	tests := []struct {
		name           string
		authHeader     string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "missing authorization header",
			authHeader:     "",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "missing_token",
		},
		{
			name:           "invalid token format without bearer prefix",
			authHeader:     "InvalidFormatToken",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid_token_format",
		},
		{
			name:           "invalid or fake token",
			authHeader:     "Bearer this-is-a-fake-token",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "invalid access token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _, _ := setupOAuthUserInfoRouter(t)

			req := httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			var response map[string]interface{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
			assert.Equal(t, tt.expectedError, response["error"])
		})
	}
}

func setupTokenRouter(t *testing.T) (*gin.Engine, *repository.OAuthClientRepository, *repository.AuthorizationCodeRepository) {
	_, db, mr := testutils.SetupIntegrationTest(t)
	t.Cleanup(func() { mr.Close() })

	clientRepo := repository.NewOAuthClientRepository(db)
	codeRepo := repository.NewAuthorizationCodeRepository(db)
	tokenRepo := repository.NewOAuthTokenRepository(db)
	userRepo := repository.NewUserRepository(db)

	oauthProviderService := service.NewOAuthProviderService(
		clientRepo,
		codeRepo,
		tokenRepo,
		repository.NewUserConsentRepository(db),
		repository.NewOAuthProviderConfigRepository(db),
		service.NewTokenService(&config.Config{
			JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		}),
		&config.Config{},
	)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/oauth/token", handler.NewOAuthHandler(oauthProviderService, userRepo).Token)
	return r, clientRepo, codeRepo
}

func TestToken_PublicClient_MissingVerifier_Rejected(t *testing.T) {
	r, clientRepo, codeRepo := setupTokenRouter(t)

	// seed a public client
	clientID := uuid.NewString()
	err := clientRepo.Create(&models.OAuthClient{
		ID:           uuid.NewString(),
		Name:         "public-app",
		ClientID:     clientID,
		ClientSecret: "unused",
		RedirectURIs: pq.StringArray{"http://localhost/cb"},
                Scopes:       pq.StringArray{"read:profile"},
		IsActive:     true,
		IsPublic:     true,
	})
	require.NoError(t, err)

	// seed a valid auth code with a PKCE challenge
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	code := uuid.NewString()
	err = codeRepo.Create(&models.AuthorizationCode{
		ID:                  uuid.NewString(),
		Code:                code,
		ClientID:            clientID,
		UserID:              uuid.NewString(),
		RedirectURI:        "http://localhost/cb",
		Scopes:              pq.StringArray{"read:profile"},
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CodeChallenge:       &challenge,
		CodeChallengeMethod: stringPtr("S256"),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code="+code+"&client_id="+clientID+"&redirect_uri=http://localhost/cb"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_request", resp["error"])
}

func TestToken_ConfidentialClient_MissingSecret_Rejected(t *testing.T) {
	r, clientRepo, codeRepo := setupTokenRouter(t)

	clientID := uuid.NewString()
	hashedSecret, _ := bcrypt.GenerateFromPassword([]byte("supersecret"), bcrypt.DefaultCost)
	err := clientRepo.Create(&models.OAuthClient{
		ID:           uuid.NewString(),
		Name:         "confidential-app",
		ClientID:     clientID,
		ClientSecret: string(hashedSecret),
		RedirectURIs: pq.StringArray{"http://localhost/cb"},
                Scopes:       pq.StringArray{"read:profile"},
		IsActive:     true,
		IsPublic:     false,
	})
	require.NoError(t, err)

	code := uuid.NewString()
	err = codeRepo.Create(&models.AuthorizationCode{
		ID:          uuid.NewString(),
		Code:        code,
		ClientID:    clientID,
		UserID:      uuid.NewString(),
		RedirectURI: "http://localhost/cb",
		Scopes:      pq.StringArray{"read:profile"},
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=authorization_code&code="+code+"&client_id="+clientID+"&redirect_uri=http://localhost/cb"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	var resp map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "invalid_client", resp["error"])
}

func stringPtr(s string) *string { return &s }
