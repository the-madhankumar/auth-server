package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
