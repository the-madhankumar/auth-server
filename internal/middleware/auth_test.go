package middleware_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
)

func setupTest(t *testing.T) (*gin.Engine, *service.TokenService, *service.CacheService, *miniredis.Miniredis) {
	gin.SetMode(gin.TestMode)
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	cfg := &config.Config{
		JWT: config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh", AccessExpiry: "15m"},
	}
	tokenService := service.NewTokenService(cfg)
	cacheService := service.NewCacheService(rdb)
	router := gin.New()

	return router, tokenService, cacheService, mr
}

func TestAuthMiddleware_BlacklistedToken(t *testing.T) {
	router, tokenService, cacheService, mr := setupTest(t)
	defer mr.Close()

	// 1. Generate a valid token
	user := &models.User{ID: "user123", Email: "test@test.com", Role: "user"}
	token, err := tokenService.GenerateAccessToken(user, "session123")
	assert.NoError(t, err)

	// 2. Extract claims to get the token ID and blacklist the token in cache
	claims, err := tokenService.ValidateAccessToken(token)
	assert.NoError(t, err)

	err = cacheService.BlacklistToken(context.Background(), claims.ID, 15*time.Minute)
	assert.NoError(t, err)

	// 3. Setup route with AuthMiddleware
	router.GET("/protected", middleware.AuthMiddleware(tokenService, cacheService), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// 4. Make request with the blacklisted token
	req := httptest.NewRequest("GET", "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// 5. Assert it is rejected
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthMiddleware_CacheError(t *testing.T) {
	router, tokenService, cacheService, mr := setupTest(t)
	// Don't close mr here so we can close it early to simulate an error
	
	user := &models.User{ID: "user123", Email: "test@test.com", Role: "user"}
	token, err := tokenService.GenerateAccessToken(user, "session123")
	assert.NoError(t, err)

	router.GET("/protected_err", middleware.AuthMiddleware(tokenService, cacheService), func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	// Close miniredis to simulate a connection error
	mr.Close()

	req := httptest.NewRequest("GET", "/protected_err", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert it is rejected with 500
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestOptionalAuthMiddleware_BlacklistedToken(t *testing.T) {
	router, tokenService, cacheService, mr := setupTest(t)
	defer mr.Close()

	user := &models.User{ID: "user123", Email: "test@test.com", Role: "user"}
	token, err := tokenService.GenerateAccessToken(user, "session123")
	assert.NoError(t, err)

	claims, err := tokenService.ValidateAccessToken(token)
	assert.NoError(t, err)

	err = cacheService.BlacklistToken(context.Background(), claims.ID, 15*time.Minute)
	assert.NoError(t, err)

	router.GET("/optional", middleware.OptionalAuthMiddleware(tokenService, cacheService), func(c *gin.Context) {
		userID, exists := c.Get("userID")
		if exists {
			c.JSON(200, gin.H{"status": "authenticated", "userID": userID})
		} else {
			c.JSON(200, gin.H{"status": "anonymous"})
		}
	})

	req := httptest.NewRequest("GET", "/optional", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Assert it treats the user as anonymous
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "anonymous")
}
