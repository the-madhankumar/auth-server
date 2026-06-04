package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestAuthHandler_GetMe(t *testing.T) {
	// Custom setup for protected route
	authService, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()
	authHandler := handler.NewAuthHandler(authService, nil)
	// We need TokenService to create a valid token for the middleware
	cfg := &config.Config{JWT: config.JWTConfig{AccessSecret: "secret"}}
	tokenService := service.NewTokenService(cfg)

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AuthMiddleware(tokenService))
	r.GET("/api/auth/me", authHandler.GetMe)

	// Register user manually via service to get ID
	regReq := &dto.RegisterRequest{Email: "me@example.com", Password: "Password123!", FirstName: "Me"}
	user, err := authService.Register(regReq)
	assert.NoError(t, err)
	if err != nil {
		t.FailNow()
	}

	// Generate Token
	token, _ := tokenService.GenerateAccessToken(user)

	req, _ := http.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, "me@example.com", data["email"])
}
