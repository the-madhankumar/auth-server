package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

// AuthMiddleware validates JWT tokens and attaches user info to context (Strict)
func AuthMiddleware(tokenService *service.TokenService, cacheService *service.CacheService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := getAuthToken(c)

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Authentication required"))
			c.Abort()
			return
		}

		claims, err := tokenService.ValidateAccessToken(tokenString)
		if err != nil {
			c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Invalid or expired token"))
			c.Abort()
			return
		}

		blacklisted, err := cacheService.IsTokenBlacklisted(c.Request.Context(), claims.ID)
		if err != nil {
			utils.InternalServerErrorResponse(c, "Failed to authenticate request")
			c.Abort()
			return
		}
		if blacklisted {
			c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Invalid or expired token"))
			c.Abort()
			return
		}

		setContextUser(c, claims)
		c.Next()
	}
}

// OptionalAuthMiddleware validates JWT if present, but doesn't abort if missing
func OptionalAuthMiddleware(tokenService *service.TokenService, cacheService *service.CacheService) gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := getAuthToken(c)

		if tokenString != "" {
			claims, err := tokenService.ValidateAccessToken(tokenString)
			if err == nil {
				blacklisted, err := cacheService.IsTokenBlacklisted(c.Request.Context(), claims.ID)
				if err == nil && !blacklisted {
					setContextUser(c, claims)
				}
			}
		}

		c.Next()
	}
}

// Helper to extract token from header or cookie
func getAuthToken(c *gin.Context) string {
	// 1. Get from Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 && parts[0] == "Bearer" {
			return parts[1]
		}
	}

	// 2. Get from cookie
	if cookie, err := c.Cookie("auth_token"); err == nil {
		return cookie
	}

	return ""
}

// Helper to set user info in context
func setContextUser(c *gin.Context, claims *service.JWTClaims) {
	c.Set("userID", claims.UserID)
	c.Set("email", claims.Email)
	c.Set("role", claims.Role)
	c.Set("sessionID", claims.SessionID)
}
