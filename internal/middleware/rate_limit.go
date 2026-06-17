package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

func getLimits(cfg *config.Config, path string) (int, time.Duration) {
	switch path {

	case "/api/auth/login",
		"/api/auth/google/login",
		"/api/auth/github/login":
		return cfg.Security.LoginRateLimitMax,
			time.Duration(cfg.Security.LoginRateLimitWindow) * time.Millisecond

	case "/api/auth/register":
		return cfg.Security.RegisterRateLimitMax,
			time.Duration(cfg.Security.RegisterRateLimitWindow) * time.Millisecond

	case "/api/auth/forgot-password":
		return cfg.Security.ForgotRateLimitMax,
			time.Duration(cfg.Security.ForgotRateLimitWindow) * time.Millisecond

	default:
		return cfg.Security.RateLimitMax,
			time.Duration(cfg.Security.RateLimitWindow) * time.Millisecond
	}
}

func getRateLimitKey(c *gin.Context) (string, bool) {
	path := c.FullPath()
	ip := c.ClientIP()

	cleanPath := strings.ReplaceAll(strings.Trim(path, "/"), "/", ":")

	switch path {
	case "/api/auth/forgot-password":
		var req dto.ForgotPasswordRequest

		if err := c.ShouldBindBodyWithJSON(&req); err != nil {
			c.Abort()
			return "", false
		}

		cleanEmail := strings.ToLower(strings.TrimSpace(req.Email))
		if cleanEmail == "" {
			return "", false
		}
		return fmt.Sprintf("ratelimit:forgot:%s:%s", ip, cleanEmail), true

	case "/api/auth/login":
		return fmt.Sprintf("ratelimit:login:%s", ip), true

	case "/api/auth/google/login", "/api/auth/github/login":
		return fmt.Sprintf("ratelimit:oauth:%s", ip), true

	default:
		return fmt.Sprintf("ratelimit:%s:%s", strings.Trim(cleanPath, "/"), ip), true
	}
}

// RateLimitMiddleware applies rate limiting to requests based on IP address
func RateLimitMiddleware(cacheService *service.CacheService, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		key, ok := getRateLimitKey(c)

		if !ok || key == "" {
			c.Abort()
			return
		}
		path := c.FullPath()

		limit, window := getLimits(cfg, path)

		allowed, err := cacheService.AllowRequest(c.Request.Context(), key, limit, window)
		if err != nil {
			// Fail open on Redis error to avoid blocking valid traffic during outages
			c.Next()
			return
		}

		if !allowed {
			c.JSON(http.StatusTooManyRequests, utils.ErrorResponse("Too many requests, please try again later", nil))
			c.Abort()
			return
		}

		c.Next()
	}
}
