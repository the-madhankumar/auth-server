package middleware

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

// RateLimitMiddleware applies rate limiting to requests based on IP address
func RateLimitMiddleware(cacheService *service.CacheService, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := fmt.Sprintf("ratelimit:%s", ip)

		// Use configured values (converted to proper types)
		limit := cfg.Security.RateLimitMax
		window := time.Duration(cfg.Security.RateLimitWindow) * time.Millisecond

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
