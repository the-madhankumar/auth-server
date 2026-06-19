package routes

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/middleware"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

func SetupRoutes(router *gin.Engine, db *gorm.DB, redisClient *redis.Client, cfg *config.Config) {
	// Initialize repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	verificationRepo := repository.NewVerificationRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// OAuth Provider repositories
	oauthClientRepo := repository.NewOAuthClientRepository(db)
	oauthCodeRepo := repository.NewAuthorizationCodeRepository(db)
	oauthTokenRepo := repository.NewOAuthTokenRepository(db)
	userConsentRepo := repository.NewUserConsentRepository(db)
	oauthProviderConfigRepo := repository.NewOAuthProviderConfigRepository(db)

	// Initialize services
	tokenService := service.NewTokenService(cfg)
	cacheService := service.NewCacheService(redisClient)

	// EmailService caches all templates at startup.
	// On directory error, an empty cache is used and a warning is logged.
	// The server always starts — missing templates only fail at send time.
	emailService := service.NewEmailService(cfg)

	auditService := service.NewAuditService(auditRepo)
	oauthService := service.NewOAuthService(cfg, oauthProviderConfigRepo)
	mfaService := service.NewMFAService(cfg)

	authService := service.NewAuthService(
		userRepo,
		tokenRepo,
		verificationRepo,
		passwordResetRepo,
		tokenService,
		cacheService,
		emailService,
		auditService,
		mfaService,
		cfg,
	)

	// OAuth Provider service
	oauthProviderService := service.NewOAuthProviderService(
		oauthClientRepo,
		oauthCodeRepo,
		oauthTokenRepo,
		userConsentRepo,
		oauthProviderConfigRepo,
		tokenService,
		cfg,
	)

	// Initialize handlers
	authHandler := handler.NewAuthHandler(authService, oauthService, oauthProviderService)
	adminHandler := handler.NewAdminHandler(authService)
	oauthClientHandler := handler.NewOAuthClientHandler(oauthProviderService)
	oauthHandler := handler.NewOAuthHandler(oauthProviderService, userRepo)

	// Apply global middleware
	router.Use(middleware.CORSMiddleware(cfg))
	router.Use(middleware.SecurityMiddleware())

	// Swagger Documentation (Custom UI)
	router.Static("/swagger", "./docs")
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusMovedPermanently, "/swagger/")
	})

	// Health check endpoint
	router.GET("/health", func(c *gin.Context) {
		dbStatus := "up"
		redisStatus := "up"
		overallStatus := "ok"
		statusCode := http.StatusOK

		// Check DB
		sqlDB, err := db.DB()
		if err != nil || sqlDB.Ping() != nil {
			dbStatus = "down"
			overallStatus = "degraded"
			statusCode = http.StatusServiceUnavailable
		}

		// Check Redis
		if err := redisClient.Ping(c.Request.Context()).Err(); err != nil {
			redisStatus = "down"
			overallStatus = "degraded"
			statusCode = http.StatusServiceUnavailable
		}

		c.JSON(statusCode, gin.H{
			"status": overallStatus,
			"components": gin.H{
				"database": dbStatus,
				"redis":    redisStatus,
			},
		})
	})

	// Ready check endpoint
	router.GET("/ready", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"status":  "ok",
			"message": "Auth server is ready",
		})
	})

	// OAuth 2.0 Provider endpoints
	router.GET("/oauth/authorize", middleware.OptionalAuthMiddleware(tokenService), oauthHandler.Authorize)
	router.POST("/oauth/authorize", middleware.AuthMiddleware(tokenService), oauthHandler.AuthorizePost)
	router.POST("/oauth/token", oauthHandler.Token)
	router.GET("/oauth/userinfo", oauthHandler.UserInfo)

	// API routes
	api := router.Group("/api")
	api.Use(middleware.RateLimitMiddleware(cacheService, cfg))
	{
		auth := api.Group("/auth")
		{
			// Public endpoints
			auth.POST("/register", authHandler.Register)
			auth.GET("/login", authHandler.ShowLogin)
			auth.POST("/login", authHandler.Login)
			auth.POST("/login/mfa", authHandler.LoginMFA)
			auth.POST("/refresh", authHandler.RefreshToken)
			auth.GET("/verify-email", authHandler.VerifyEmail)
			auth.POST("/resend-verification", authHandler.ResendVerification)
			auth.POST("/forgot-password", authHandler.ForgotPassword)
			auth.POST("/reset-password", authHandler.ResetPassword)

			// OAuth Routes
			auth.GET("/google/login", authHandler.GoogleLogin)
			auth.GET("/google/callback", authHandler.GoogleCallback)
			auth.GET("/github/login", authHandler.GitHubLogin)
			auth.GET("/github/callback", authHandler.GitHubCallback)

			// Protected routes
			protected := auth.Group("")
			protected.Use(middleware.AuthMiddleware(tokenService))
			{
				protected.GET("/me", authHandler.GetMe)
				protected.PUT("/profile", authHandler.UpdateProfile)
				protected.POST("/logout", authHandler.Logout)
				protected.POST("/logout-all", authHandler.LogoutAll)
				protected.GET("/sessions", authHandler.GetSessions)
				protected.DELETE("/sessions/:sessionId", authHandler.RevokeSession)
				protected.POST("/password", authHandler.ChangePassword)
				protected.DELETE("/me", authHandler.DeleteAccount)
				protected.GET("/audit-logs", authHandler.GetAuditLogs)

				// MFA Routes
				protected.POST("/mfa/enable", authHandler.EnableMFA)
				protected.POST("/mfa/verify", authHandler.VerifyMFA)
				protected.POST("/mfa/disable", authHandler.DisableMFA)

				// OAuth Client Management
				oauthClients := protected.Group("/oauth/clients")
				{
					oauthClients.POST("", oauthClientHandler.CreateOAuthClient)
					oauthClients.GET("", oauthClientHandler.ListOAuthClients)
					oauthClients.DELETE("/:clientId", oauthClientHandler.DeleteOAuthClient)

					oauthProviderConfigHandler := handler.NewOAuthProviderConfigHandler(oauthProviderService)
					providerConfigPath := "/:clientId/providers/:provider"
					oauthClients.POST(providerConfigPath, oauthProviderConfigHandler.CreateOrUpdateProviderConfig)
					oauthClients.GET(providerConfigPath, oauthProviderConfigHandler.GetProviderConfig)
					oauthClients.DELETE(providerConfigPath, oauthProviderConfigHandler.DeleteProviderConfig)
				}
			}
		}

		// Admin routes
		admin := api.Group("/admin")
		admin.Use(middleware.AuthMiddleware(tokenService))
		admin.Use(middleware.RequireRole("admin"))
		{
			admin.GET("/users", adminHandler.GetUsers)
			admin.POST("/users/:id/lock", adminHandler.LockUser)
			admin.POST("/users/:id/unlock", adminHandler.UnlockUser)
			admin.DELETE("/users/:id", adminHandler.DeleteUser)
		}
	}
}