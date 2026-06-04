package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/routes"
)

// @title Auth Server API
// @version 1.0
// @description Production-ready Authentication Server in Go
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.email support@authserver.com

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @host localhost:8080
// @BasePath /
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database
	db := config.InitDatabase(cfg)

	// Auto-migrate database models
	err := config.AutoMigrate(db, &models.User{},
		&models.RefreshToken{},
		&models.VerificationToken{},
		&models.PasswordResetToken{},
		&models.AuditLog{},
		// OAuth 2.0 Provider models
		&models.OAuthClient{},
		&models.AuthorizationCode{},
		&models.OAuthAccessToken{},
		&models.UserConsent{},
	)
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	// Initialize Redis
	redisClient := config.InitRedis(cfg)

	// Setup Gin
	if cfg.App.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	router := gin.Default()

	// Load HTML templates for OAuth consent
	router.LoadHTMLGlob("templates/*")

	// Setup routes
	routes.SetupRoutes(router, db, redisClient, cfg)

	// Configure HTTP server
	addr := fmt.Sprintf(":%d", cfg.App.Port)
	srv := &http.Server{
		Addr:    addr,
		Handler: router,
	}

	// Start server in goroutine
	go func() {
		log.Printf(" Server starting on %s", addr)
		log.Printf(" Environment: %s", cfg.App.Env)

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("Failed to start server:", err)
		}
	}()

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	// Accept SIGINT (Ctrl+C) and SIGTERM (docker stop)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")

	// Graceful shutdown with 5 second timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	}

	// Close database connection
	sqlDB, err := db.DB()
	if err == nil {
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		} else {
			log.Println(" Database connection closed")
		}
	}

	// Close Redis connection
	if err := redisClient.Close(); err != nil {
		log.Printf("Error closing Redis: %v", err)
	} else {
		log.Println(" Redis connection closed")
	}

	log.Println(" Server exited gracefully")
}
