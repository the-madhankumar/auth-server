package testutils

import (
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/glebarez/sqlite"
	"github.com/go-redis/redis/v8"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

// MockEmailSender
type MockEmailSender struct {
	LastEmail map[string]string
}

func (m *MockEmailSender) SendVerificationEmail(email, token, appURL string) error {
	if m.LastEmail == nil {
		m.LastEmail = make(map[string]string)
	}
	m.LastEmail["verification"] = email
	return nil
}

func (m *MockEmailSender) SendPasswordResetEmail(email, token, appURL string) error {
	if m.LastEmail == nil {
		m.LastEmail = make(map[string]string)
	}
	m.LastEmail["reset"] = email
	return nil
}

func SetupIntegrationTest(t *testing.T) (*service.AuthService, *gorm.DB, *miniredis.Miniredis) {
	// 1. In-memory SQLite
	db, err := gorm.Open(sqlite.Open("file::memory:?mode=memory&cache=private"), &gorm.Config{})
	assert.NoError(t, err)

	// Migrate
	err = db.AutoMigrate(
		&models.User{},
		&models.RefreshToken{},
		&models.VerificationToken{},
		&models.PasswordResetToken{},
		&models.AuditLog{},
		&models.OAuthAccessToken{},
	)
        assert.NoError(t, err)
        assert.NoError(t, db.Exec("DELETE FROM oauth_access_tokens").Error)
        
        // OAuth tables — using raw SQL to avoid Postgres-specific gen_random_uuid()
        err = db.Exec(`CREATE TABLE IF NOT EXISTS oauth_clients (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            client_id TEXT UNIQUE NOT NULL,
            client_secret TEXT NOT NULL,
            redirect_uris TEXT,
            scopes TEXT,
            owner_id TEXT,
            is_active INTEGER DEFAULT 1,
            is_public INTEGER DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME
        )`).Error
        assert.NoError(t, err)

        err = db.Exec(`CREATE TABLE IF NOT EXISTS authorization_codes (
            id TEXT PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            client_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scopes TEXT,
            expires_at DATETIME NOT NULL,
            used INTEGER DEFAULT 0,
            created_at DATETIME,
            code_challenge TEXT,
            code_challenge_method TEXT
        )`).Error
        assert.NoError(t, err)

        err = db.Exec(`CREATE TABLE IF NOT EXISTS user_consents (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            scopes TEXT,
            created_at DATETIME,
            updated_at DATETIME
        )`).Error
        assert.NoError(t, err)

        // 2. Miniredis
	mr, err := miniredis.Run()
	assert.NoError(t, err)

	rdb := redis.NewClient(&redis.Options{
		Addr: mr.Addr(),
	})

	// 3. Repositories
	userRepo := repository.NewUserRepository(db)
	tokenRepo := repository.NewTokenRepository(db)
	verificationRepo := repository.NewVerificationRepository(db)
	passwordResetRepo := repository.NewPasswordResetRepository(db)
	auditRepo := repository.NewAuditRepository(db)

	// 4. Services
	cfg := &config.Config{
		JWT:      config.JWTConfig{AccessSecret: "secret", RefreshSecret: "refresh"},
		Security: config.SecurityConfig{RateLimitMax: 10, RateLimitWindow: 60},
		App:      config.AppConfig{URL: "http://localhost"},
	}
	tokenService := service.NewTokenService(cfg)
	cacheService := service.NewCacheService(rdb)
	emailService := &MockEmailSender{}
	auditService := service.NewAuditService(auditRepo)
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

	return authService, db, mr
}
