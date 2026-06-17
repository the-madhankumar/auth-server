package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	App      AppConfig
	Database DatabaseConfig
	Redis    RedisConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
	Email    EmailConfig
	Security SecurityConfig
}

type AppConfig struct {
	Port int
	Env  string
	URL  string
}

type DatabaseConfig struct {
	URL     string
	PoolMin int
	PoolMax int
}

type RedisConfig struct {
	URL string
	TTL int
}

type JWTConfig struct {
	AccessSecret  string
	RefreshSecret string
	AccessExpiry  string
	RefreshExpiry string
}
type OAuthConfig struct {
	Google GoogleOAuthConfig
	GitHub GitHubOAuthConfig
}

type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

type GitHubOAuthConfig struct {
	ClientID     string
	ClientSecret string
	CallbackURL  string
}

type SecurityConfig struct {
	BcryptRounds           int
	RateLimitWindow        int
	RateLimitMax           int
	AccountLockMaxAttempts int
	AccountLockDuration    int // in minutes
	EncryptionKey          string

	LoginRateLimitMax    int
	LoginRateLimitWindow int

	RegisterRateLimitMax    int
	RegisterRateLimitWindow int

	ForgotRateLimitMax    int
	ForgotRateLimitWindow int
}

func mustAtoi(key string, defaultValue int) int {
	v, err := strconv.Atoi(getEnv(key, strconv.Itoa(defaultValue)))
	if err != nil || v <= 0 {
		return defaultValue
	}
	return v
}

func LoadConfig() *Config {
	// Load .env file (ignore error if file doesn't exist)
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	port, _ := strconv.Atoi(getEnv("PORT", "3000"))
	poolMin, _ := strconv.Atoi(getEnv("DB_POOL_MIN", "2"))
	poolMax, _ := strconv.Atoi(getEnv("DB_POOL_MAX", "10"))
	redisTTL, _ := strconv.Atoi(getEnv("REDIS_TTL", "3600"))
	bcryptRounds, _ := strconv.Atoi(getEnv("BCRYPT_ROUNDS", "12"))
	rateLimitWindow, _ := strconv.Atoi(getEnv("RATE_LIMIT_WINDOW", "900000"))
	rateLimitMax, _ := strconv.Atoi(getEnv("RATE_LIMIT_MAX", "5"))
	accountLockMax, _ := strconv.Atoi(getEnv("ACCOUNT_LOCK_MAX_ATTEMPTS", "5"))
	accountLockDuration, _ := strconv.Atoi(getEnv("ACCOUNT_LOCK_DURATION", "30")) // Minutes

	loginRateLimitMax := mustAtoi("LOGIN_RATE_LIMIT_MAX", 5)
	loginRateLimitWindow := mustAtoi("LOGIN_RATE_LIMIT_WINDOW", 900000)

	registerRateLimitMax := mustAtoi("REGISTER_RATE_LIMIT_MAX", 3)
	registerRateLimitWindow := mustAtoi("REGISTER_RATE_LIMIT_WINDOW", 3600000)

	forgotRateLimitMax := mustAtoi("FORGOT_RATE_LIMIT_MAX", 3)
	forgotRateLimitWindow := mustAtoi("FORGOT_RATE_LIMIT_WINDOW", 3600000)

	appURL := getEnv("APP_URL", "http://localhost:3000")

	accessSecret := getEnv("JWT_SECRET", "")
	refreshSecret := getEnv("JWT_REFRESH_SECRET", "")
	if len(accessSecret) < 32 {
		log.Fatal("JWT_SECRET must be set and at least 32 bytes long")
	}
	if len(refreshSecret) < 32 {
		log.Fatal("JWT_REFRESH_SECRET must be set and at least 32 bytes long")
	}

	encKey := getEnv("ENCRYPTION_KEY", "")
	if encKey == "" || encKey == "0123456789abcdef0123456789abcdef" {
		log.Fatal("ENCRYPTION_KEY must be set to a unique secret")
	}

	return &Config{
		App: AppConfig{
			Port: port,
			Env:  getEnv("APP_ENV", "development"),
			URL:  appURL,
		},
		Database: DatabaseConfig{
			URL:     getEnv("DATABASE_URL", ""),
			PoolMin: poolMin,
			PoolMax: poolMax,
		},
		Redis: RedisConfig{
			URL: getEnv("REDIS_URL", ""),
			TTL: redisTTL,
		},
		JWT: JWTConfig{
			AccessSecret:  getEnv("JWT_SECRET", ""),
			RefreshSecret: getEnv("JWT_REFRESH_SECRET", ""),
			AccessExpiry:  getEnv("JWT_ACCESS_EXPIRY", "15m"),
			RefreshExpiry: getEnv("JWT_REFRESH_EXPIRY", "168h"),
		},
		OAuth: OAuthConfig{
			Google: GoogleOAuthConfig{
				ClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
				ClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
				CallbackURL:  appURL + "/api/oauth/google/callback",
			},
			GitHub: GitHubOAuthConfig{
				ClientID:     getEnv("GITHUB_CLIENT_ID", ""),
				ClientSecret: getEnv("GITHUB_CLIENT_SECRET", ""),
				CallbackURL:  appURL + "/api/oauth/github/callback",
			},
		},
		Email: LoadEmailConfig(),
		Security: SecurityConfig{
			BcryptRounds:           bcryptRounds,
			RateLimitWindow:        rateLimitWindow,
			RateLimitMax:           rateLimitMax,
			AccountLockMaxAttempts: accountLockMax,
			AccountLockDuration:    accountLockDuration,
			EncryptionKey:          encKey,

			LoginRateLimitMax:    loginRateLimitMax,
			LoginRateLimitWindow: loginRateLimitWindow,

			RegisterRateLimitMax:    registerRateLimitMax,
			RegisterRateLimitWindow: registerRateLimitWindow,

			ForgotRateLimitMax:    forgotRateLimitMax,
			ForgotRateLimitWindow: forgotRateLimitWindow,
		},
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
