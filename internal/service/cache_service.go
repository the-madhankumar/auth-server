package service

import (
	"context"
	"fmt"
	"time"

	"github.com/go-redis/redis/v8"
)

const (
	cacheKeySession       = "session:%s"
	cacheKeyLoginAttempts = "login_attempts:%s"
)

type CacheService struct {
	client *redis.Client
}

func NewCacheService(client *redis.Client) *CacheService {
	return &CacheService{client: client}
}

// BlacklistToken adds a token to the blacklist (for logout)
func (s *CacheService) BlacklistToken(ctx context.Context, token string, expiry time.Duration) error {
	key := fmt.Sprintf("blacklist:%s", token)
	return s.client.Set(ctx, key, "1", expiry).Err()
}

// IsTokenBlacklisted checks if a token is blacklisted
func (s *CacheService) IsTokenBlacklisted(ctx context.Context, token string) (bool, error) {
	key := fmt.Sprintf("blacklist:%s", token)
	result, err := s.client.Get(ctx, key).Result()

	if err == redis.Nil {
		return false, nil // Not blacklisted
	}
	if err != nil {
		return false, err // Error occurred
	}

	return result == "1", nil
}

// StoreSession stores session data in Redis
func (s *CacheService) StoreSession(ctx context.Context, sessionID string, data interface{}, expiry time.Duration) error {
	key := fmt.Sprintf(cacheKeySession, sessionID)
	return s.client.Set(ctx, key, data, expiry).Err()
}

// GetSession retrieves session data from Redis
func (s *CacheService) GetSession(ctx context.Context, sessionID string) (string, error) {
	key := fmt.Sprintf(cacheKeySession, sessionID)
	return s.client.Get(ctx, key).Result()
}

// DeleteSession removes a session from Redis
func (s *CacheService) DeleteSession(ctx context.Context, sessionID string) error {
	key := fmt.Sprintf(cacheKeySession, sessionID)
	return s.client.Del(ctx, key).Err()
}

// IncrementLoginAttempts increments failed login attempts for an email
func (s *CacheService) IncrementLoginAttempts(ctx context.Context, email string) (int64, error) {
	key := fmt.Sprintf(cacheKeyLoginAttempts, email)
	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}

	// Set expiry on first attempt (15 minutes)
	if count == 1 {
		s.client.Expire(ctx, key, 15*time.Minute)
	}

	return count, nil
}

// GetLoginAttempts gets the number of failed login attempts
func (s *CacheService) GetLoginAttempts(ctx context.Context, email string) (int64, error) {
	key := fmt.Sprintf(cacheKeyLoginAttempts, email)
	count, err := s.client.Get(ctx, key).Int64()

	if err == redis.Nil {
		return 0, nil
	}
	return count, err
}

// ResetLoginAttempts resets failed login attempts for an email
func (s *CacheService) ResetLoginAttempts(ctx context.Context, email string) error {
	key := fmt.Sprintf(cacheKeyLoginAttempts, email)
	return s.client.Del(ctx, key).Err()
}

// AllowRequest checks if a request is allowed based on rate limiting logic
func (s *CacheService) AllowRequest(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	// Simple counter based rate limiting
	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return false, err
	}

	// Set expiry on first request
	if count == 1 {
		s.client.Expire(ctx, key, window)
	}

	return count <= int64(limit), nil
}
