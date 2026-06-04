package repository

import (
	"errors"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

var ErrRefreshTokenNotFound = errors.New("refresh token not found")

type TokenRepository struct {
	db *gorm.DB
}

func NewTokenRepository(db *gorm.DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// CreateRefreshToken stores a new refresh token
func (r *TokenRepository) CreateRefreshToken(token *models.RefreshToken) error {
	return r.db.Create(token).Error
}

// FindRefreshToken finds a refresh token by token string
func (r *TokenRepository) FindRefreshToken(tokenString string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	if err := r.db.Where("token = ?", tokenString).First(&token).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}
	return &token, nil
}

// FindRefreshTokenByID finds a refresh token by ID
func (r *TokenRepository) FindRefreshTokenByID(id string) (*models.RefreshToken, error) {
	var token models.RefreshToken
	if err := r.db.First(&token, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrRefreshTokenNotFound
		}
		return nil, err
	}
	return &token, nil
}

// FindUserRefreshTokens finds all refresh tokens for a user
func (r *TokenRepository) FindUserRefreshTokens(userID string) ([]models.RefreshToken, error) {
	var tokens []models.RefreshToken
	if err := r.db.Where("user_id = ? AND is_revoked = ?", userID, false).
		Order("created_at DESC").
		Find(&tokens).Error; err != nil {
		return nil, err
	}
	return tokens, nil
}

// RevokeRefreshToken marks a refresh token as revoked
func (r *TokenRepository) RevokeRefreshToken(tokenString string) error {
	result := r.db.Model(&models.RefreshToken{}).
		Where("token = ?", tokenString).
		Update("is_revoked", true)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrRefreshTokenNotFound
	}
	return nil
}

// RevokeRefreshTokenByID marks a refresh token as revoked by ID
func (r *TokenRepository) RevokeRefreshTokenByID(id string) error {
	result := r.db.Model(&models.RefreshToken{}).
		Where("id = ?", id).
		Update("is_revoked", true)

	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrRefreshTokenNotFound
	}
	return nil
}

// RevokeAllUserTokens revokes all refresh tokens for a user
func (r *TokenRepository) RevokeAllUserTokens(userID string) error {
	return r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND is_revoked = ?", userID, false).
		Update("is_revoked", true).Error
}

// DeleteExpiredTokens removes expired refresh tokens (cleanup job)
func (r *TokenRepository) DeleteExpiredTokens() (int64, error) {
	result := r.db.Where("expires_at < ?", time.Now()).
		Delete(&models.RefreshToken{})

	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}

// DeleteRevokedTokens removes revoked tokens older than specified duration
func (r *TokenRepository) DeleteRevokedTokens(olderThan time.Duration) (int64, error) {
	cutoffTime := time.Now().Add(-olderThan)
	result := r.db.Where("is_revoked = ? AND updated_at < ?", true, cutoffTime).
		Delete(&models.RefreshToken{})

	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}

// CountUserActiveSessions counts active (valid) refresh tokens for a user
func (r *TokenRepository) CountUserActiveSessions(userID string) (int64, error) {
	var count int64
	err := r.db.Model(&models.RefreshToken{}).
		Where("user_id = ? AND is_revoked = ? AND expires_at > ?", userID, false, time.Now()).
		Count(&count).Error
	return count, err
}
