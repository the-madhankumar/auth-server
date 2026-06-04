package repository

import (
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

type OAuthProviderConfigRepository struct {
	db *gorm.DB
}

func NewOAuthProviderConfigRepository(db *gorm.DB) *OAuthProviderConfigRepository {
	return &OAuthProviderConfigRepository{db: db}
}

// Create adds a new config
func (r *OAuthProviderConfigRepository) Create(config *models.OAuthProviderConfig) error {
	return r.db.Create(config).Error
}

// FindByClientAndProvider finds config by client ID and provider
func (r *OAuthProviderConfigRepository) FindByClientAndProvider(clientID, provider string) (*models.OAuthProviderConfig, error) {
	var config models.OAuthProviderConfig
	err := r.db.Where("client_id = ? AND provider = ?", clientID, provider).First(&config).Error
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// Update updates the existing config
func (r *OAuthProviderConfigRepository) Update(config *models.OAuthProviderConfig) error {
	return r.db.Save(config).Error
}

// Delete removes a config
func (r *OAuthProviderConfigRepository) Delete(id string) error {
	return r.db.Delete(&models.OAuthProviderConfig{}, "id = ?", id).Error
}
