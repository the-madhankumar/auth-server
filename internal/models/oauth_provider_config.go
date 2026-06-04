package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// OAuthProviderConfig represents a third-party application's dynamic OAuth provider configurations (like Google/GitHub Client IDs)
type OAuthProviderConfig struct {
	ID                   string    `gorm:"primaryKey;type:uuid;default:gen_random_uuid()" json:"id"`
	ClientID             string    `gorm:"type:uuid;not null" json:"client_id"` // FK to oauth_clients.id
	Provider             string    `gorm:"not null" json:"provider"`            // google, github
	ProviderClientID     string    `gorm:"not null" json:"provider_client_id"`
	ProviderClientSecret string    `gorm:"not null" json:"-"` // Encrypted secret
	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// TableName specifies the table name for OAuthProviderConfig
func (OAuthProviderConfig) TableName() string {
	return "oauth_provider_configs"
}

// BeforeCreate will set a UUID rather than numeric ID.
func (c *OAuthProviderConfig) BeforeCreate(tx *gorm.DB) error {
	if c.ID == "" {
		c.ID = uuid.New().String()
	}
	return nil
}
