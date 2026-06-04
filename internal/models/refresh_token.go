package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RefreshToken struct {
	ID        string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"userId"`
	Token     string    `gorm:"type:varchar(500);uniqueIndex;not null" json:"-"` // Never expose in JSON
	ExpiresAt time.Time `gorm:"not null;index" json:"expiresAt"`
	IsRevoked bool      `gorm:"default:false;index" json:"isRevoked"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`

	// Device information for session tracking
	IPAddress string `gorm:"size:45" json:"ipAddress,omitempty"` // IPv6 max length
	UserAgent string `gorm:"size:500" json:"userAgent,omitempty"`
	DeviceID  string `gorm:"size:255" json:"deviceId,omitempty"` // For device tracking

	// Relationship
	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// BeforeCreate hook to generate UUID if not provided
func (rt *RefreshToken) BeforeCreate(tx *gorm.DB) error {
	if rt.ID == "" {
		rt.ID = uuid.New().String()
	}
	return nil
}

// TableName specifies the table name for GORM
func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

// IsExpired checks if the refresh token has expired
func (rt *RefreshToken) IsExpired() bool {
	return time.Now().After(rt.ExpiresAt)
}

// IsValid checks if the token is valid (not expired and not revoked)
func (rt *RefreshToken) IsValid() bool {
	return !rt.IsExpired() && !rt.IsRevoked
}
