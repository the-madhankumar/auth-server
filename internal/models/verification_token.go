package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type VerificationToken struct {
	ID        string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"userId"`
	Token     string    `gorm:"type:varchar(255);uniqueIndex;not null" json:"token"`
	ExpiresAt time.Time `gorm:"not null" json:"expiresAt"`
	CreatedAt time.Time `json:"createdAt"`

	// Relationship
	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// BeforeCreate hook to generate UUID
func (vt *VerificationToken) BeforeCreate(tx *gorm.DB) error {
	if vt.ID == "" {
		vt.ID = uuid.New().String()
	}
	return nil
}

// IsExpired checks if token is expired
func (vt *VerificationToken) IsExpired() bool {
	return time.Now().After(vt.ExpiresAt)
}
