package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type PasswordResetToken struct {
	ID        string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID    string    `gorm:"type:uuid;not null;index" json:"userId"`
	Token     string    `gorm:"type:varchar(255);uniqueIndex;not null" json:"token"`
	ExpiresAt time.Time `gorm:"not null" json:"expiresAt"`
	Used      bool      `gorm:"default:false" json:"used"`
	CreatedAt time.Time `json:"createdAt"`

	// Relationship
	User User `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE" json:"-"`
}

// BeforeCreate hook to generate UUID
func (prt *PasswordResetToken) BeforeCreate(tx *gorm.DB) error {
	if prt.ID == "" {
		prt.ID = uuid.New().String()
	}
	return nil
}

// IsExpired checks if token is expired
func (prt *PasswordResetToken) IsExpired() bool {
	return time.Now().After(prt.ExpiresAt)
}

// IsValid checks if token is valid (not expired and not used)
func (prt *PasswordResetToken) IsValid() bool {
	return !prt.IsExpired() && !prt.Used
}
