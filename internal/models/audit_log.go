package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// AuditLog represents a security audit event
type AuditLog struct {
	ID        string    `gorm:"type:uuid;primary_key" json:"id"`
	UserID    *string   `gorm:"index" json:"userId,omitempty"`
	Action    string    `gorm:"not null" json:"action"`
	Entity    string    `gorm:"size:50" json:"entity"`    // e.g., "USER", "TOKEN"
	EntityID  string    `gorm:"size:255" json:"entityId"` // ID of the affected entity
	IPAddress string    `gorm:"size:45" json:"ipAddress"`
	UserAgent string    `gorm:"size:255" json:"userAgent"`
	Metadata  string    `gorm:"type:text" json:"metadata"` // JSON string for extra details
	CreatedAt time.Time `json:"createdAt"`
}

// BeforeCreate hook to generate UUID if not provided
func (a *AuditLog) BeforeCreate(tx *gorm.DB) error {
	if a.ID == "" {
		a.ID = uuid.New().String()
	}
	return nil
}
