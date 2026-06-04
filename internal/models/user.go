package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type User struct {
	ID                  string         `gorm:"type:uuid;primary_key" json:"id"`
	Email               string         `gorm:"uniqueIndex;not null;size:255" json:"email"`
	PasswordHash        string         `gorm:"not null;size:255" json:"-"` // Never expose in JSON
	FirstName           string         `gorm:"size:100" json:"firstName,omitempty"`
	LastName            string         `gorm:"size:100" json:"lastName,omitempty"`
	Phone               string         `gorm:"size:20" json:"phone,omitempty"`
	PhoneVerified       bool           `gorm:"default:false" json:"phoneVerified"`
	EmailVerified       bool           `gorm:"default:false" json:"emailVerified"`
	IsActive            bool           `gorm:"default:true" json:"isActive"`
	ProfileImage        string         `json:"profileImage,omitempty"`
	OAuthProvider       string         `gorm:"size:50" json:"oauthProvider,omitempty"` // 'google', 'github', 'local'
	OAuthID             string         `gorm:"size:255" json:"-"`
	MFAEnabled          bool           `gorm:"default:false" json:"mfaEnabled"`
	MFASecret           string         `gorm:"size:255" json:"-"`
	Role                string         `gorm:"default:'user';size:50" json:"role"` // 'user', 'admin'
	FailedLoginAttempts int            `gorm:"default:0" json:"-"`
	LockedUntil         *time.Time     `json:"lockedUntil,omitempty"`
	CreatedAt           time.Time      `json:"createdAt"`
	UpdatedAt           time.Time      `json:"updatedAt"`
	DeletedAt           gorm.DeletedAt `gorm:"index" json:"-"`
	LastLoginAt         *time.Time     `json:"lastLoginAt,omitempty"`
}

// BeforeCreate hook to generate UUID if not provided
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == "" {
		u.ID = uuid.New().String()
	}
	// Set default OAuth provider if not set
	if u.OAuthProvider == "" {
		u.OAuthProvider = "local"
	}
	// Set default Role if not set
	if u.Role == "" {
		u.Role = "user"
	}
	return nil
}

// TableName specifies the table name for GORM
func (User) TableName() string {
	return "users"
}

// PublicUser returns user data safe for public consumption
type PublicUser struct {
	ID            string     `json:"id"`
	Email         string     `json:"email"`
	FirstName     string     `json:"firstName,omitempty"`
	LastName      string     `json:"lastName,omitempty"`
	EmailVerified bool       `json:"emailVerified"`
	MFAEnabled    bool       `json:"mfaEnabled"`
	CreatedAt     time.Time  `json:"createdAt"`
	LastLoginAt   *time.Time `json:"lastLoginAt,omitempty"`
}

// ToPublic converts User to PublicUser (safe for API responses)
func (u *User) ToPublic() *PublicUser {
	return &PublicUser{
		ID:            u.ID,
		Email:         u.Email,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		EmailVerified: u.EmailVerified,
		MFAEnabled:    u.MFAEnabled,
		CreatedAt:     u.CreatedAt,
		LastLoginAt:   u.LastLoginAt,
	}
}
