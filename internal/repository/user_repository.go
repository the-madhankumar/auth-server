package repository

import (
	"errors"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"gorm.io/gorm"
)

var ErrUserNotFound = errors.New("user not found")

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// GetUsers get all users by limit and offset [Pagination]
func (r *UserRepository) GetUsers(limit int, offset int) (models.PaginatedUsers, error) {
	var users []models.User
	var total int64

	query := r.db.Model(&models.User{}).Where("role = ?", "user")

	if err := query.Count(&total).Error; err != nil {
		return models.PaginatedUsers{}, err
	}

	if err := query.
		Limit(limit).
		Offset(offset).
		Find(&users).Error; err != nil {
		return models.PaginatedUsers{}, err
	}

	return models.PaginatedUsers{
		Users: users,
		Total: total,
	}, nil
}

// FindByID finds a user by ID
func (r *UserRepository) FindByID(id string) (*models.User, error) {
	var user models.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// FindByEmail finds a user by email
func (r *UserRepository) FindByEmail(email string) (*models.User, error) {
	var user models.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

// Create creates a new user
func (r *UserRepository) Create(user *models.User) error {
	return r.db.Create(user).Error
}

// Update updates user fields
func (r *UserRepository) Update(id string, updates map[string]interface{}) error {
	result := r.db.Model(&models.User{}).Where("id = ?", id).Updates(updates)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// Delete soft deletes a user (if using soft delete) or hard deletes
func (r *UserRepository) Delete(id string) error {
	result := r.db.Delete(&models.User{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}
	return nil
}

// EmailExists checks if an email is already registered
func (r *UserRepository) EmailExists(email string) (bool, error) {
	var count int64
	err := r.db.Model(&models.User{}).Where("email = ?", email).Count(&count).Error
	return count > 0, err
}

func (r *UserRepository) RunInTx(fn func(u *UserRepository, t *TokenRepository) error) error {
	return r.db.Transaction(func(tx *gorm.DB) error {
		return fn(NewUserRepository(tx), NewTokenRepository(tx))
	})
}

func (r *UserRepository) LockUser(userID string, lockedUntil time.Time) error {
	result := r.db.Model(&models.User{}).
		Where("id = ?", userID).
		Update("locked_until", lockedUntil)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *UserRepository) UnlockUser(userID string) error {
	result := r.db.Model(&models.User{}).
		Where("id = ?", userID).
		Updates(map[string]interface{}{
			"locked_until":          nil,
			"failed_login_attempts": 0,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}
