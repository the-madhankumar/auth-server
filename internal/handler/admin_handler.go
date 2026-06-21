package handler

import (
	"errors"
	"net/http"
	"strconv"
	"math"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"github.com/roshankumar0036singh/auth-server/internal/models"
)

type AdminAuthService interface {
	LockUser(userID, adminID, ipAddress, userAgent string) error
	UnlockUser(userID, adminID, ipAddress, userAgent string) error
	DeleteAccount(userID string) error
	GetUsers(limit, offset int)  (models.PaginatedUsers, error)
}

type AdminHandler struct {
	authService AdminAuthService
}

func NewAdminHandler(authService AdminAuthService) *AdminHandler {
	return &AdminHandler{authService: authService}
}

// GetUsers lists all users
// @Summary List all users
// @Tags admin
// @Security BearerAuth
// @Produce json
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Items per page" default(10)
// @Success 200 {object} utils.Response
// @Router /api/admin/users [get]
func (h *AdminHandler) GetUsers(c *gin.Context) {
	page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
	if err != nil || page < 1 {
		page = 1
	}

	limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
	if err != nil || limit < 1 {
		limit = 10
	}

	if limit > 100 {
		limit = 100
	}

	if page > (math.MaxInt/limit)+1 {
		page = (math.MaxInt / limit) + 1
	}

	offset := (page - 1) * limit

	users, err := h.authService.GetUsers(limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError,
			utils.ErrorResponse("Failed to fetch users", err))
		return
	}

	c.JSON(http.StatusOK,
		utils.SuccessResponse("List of users", users))
}

// LockUser locks a user account
// @Summary Lock user
// @Tags admin
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} utils.Response
// @Router /api/admin/users/{id}/lock [post]
func (h *AdminHandler) LockUser(c *gin.Context) {
	adminID := c.GetString("userID")
	userID := c.Param("id")
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	if err := h.authService.LockUser(userID, adminID, ipAddress, userAgent); err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(http.StatusNotFound,
				utils.ErrorResponse("User not found", err))
		case errors.Is(err, service.ErrSelfLock):
			c.JSON(http.StatusBadRequest,
				utils.ErrorResponse("Cannot lock your own account", err))
		case errors.Is(err, service.ErrAdminLock):
			c.JSON(http.StatusForbidden,
				utils.ErrorResponse("Admin accounts cannot be locked", err))
		case errors.Is(err, service.ErrAlreadyLocked):
			c.JSON(http.StatusConflict,
				utils.ErrorResponse("Account is already locked", err))
		default:
			c.JSON(http.StatusInternalServerError,
				utils.ErrorResponse("Failed to lock user", err))
		}
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse("User locked successfully", map[string]string{"userID": userID}))
}

// UnlockUser unlocks a user account
// @Summary Unlock user
// @Tags admin
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} utils.Response
// @Router /api/admin/users/{id}/unlock [post]
func (h *AdminHandler) UnlockUser(c *gin.Context) {
	adminID := c.GetString("userID")
	userID := c.Param("id")
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")
	if err := h.authService.UnlockUser(userID, adminID, ipAddress, userAgent); err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			c.JSON(http.StatusNotFound,
				utils.ErrorResponse("User not found", err))
		case errors.Is(err, service.ErrNotLocked):
			c.JSON(http.StatusBadRequest,
				utils.ErrorResponse("Account is not locked", err))
		default:
			c.JSON(http.StatusInternalServerError,
				utils.ErrorResponse("Failed to unlock user", err))
		}
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse("User unlocked successfully", map[string]string{"userID": userID}))
}

// DeleteUser deletes a user account (admin override)
// @Summary Delete user
// @Tags admin
// @Security BearerAuth
// @Param id path string true "User ID"
// @Success 200 {object} utils.Response
// @Router /api/admin/users/{id} [delete]
func (h *AdminHandler) DeleteUser(c *gin.Context) {
	userID := c.Param("id")
	if err := h.authService.DeleteAccount(userID); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to delete user", err))
		return
	}
	c.JSON(http.StatusOK, utils.SuccessResponse("User deleted successfully", nil))
}
