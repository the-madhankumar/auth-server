package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

type OAuthProviderConfigHandler struct {
	providerService *service.OAuthProviderService
}

func NewOAuthProviderConfigHandler(providerService *service.OAuthProviderService) *OAuthProviderConfigHandler {
	return &OAuthProviderConfigHandler{
		providerService: providerService,
	}
}

type ProviderConfigRequest struct {
	ProviderClientID     string `json:"provider_client_id" binding:"required"`
	ProviderClientSecret string `json:"provider_client_secret" binding:"required"`
}

// CreateOrUpdateProviderConfig handles creating or updating a provider config
// @Summary Create/Update OAuth Provider Config
// @Tags oauth-clients
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param clientId path string true "Client ID"
// @Param provider path string true "Provider (google/github)"
// @Param request body ProviderConfigRequest true "Config data"
// @Success 200 {object} utils.Response
// @Router /api/auth/oauth/clients/{clientId}/providers/{provider} [post]
func (h *OAuthProviderConfigHandler) CreateOrUpdateProviderConfig(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	clientID := c.Param("clientId")
	provider := c.Param("provider")

	if provider != "google" && provider != "github" {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("Invalid provider. Must be google or github"))
		return
	}

	var req ProviderConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	err := h.providerService.CreateOrUpdateProviderConfig(userID.(string), clientID, provider, req.ProviderClientID, req.ProviderClientSecret)
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			c.JSON(http.StatusForbidden, utils.ErrorResponse("Forbidden", err))
			return
		}
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to update provider config", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Provider configuration updated successfully", nil))
}

// GetProviderConfig retrieves a provider config
// @Summary Get OAuth Provider Config
// @Tags oauth-clients
// @Security BearerAuth
// @Produce json
// @Param clientId path string true "Client ID"
// @Param provider path string true "Provider (google/github)"
// @Success 200 {object} utils.Response
// @Router /api/auth/oauth/clients/{clientId}/providers/{provider} [get]
func (h *OAuthProviderConfigHandler) GetProviderConfig(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	clientID := c.Param("clientId")
	provider := c.Param("provider")

	config, err := h.providerService.GetProviderConfig(userID.(string), clientID, provider)
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			c.JSON(http.StatusForbidden, utils.ErrorResponse("Forbidden", err))
			return
		}
		c.JSON(http.StatusNotFound, utils.ErrorResponse("Config not found", err))
		return
	}

	// Do not return the secret
	c.JSON(http.StatusOK, utils.SuccessResponse("Provider configuration retrieved", gin.H{
		"id":                 config.ID,
		"client_id":          config.ClientID,
		"provider":           config.Provider,
		"provider_client_id": config.ProviderClientID,
		"created_at":         config.CreatedAt,
		"updated_at":         config.UpdatedAt,
	}))
}

// DeleteProviderConfig deletes a provider config
// @Summary Delete OAuth Provider Config
// @Tags oauth-clients
// @Security BearerAuth
// @Produce json
// @Param clientId path string true "Client ID"
// @Param provider path string true "Provider (google/github)"
// @Success 200 {object} utils.Response
// @Router /api/auth/oauth/clients/{clientId}/providers/{provider} [delete]
func (h *OAuthProviderConfigHandler) DeleteProviderConfig(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	clientID := c.Param("clientId")
	provider := c.Param("provider")

	err := h.providerService.DeleteProviderConfig(userID.(string), clientID, provider)
	if err != nil {
		if errors.Is(err, service.ErrUnauthorized) {
			c.JSON(http.StatusForbidden, utils.ErrorResponse("Forbidden", err))
			return
		}
		c.JSON(http.StatusNotFound, utils.ErrorResponse("Config not found", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Provider configuration deleted successfully", nil))
}
