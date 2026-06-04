package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

const errUserNotAuthenticated = "User not authenticated"

type OAuthClientHandler struct {
	oauthProviderService *service.OAuthProviderService
}

func NewOAuthClientHandler(oauthProviderService *service.OAuthProviderService) *OAuthClientHandler {
	return &OAuthClientHandler{
		oauthProviderService: oauthProviderService,
	}
}

// CreateOAuthClient creates a new OAuth client
// @Summary Create OAuth Client
// @Description Create a new OAuth client for third-party apps
// @Tags OAuth Client
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateOAuthClientRequest true "Client details"
// @Success 201 {object} CreateOAuthClientResponse
// @Failure 400 {object} utils.ErrorResponse
// @Failure 401 {object} utils.ErrorResponse
// @Router /api/auth/oauth/clients [post]
func (h *OAuthClientHandler) CreateOAuthClient(c *gin.Context) {
	var req CreateOAuthClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Get current user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse(errUserNotAuthenticated))
		return
	}

	// Create the OAuth client
	client, clientSecret, err := h.oauthProviderService.CreateClient(
		req.Name,
		req.RedirectURIs,
		req.Scopes,
		userID.(string),
	)
	if err != nil {
		utils.BadRequestResponse(c, err.Error())
		return
	}

	// Return client details with secret (only shown once)
	c.JSON(http.StatusCreated, CreateOAuthClientResponse{
		Success: true,
		Message: "OAuth client created successfully",
		Data: OAuthClientData{
			ID:           client.ID,
			Name:         client.Name,
			ClientID:     client.ClientID,
			ClientSecret: clientSecret, // Only returned once!
			RedirectURIs: client.RedirectURIs,
			Scopes:       client.Scopes,
			CreatedAt:    client.CreatedAt,
		},
	})
}

// ListOAuthClients lists all OAuth clients owned by the user
// @Summary List My OAuth Clients
// @Description List all OAuth clients registered by the authenticated user
// @Tags OAuth Client
// @Produce json
// @Security BearerAuth
// @Success 200 {object} ListOAuthClientsResponse
// @Failure 401 {object} utils.ErrorResponse
// @Router /api/auth/oauth/clients [get]
func (h *OAuthClientHandler) ListOAuthClients(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse(errUserNotAuthenticated))
		return
	}

	clients, err := h.oauthProviderService.GetClientsByOwner(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to retrieve clients", err))
		return
	}

	c.JSON(http.StatusOK, ListOAuthClientsResponse{
		Success: true,
		Data:    clients,
	})
}

// DeleteOAuthClient deletes an OAuth client
// @Summary Delete OAuth Client
// @Description Delete an OAuth client registered by the user
// @Tags OAuth Client
// @Produce json
// @Security BearerAuth
// @Param clientId path string true "Client ID (UUID)"
// @Success 200 {object} utils.SuccessResponse
// @Failure 401 {object} utils.ErrorResponse
// @Failure 403 {object} utils.ErrorResponse
// @Failure 404 {object} utils.ErrorResponse
// @Router /api/auth/oauth/clients/{clientId} [delete]
func (h *OAuthClientHandler) DeleteOAuthClient(c *gin.Context) {
	clientID := c.Param("clientId")
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse(errUserNotAuthenticated))
		return
	}

	if err := h.oauthProviderService.DeleteClient(clientID, userID.(string)); err != nil {
		utils.BadRequestResponse(c, err.Error())
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("OAuth client deleted successfully", nil))
}

// DTOs
type CreateOAuthClientRequest struct {
	Name         string   `json:"name" binding:"required"`
	RedirectURIs []string `json:"redirect_uris" binding:"required,min=1"`
	Scopes       []string `json:"scopes" binding:"required,min=1"`
}

type CreateOAuthClientResponse struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    OAuthClientData `json:"data"`
}

type OAuthClientData struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	ClientID     string      `json:"client_id"`
	ClientSecret string      `json:"client_secret"` // Only in creation response
	RedirectURIs []string    `json:"redirect_uris"`
	Scopes       []string    `json:"scopes"`
	CreatedAt    interface{} `json:"created_at"`
}

type ListOAuthClientsResponse struct {
	Success bool                 `json:"success"`
	Data    []models.OAuthClient `json:"data"`
}
