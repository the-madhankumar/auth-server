package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

const (
	userAgentHeader = "User-Agent"
	msgLoginSuccess = "Login successful"
	msgLoginFailed  = "Login failed"
)

type AuthHandler struct {
	authService  *service.AuthService
	oauthService *service.OAuthService
}

func NewAuthHandler(authService *service.AuthService, oauthService *service.OAuthService) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		oauthService: oauthService,
	}
}

// Register handles user registration
// @Summary Register a new user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RegisterRequest true "Registration data"
// @Success 201 {object} utils.Response
// @Failure 400 {object} utils.Response
// @Router /api/auth/register [post]
func (h *AuthHandler) Register(c *gin.Context) {
	var req dto.RegisterRequest

	// Validate request body
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	// Register user
	user, err := h.authService.Register(&req)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Registration failed", err))
		return
	}

	c.JSON(http.StatusCreated, utils.SuccessResponse("Registration successful. Please check your email to verify your account.", user.ToPublic()))
}

// VerifyEmail handles email verification
// @Summary Verify email
// @Tags auth
// @Accept json
// @Produce json
// @Param token query string true "Verification token"
// @Success 200 {object} utils.Response
// @Router /api/auth/verify-email [get]
func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("Token is required"))
		return
	}

	if err := h.authService.VerifyEmail(token); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Verification failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Email verified successfully", nil))
}

// ResendVerification handles resending verification email
// @Summary Resend verification email
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.ResendVerificationRequest true "Email data"
// @Success 200 {object} utils.Response
// @Router /api/auth/resend-verification [post]
func (h *AuthHandler) ResendVerification(c *gin.Context) {
	var req dto.ResendVerificationRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	if err := h.authService.ResendVerification(req.Email); err != nil {
		// Don't reveal if user exists or not for security (unless it's a validation error)
		// But for now we might return the error if it's "email already verified"
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to resend verification", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Verification email sent", nil))
}

// ForgotPassword handles forgot password request
// @Summary Request password reset
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.ForgotPasswordRequest true "Email data"
// @Success 200 {object} utils.Response
// @Router /api/auth/forgot-password [post]
func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req dto.ForgotPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	if err := h.authService.ForgotPassword(req.Email); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to process request", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("If an account exists with this email, a password reset link has been sent.", nil))
}

// ResetPassword handles password reset
// @Summary Reset password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.ResetPasswordRequest true "Reset data"
// @Success 200 {object} utils.Response
// @Router /api/auth/reset-password [post]
func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req dto.ResetPasswordRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	if err := h.authService.ResetPassword(req.Token, req.Password); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Password reset failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Password has been reset successfully. You can now login with your new password.", nil))
}

// UpdateProfile handles profile updates
// @Summary Update user profile
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.UpdateProfileRequest true "Profile data"
// @Success 200 {object} utils.Response
// @Router /api/auth/profile [put]
func (h *AuthHandler) UpdateProfile(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	var req dto.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	user, err := h.authService.UpdateProfile(userID.(string), &req)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to update profile", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Profile updated successfully", user.ToPublic()))
}

// ChangePassword handles password change
// @Summary Change password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.ChangePasswordRequest true "Password data"
// @Success 200 {object} utils.Response
// @Router /api/auth/password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	var req dto.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	if err := h.authService.ChangePassword(userID.(string), &req); err != nil {
		statusCode := http.StatusBadRequest
		if err.Error() == "incorrect current password" {
			statusCode = http.StatusUnauthorized
		}
		c.JSON(statusCode, utils.ErrorResponse(err.Error(), err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Password changed successfully", nil))
}

// DeleteAccount handles account deletion
// @Summary Delete account
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} utils.Response
// @Router /api/auth/me [delete]
func (h *AuthHandler) DeleteAccount(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	if err := h.authService.DeleteAccount(userID.(string)); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to delete account", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Account deleted successfully", nil))
}

// GetAuditLogs retrieves audit logs for the authenticated user
// @Summary Get audit logs
// @Tags auth
// @Accept json
// @Produce json
// @Success 200 {object} utils.Response
// @Router /api/auth/audit-logs [get]
func (h *AuthHandler) GetAuditLogs(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	logs, err := h.authService.GetUserAuditLogs(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to retrieve audit logs", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Audit logs retrieved successfully", logs))
}

// ShowLogin serves the login page UI
func (h *AuthHandler) ShowLogin(c *gin.Context) {
	c.HTML(http.StatusOK, "login.html", nil)
}

// Login handles user login with device tracking
// @Summary Login user
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.LoginRequest true "Login credentials"
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /api/auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req dto.LoginRequest

	// Validate request body
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	// Get device information
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader(userAgentHeader)

	// Authenticate user
	loginResp, err := h.authService.Login(&req, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse(msgLoginFailed, err))
		return
	}

	// Set session cookie for browser flows (like OAuth)
	// MaxAge is 7 days (matching refresh token)
	c.SetCookie("auth_token", loginResp.AccessToken, 7*24*3600, "/", "", false, true)

	c.JSON(http.StatusOK, utils.SuccessResponse(msgLoginSuccess, loginResp))
}

// RefreshToken handles refresh token requests with token rotation
// @Summary Refresh access token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.RefreshTokenRequest true "Refresh token"
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /api/auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req dto.RefreshTokenRequest

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	// Get device information for new token
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader(userAgentHeader)

	// Refresh with token rotation
	tokenResp, err := h.authService.RefreshAccessToken(req.RefreshToken, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse("Token refresh failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Token refreshed successfully", tokenResp))
}

// Logout handles user logout
// @Summary Logout user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body dto.LogoutRequest false "Logout request"
// @Success 200 {object} utils.Response
// @Router /api/auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get access token from header
	authHeader := c.GetHeader("Authorization")
	accessToken := ""
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 {
			accessToken = parts[1]
		}
	}

	// Get refresh token from body (optional)
	var req dto.LogoutRequest
	c.ShouldBindJSON(&req)

	// Logout
	if err := h.authService.Logout(accessToken, req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Logout failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Logout successful", nil))
}

// LogoutAll handles logout from all devices
// @Summary Logout from all devices
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.Response
// @Router /api/auth/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get current access token
	authHeader := c.GetHeader("Authorization")
	accessToken := ""
	if authHeader != "" {
		parts := strings.Split(authHeader, " ")
		if len(parts) == 2 {
			accessToken = parts[1]
		}
	}

	// Logout from all devices
	if err := h.authService.LogoutAll(userID.(string), accessToken); err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to logout from all devices", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Logged out from all devices", nil))
}

// GetMe returns the current authenticated user's info
// @Summary Get current user
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.Response
// @Failure 401 {object} utils.Response
// @Router /api/auth/me [get]
func (h *AuthHandler) GetMe(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get user details
	user, err := h.authService.GetUserByID(userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, utils.ErrorResponse("User not found", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("User retrieved successfully", user.ToPublic()))
}

// GetSessions returns all active sessions for the current user
// @Summary Get active sessions
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Success 200 {object} utils.Response
// @Router /api/auth/sessions [get]
func (h *AuthHandler) GetSessions(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get sessions
	sessions, err := h.authService.GetUserSessions(userID.(string))
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to retrieve sessions", err))
		return
	}

	// Convert to response format
	sessionResponses := make([]dto.SessionResponse, len(sessions))
	for i, session := range sessions {
		sessionResponses[i] = dto.SessionResponse{
			ID:        session.ID,
			IPAddress: session.IPAddress,
			UserAgent: session.UserAgent,
			CreatedAt: session.CreatedAt.Format("2006-01-02 15:04:05"),
			ExpiresAt: session.ExpiresAt.Format("2006-01-02 15:04:05"),
			IsCurrent: false, // TODO: Determine if this is the current session
		}
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Sessions retrieved successfully", sessionResponses))
}

// RevokeSession revokes a specific session
// @Summary Revoke a session
// @Tags auth
// @Produce json
// @Security BearerAuth
// @Param sessionId path string true "Session ID"
// @Success 200 {object} utils.Response
// @Router /api/auth/sessions/{sessionId} [delete]
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	// Get user ID from context
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	// Get session ID from URL
	sessionID := c.Param("sessionId")
	if sessionID == "" {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse("Session ID is required"))
		return
	}

	// Revoke session
	if err := h.authService.RevokeSession(userID.(string), sessionID); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to revoke session", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Session revoked successfully", nil))
}

// GoogleLogin initiates Google OAuth login
// @Summary Login with Google
// @Tags auth
// @Router /api/auth/google/login [get]
func (h *AuthHandler) GoogleLogin(c *gin.Context) {
	clientID := c.Query("client_id")

	rawState, err := h.oauthService.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to generate state", err))
		return
	}

	state := rawState
	if clientID != "" {
		state = rawState + "|" + clientID
	}

	// Store state in cookie for verification
	isProd := gin.Mode() == gin.ReleaseMode
	c.SetCookie("oauth_state", state, 3600, "/", "", isProd, true)

	url, err := h.oauthService.GetGoogleAuthURL(clientID, state)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to get auth URL", err))
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GoogleCallback handles Google OAuth callback
// @Summary Google OAuth callback
// @Tags auth
// @Router /api/auth/google/callback [get]
func (h *AuthHandler) GoogleCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	// Verify state
	cookieState, err := c.Cookie("oauth_state")
	if err != nil || state != cookieState {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid state parameter", nil))
		return
	}

	clientID := ""
	if parts := strings.Split(state, "|"); len(parts) > 1 {
		clientID = parts[1]
	}

	// Clear state cookie
	isProd := gin.Mode() == gin.ReleaseMode
	c.SetCookie("oauth_state", "", -1, "/", "", isProd, true)

	// Exchange code
	token, err := h.oauthService.ExchangeGoogleCode(c.Request.Context(), clientID, code)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to exchange token", err))
		return
	}

	// Get user info
	userInfo, err := h.oauthService.FetchGoogleUser(c.Request.Context(), clientID, token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to fetch user info", err))
		return
	}

	email := userInfo["email"].(string)
	firstName := userInfo["given_name"].(string)
	lastName := ""
	if val, ok := userInfo["family_name"].(string); ok {
		lastName = val
	}
	oauthID := userInfo["id"].(string)

	// Login or Register
	ipAddress := c.ClientIP()
	userAgent := c.GetHeader(userAgentHeader)

	loginResp, err := h.authService.LoginWithOAuth(email, oauthID, firstName, lastName, "google", ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse(msgLoginFailed, err))
		return
	}

	// Redirect to frontend with tokens? Or return JSON?
	// Usually callback redirects to frontend with query params or sets cookies
	// For this API, let's return JSON if caller can handle it, but standard Browser flow needs redirect.
	// We'll return JSON for now as per API design, but in real app we'd redirect to frontend app URL
	c.JSON(http.StatusOK, utils.SuccessResponse(msgLoginSuccess, loginResp))
}

// GitHubLogin initiates GitHub OAuth login
// @Summary Login with GitHub
// @Tags auth
// @Router /api/auth/github/login [get]
func (h *AuthHandler) GitHubLogin(c *gin.Context) {
	clientID := c.Query("client_id")

	rawState, err := h.oauthService.GenerateState()
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to generate state", err))
		return
	}

	state := rawState
	if clientID != "" {
		state = rawState + "|" + clientID
	}

	// Store state in cookie for verification
	isProd := gin.Mode() == gin.ReleaseMode
	c.SetCookie("oauth_state", state, 3600, "/", "", isProd, true)

	url, err := h.oauthService.GetGitHubAuthURL(clientID, state)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to get auth URL", err))
		return
	}
	c.Redirect(http.StatusTemporaryRedirect, url)
}

// GitHubCallback handles GitHub OAuth callback
// @Summary GitHub OAuth callback
// @Tags auth
// @Router /api/auth/github/callback [get]
func (h *AuthHandler) GitHubCallback(c *gin.Context) {
	state := c.Query("state")
	code := c.Query("code")

	cookieState, err := c.Cookie("oauth_state")
	if err != nil || state != cookieState {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Invalid state parameter", nil))
		return
	}

	clientID := ""
	if parts := strings.Split(state, "|"); len(parts) > 1 {
		clientID = parts[1]
	}

	// Clear state cookie
	isProd := gin.Mode() == gin.ReleaseMode
	c.SetCookie("oauth_state", "", -1, "/", "", isProd, true)

	token, err := h.oauthService.ExchangeGitHubCode(c.Request.Context(), clientID, code)
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to exchange token", err))
		return
	}

	userInfo, err := h.oauthService.FetchGitHubUser(c.Request.Context(), clientID, token)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Failed to fetch user info", err))
		return
	}

	email := userInfo["email"].(string)

	// GitHub names are often one string "Name" or just login
	firstName := ""
	lastName := ""
	if name, ok := userInfo["name"].(string); ok && name != "" {
		parts := strings.SplitN(name, " ", 2)
		firstName = parts[0]
		if len(parts) > 1 {
			lastName = parts[1]
		}
	} else {
		firstName = userInfo["login"].(string)
	}

	oauthID := fmt.Sprintf("%.0f", userInfo["id"].(float64)) // GitHub ID is number

	ipAddress := c.ClientIP()
	userAgent := c.GetHeader(userAgentHeader)

	loginResp, err := h.authService.LoginWithOAuth(email, oauthID, firstName, lastName, "github", ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, utils.ErrorResponse("Login failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse(msgLoginSuccess, loginResp))
}

// EnableMFA initates MFA setup
// @Summary Enable MFA
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} utils.Response
// @Router /api/auth/mfa/enable [post]
func (h *AuthHandler) EnableMFA(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	resp, err := h.authService.EnableMFA(userID.(string))
	if err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("Failed to enable MFA", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("MFA setup initiated", resp))
}

// VerifyMFA verifies and enables MFA
// @Summary Verify and enable MFA
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body dto.MFAVerifyRequest true "Verification code"
// @Success 200 {object} utils.Response
// @Router /api/auth/mfa/verify [post]
func (h *AuthHandler) VerifyMFA(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, utils.UnauthorizedResponse("Unauthorized"))
		return
	}

	var req dto.MFAVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	if err := h.authService.VerifyEnableMFA(userID.(string), req.Code); err != nil {
		c.JSON(http.StatusBadRequest, utils.ErrorResponse("MFA verification failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("MFA enabled successfully", nil))
}

// LoginMFA handles login with MFA code
// @Summary Login with MFA
// @Tags auth
// @Accept json
// @Produce json
// @Param request body dto.MFALoginRequest true "MFA Login data"
// @Success 200 {object} utils.Response
// @Router /api/auth/login/mfa [post]
func (h *AuthHandler) LoginMFA(c *gin.Context) {
	var req dto.MFALoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, utils.ValidationErrorResponse(err.Error()))
		return
	}

	ipAddress := c.ClientIP()
	userAgent := c.GetHeader("User-Agent")

	resp, err := h.authService.VerifyLoginMFA(req.Email, req.Code, ipAddress, userAgent)
	if err != nil {
		c.JSON(http.StatusUnauthorized, utils.ErrorResponse("MFA login failed", err))
		return
	}

	c.JSON(http.StatusOK, utils.SuccessResponse("Login successful", resp))
}
