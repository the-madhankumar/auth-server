package handler

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
)

const errTmpl = "error.html"

type OAuthHandler struct {
	oauthProviderService *service.OAuthProviderService
	userRepo             *repository.UserRepository
}

func NewOAuthHandler(oauthProviderService *service.OAuthProviderService, userRepo *repository.UserRepository) *OAuthHandler {
	if userRepo == nil {
		panic("oauth handler requires user repository")
	}

	return &OAuthHandler{
		oauthProviderService: oauthProviderService,
		userRepo:             userRepo,
	}
}

// Authorize handles the OAuth authorization request
// GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&scope=...&state=...
func (h *OAuthHandler) Authorize(c *gin.Context) {
	// Extract query parameters
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")
        codeChallenge := c.Query("code_challenge")
        codeChallengeMethod := c.Query("code_challenge_method")
        if codeChallenge != "" && codeChallengeMethod == "" {
            codeChallengeMethod = "S256"
        }

	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType == "" {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{
			"error": "Missing required parameters",
		})
		return
	}

	// Only support authorization_code flow
	if responseType != "code" {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{
			"error": "Unsupported response_type. Only 'code' is supported",
		})
		return
	}

	// Validate client
	client, err := h.oauthProviderService.GetPublicClient(clientID)
	if err != nil {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{
			"error": "Invalid client_id",
		})
		return
	}

	// Validate redirect URI
	if err := h.oauthProviderService.ValidateRedirectURI(client, redirectURI); err != nil {
		c.HTML(http.StatusBadRequest, errTmpl, gin.H{
			"error": "Invalid redirect_uri",
		})
		return
	}

	// Parse and validate scopes
	scopes := service.ParseScopes(scope)
	if err := h.oauthProviderService.ValidateScopes(scopes); err != nil {
		redirectError(c, redirectURI, "invalid_scope", err.Error(), state)
		return
	}

	// Check if user is authenticated
	userID, exists := c.Get("userID")
	if !exists {
		// Redirect to login with return URL
		loginURL := "/api/auth/login?return_to=" + url.QueryEscape(c.Request.URL.String())
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Check if user has previously consented
	hasConsent, err := h.oauthProviderService.CheckConsent(userID.(string), clientID, scopes)
	if err == nil && hasConsent {
		// User has already consented, generate code immediately
		// in Authorize GET:
                code, err := h.oauthProviderService.GenerateAuthorizationCode(clientID, userID.(string), redirectURI, scopes, strPtr(codeChallenge), strPtr(codeChallengeMethod))
		if err != nil {
			redirectError(c, redirectURI, "server_error", "Failed to generate authorization code", state)
			return
		}

		// Redirect back to client with code
		redirectWithCode(c, redirectURI, code, state)
		return
	}

	// Show consent screen
	scopeDescriptions := make([]string, len(scopes))
	for i, scope := range scopes {
		if desc, ok := service.ValidScopes[scope]; ok {
			scopeDescriptions[i] = desc
		} else {
			scopeDescriptions[i] = scope
		}
	}

	c.HTML(http.StatusOK, "oauth_consent.html", gin.H{
		"ClientName":  client.Name,
		"ClientID":    clientID,
		"RedirectURI": redirectURI,
		"Scope":       scope,
		"Scopes":      scopeDescriptions,
		"State":       state,
	})
}

// AuthorizePost handles the consent form submission
// POST /oauth/authorize
func (h *OAuthHandler) AuthorizePost(c *gin.Context) {
	action := c.PostForm("action")
	clientID := c.PostForm("client_id")
        redirectURI := c.PostForm("redirect_uri")
        scope := c.PostForm("scope")
	state := c.PostForm("state")
        codeChallenge := c.PostForm("code_challenge")
        codeChallengeMethod := c.PostForm("code_challenge_method")

	// Check if user denied
	if action == "deny" {
		redirectError(c, redirectURI, "access_denied", "User denied authorization", state)
		return
	}

	// Get authenticated user
	userID, exists := c.Get("userID")
	if !exists {
		c.HTML(http.StatusUnauthorized, "error.html", gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// Parse scopes
	scopes := service.ParseScopes(scope)

	// Save consent
	if err := h.oauthProviderService.SaveConsent(userID.(string), clientID, scopes); err != nil {
		redirectError(c, redirectURI, "server_error", "Failed to save consent", state)
		return
	}

	// Generate authorization code
        code, err := h.oauthProviderService.GenerateAuthorizationCode(clientID, userID.(string), redirectURI, scopes, strPtr(codeChallenge), strPtr(codeChallengeMethod))
	if err != nil {
		redirectError(c, redirectURI, "server_error", "Failed to generate authorization code", state)
		return
	}

	// Redirect back to client with code
	redirectWithCode(c, redirectURI, code, state)
}

// Token handles the token exchange
// POST /oauth/token
// Note: Token endpoint errors follow RFC 6749 §5.2 (error/error_description) rather than
// the project JSON schema, as required by the OAuth 2.0 specification.
func (h *OAuthHandler) Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	redirectURI := c.PostForm("redirect_uri")
        codeVerifier := c.PostForm("code_verifier")

	// Validate grant type
	if grantType != "authorization_code" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code grant type is supported",
		})
		return
	}

	// Validate client credentials
	client, err := h.oauthProviderService.ResolveClientForToken(clientID, clientSecret)
        if err != nil {
                c.JSON(http.StatusUnauthorized, gin.H{
                        "error":             "invalid_client",
                        "error_description": err.Error(),
                })
                return
        }

        // Public clients MUST use PKCE — reject if no verifier was sent at all,
        // independent of whether the stored auth code happens to have a challenge.
        if client.IsPublic && codeVerifier == "" {
                c.JSON(http.StatusBadRequest, gin.H{
                        "error":             "invalid_request",
                        "error_description": "code_verifier is required for public clients",
                })
                return
        }

	// Exchange code for token
	accessToken, err := h.oauthProviderService.ExchangeCodeForToken(code, clientID, redirectURI, codeVerifier, client.IsPublic)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_grant",
			"error_description": err.Error(),
		})
		return
	}

	// Return access token
	c.JSON(http.StatusOK, gin.H{
		"access_token": accessToken.Token,
		"token_type":   "Bearer",
		"expires_in":   3600, // 1 hour
		"scope":        strings.Join(accessToken.Scopes, " "),
	})
}

// UserInfo returns user information based on the access token
// GET /oauth/userinfo
func (h *OAuthHandler) UserInfo(c *gin.Context) {
	token, err := extractBearerToken(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	// Validate token
	accessToken, err := h.oauthProviderService.ValidateAccessToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	user, err := h.userRepo.FindByID(accessToken.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed_to_fetch_user"})
		return
	}

	response := buildUserInfoResponse(user, accessToken)
	c.JSON(http.StatusOK, response)
}

func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", errors.New("missing_token")
	}

	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		return authHeader[7:], nil
	}
	return "", errors.New("invalid_token_format")
}

func buildUserInfoResponse(user *models.User, accessToken *models.OAuthAccessToken) gin.H {
	response := gin.H{
		"sub":    accessToken.UserID,
		"scopes": accessToken.Scopes,
	}

	if slices.Contains(accessToken.Scopes, "read:profile") {
		name := strings.TrimSpace(user.FirstName + " " + user.LastName)
		if name != "" {
			response["name"] = name
		}
		if user.FirstName != "" {
			response["given_name"] = user.FirstName
		}
		if user.LastName != "" {
			response["family_name"] = user.LastName
		}
		if user.ProfileImage != "" {
			response["picture"] = user.ProfileImage
		}
	}

	if slices.Contains(accessToken.Scopes, "read:email") {
		if user.Email != "" {
			response["email"] = user.Email
		}
		response["email_verified"] = user.EmailVerified
	}

	return response
}

func redirectWithCode(c *gin.Context, redirectURI, code, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func redirectError(c *gin.Context, redirectURI, errorCode, errorDesc, state string) {
	u, _ := url.Parse(redirectURI)
	q := u.Query()
	q.Set("error", errorCode)
	q.Set("error_description", errorDesc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
