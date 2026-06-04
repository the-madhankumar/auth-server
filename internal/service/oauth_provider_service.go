package service

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lib/pq"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

var ErrUnauthorized = errors.New("unauthorized")

type OAuthProviderService struct {
	clientRepo   *repository.OAuthClientRepository
	codeRepo     *repository.AuthorizationCodeRepository
	tokenRepo    *repository.OAuthTokenRepository
	consentRepo  *repository.UserConsentRepository
	configRepo   *repository.OAuthProviderConfigRepository
	tokenService *TokenService
	cfg          *config.Config
}

func NewOAuthProviderService(
	clientRepo *repository.OAuthClientRepository,
	codeRepo *repository.AuthorizationCodeRepository,
	tokenRepo *repository.OAuthTokenRepository,
	consentRepo *repository.UserConsentRepository,
	configRepo *repository.OAuthProviderConfigRepository,
	tokenService *TokenService,
	cfg *config.Config,
) *OAuthProviderService {
	return &OAuthProviderService{
		clientRepo:   clientRepo,
		codeRepo:     codeRepo,
		tokenRepo:    tokenRepo,
		consentRepo:  consentRepo,
		configRepo:   configRepo,
		tokenService: tokenService,
		cfg:          cfg,
	}
}

// ValidScopes defines all available OAuth scopes
var ValidScopes = map[string]string{
	"read:profile":  "Read your profile information",
	"write:profile": "Update your profile",
	"read:email":    "Access your email address",
	"admin:users":   "Full admin access",
}

// CreateClient creates a new OAuth client
func (s *OAuthProviderService) CreateClient(name string, redirectURIs []string, scopes []string, ownerID string) (*models.OAuthClient, string, error) {
	// Generate client ID and secret
	clientID, err := generateRandomString(32)
	if err != nil {
		return nil, "", err
	}

	clientSecret, err := generateRandomString(48)
	if err != nil {
		return nil, "", err
	}

	// Hash the client secret
	hashedSecret, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	// Validate scopes
	if err := s.ValidateScopes(scopes); err != nil {
		return nil, "", err
	}

	client := &models.OAuthClient{
		Name:         name,
		ClientID:     clientID,
		ClientSecret: string(hashedSecret),
		RedirectURIs: pq.StringArray(redirectURIs),
		Scopes:       pq.StringArray(scopes),
		OwnerID:      ownerID,
		IsActive:     true,
	}

	if err := s.clientRepo.Create(client); err != nil {
		return nil, "", err
	}

	// Return the plain secret only once
	return client, clientSecret, nil
}

// ValidateClient validates client credentials
func (s *OAuthProviderService) ValidateClient(clientID, clientSecret string) (*models.OAuthClient, error) {
	client, err := s.clientRepo.FindByClientID(clientID)
	if err != nil {
		return nil, errors.New("invalid client credentials")
	}

	if !client.IsActive {
		return nil, errors.New("client is inactive")
	}

	// Verify client secret
	if err := bcrypt.CompareHashAndPassword([]byte(client.ClientSecret), []byte(clientSecret)); err != nil {
		return nil, errors.New("invalid client credentials")
	}

	return client, nil
}

// GetPublicClient validates only client ID and status (for authorization flow)
func (s *OAuthProviderService) GetPublicClient(clientID string) (*models.OAuthClient, error) {
	client, err := s.clientRepo.FindByClientID(clientID)
	if err != nil {
		return nil, errors.New("client not found")
	}

	if !client.IsActive {
		return nil, errors.New("client is inactive")
	}

	return client, nil
}

// ValidateRedirectURI checks if the redirect URI is allowed for the client
func (s *OAuthProviderService) ValidateRedirectURI(client *models.OAuthClient, redirectURI string) error {
	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return nil
		}
	}
	return errors.New("invalid redirect_uri")
}

// ValidateScopes checks if all requested scopes are valid
func (s *OAuthProviderService) ValidateScopes(scopes []string) error {
	for _, scope := range scopes {
		if _, exists := ValidScopes[scope]; !exists {
			return fmt.Errorf("invalid scope: %s", scope)
		}
	}
	return nil
}

// GenerateAuthorizationCode creates an authorization code
func (s *OAuthProviderService) GenerateAuthorizationCode(clientID, userID, redirectURI string, scopes []string) (string, error) {
	code, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	authCode := &models.AuthorizationCode{
		Code:        code,
		ClientID:    clientID,
		UserID:      userID,
		Scopes:      pq.StringArray(scopes),
		RedirectURI: redirectURI,
		ExpiresAt:   time.Now().Add(10 * time.Minute), // 10 minutes
		Used:        false,
	}

	if err := s.codeRepo.Create(authCode); err != nil {
		return "", err
	}

	return code, nil
}

// ExchangeCodeForToken exchanges an authorization code for an access token
func (s *OAuthProviderService) ExchangeCodeForToken(code, clientID, redirectURI string) (*models.OAuthAccessToken, error) {
	// Find the authorization code
	authCode, err := s.codeRepo.FindByCode(code)
	if err != nil {
		return nil, errors.New("invalid authorization code")
	}

	// Validate the code
	if !authCode.IsValid() {
		return nil, errors.New("authorization code expired or already used")
	}

	// Verify client ID and redirect URI match
	if authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		return nil, errors.New("invalid client or redirect_uri")
	}

	// Mark code as used
	if err := s.codeRepo.MarkAsUsed(code); err != nil {
		return nil, err
	}

	// Generate access token
	tokenString, err := generateRandomString(48)
	if err != nil {
		return nil, err
	}

	accessToken := &models.OAuthAccessToken{
		Token:     tokenString,
		ClientID:  authCode.ClientID,
		UserID:    authCode.UserID,
		Scopes:    models.StringArray(authCode.Scopes),
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour
	}

	if err := s.tokenRepo.Create(accessToken); err != nil {
		return nil, err
	}

	return accessToken, nil
}

// ValidateAccessToken validates an OAuth access token
func (s *OAuthProviderService) ValidateAccessToken(tokenString string) (*models.OAuthAccessToken, error) {
	token, err := s.tokenRepo.FindByToken(tokenString)
	if err != nil {
		return nil, errors.New("invalid access token")
	}

	if token.IsExpired() {
		return nil, errors.New("access token expired")
	}

	return token, nil
}

// CheckConsent checks if user has previously consented to the client
func (s *OAuthProviderService) CheckConsent(userID, clientID string, requestedScopes []string) (bool, error) {
	consent, err := s.consentRepo.FindByUserAndClient(userID, clientID)
	if err != nil {
		// No consent found
		return false, nil
	}

	// Check if all requested scopes are in the consent
	for _, scope := range requestedScopes {
		found := false
		for _, consentedScope := range consent.Scopes {
			if scope == consentedScope {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	return true, nil
}

// SaveConsent saves user consent
func (s *OAuthProviderService) SaveConsent(userID, clientID string, scopes []string) error {
	// Check if consent already exists
	existing, err := s.consentRepo.FindByUserAndClient(userID, clientID)
	if err == nil {
		// Update existing consent
		existing.Scopes = pq.StringArray(scopes)
		return s.consentRepo.Update(existing)
	}

	// Create new consent
	consent := &models.UserConsent{
		UserID:   userID,
		ClientID: clientID,
		Scopes:   pq.StringArray(scopes),
	}

	return s.consentRepo.Create(consent)
}

// GetClientsByOwner returns all OAuth clients owned by a user
func (s *OAuthProviderService) GetClientsByOwner(ownerID string) ([]models.OAuthClient, error) {
	return s.clientRepo.FindByOwner(ownerID)
}

// DeleteClient deletes an OAuth client if owned by the user
func (s *OAuthProviderService) DeleteClient(clientID, ownerID string) error {
	client, err := s.clientRepo.FindByID(clientID)
	if err != nil {
		return errors.New("client not found")
	}

	if client.OwnerID != ownerID {
		return errors.New("unauthorized to delete this client")
	}

	return s.clientRepo.Delete(clientID)
}

// ParseScopes parses a space-separated scope string
func ParseScopes(scopeString string) []string {
	if scopeString == "" {
		return []string{}
	}
	return strings.Split(scopeString, " ")
}

// Helper function to generate random strings
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// CreateOrUpdateProviderConfig creates or updates provider configurations for a client
func (s *OAuthProviderService) CreateOrUpdateProviderConfig(ownerID, clientID, provider, providerClientID, providerClientSecret string) error {
	client, err := s.clientRepo.FindByID(clientID)
	if err != nil {
		return err
	}
	if client.OwnerID != ownerID {
		return ErrUnauthorized
	}

	encryptedSecret, err := utils.Encrypt(providerClientSecret, s.cfg.Security.EncryptionKey)
	if err != nil {
		return err
	}

	config, err := s.configRepo.FindByClientAndProvider(clientID, provider)
	if err == nil && config != nil {
		config.ProviderClientID = providerClientID
		config.ProviderClientSecret = encryptedSecret
		return s.configRepo.Update(config)
	}

	newConfig := &models.OAuthProviderConfig{
		ClientID:             clientID,
		Provider:             provider,
		ProviderClientID:     providerClientID,
		ProviderClientSecret: encryptedSecret,
	}

	return s.configRepo.Create(newConfig)
}

// GetProviderConfig returns the provider config if the user owns the client
func (s *OAuthProviderService) GetProviderConfig(ownerID, clientID, provider string) (*models.OAuthProviderConfig, error) {
	client, err := s.clientRepo.FindByID(clientID)
	if err != nil {
		return nil, err
	}
	if client.OwnerID != ownerID {
		return nil, ErrUnauthorized
	}

	config, err := s.configRepo.FindByClientAndProvider(clientID, provider)
	if err != nil {
		return nil, err
	}

	return config, nil
}

// DeleteProviderConfig removes the provider configuration
func (s *OAuthProviderService) DeleteProviderConfig(ownerID, clientID, provider string) error {
	client, err := s.clientRepo.FindByID(clientID)
	if err != nil {
		return err
	}
	if client.OwnerID != ownerID {
		return ErrUnauthorized
	}

	config, err := s.configRepo.FindByClientAndProvider(clientID, provider)
	if err != nil {
		return errors.New("config not found")
	}

	return s.configRepo.Delete(config.ID)
}
