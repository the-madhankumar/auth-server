package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

type OAuthService struct {
	cfg          *config.Config
	providerRepo *repository.OAuthProviderConfigRepository
}

func NewOAuthService(cfg *config.Config, providerRepo *repository.OAuthProviderConfigRepository) *OAuthService {
	return &OAuthService{
		cfg:          cfg,
		providerRepo: providerRepo,
	}
}

// GenerateState generates a random state string for CSRF protection
func (s *OAuthService) GenerateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (s *OAuthService) getGoogleConfig(clientID string) (*oauth2.Config, error) {
	var oauthClientID, oauthClientSecret string

	// 1. Try per-client config from DB first
	if clientID != "" && s.providerRepo != nil {
		providerConf, err := s.providerRepo.FindByClientAndProvider(clientID, "google")
		if err == nil && providerConf != nil {
			decryptedSecret, err := utils.Decrypt(providerConf.ProviderClientSecret, s.cfg.Security.EncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt google client secret: %w", err)
			}
			oauthClientID = providerConf.ProviderClientID
			oauthClientSecret = decryptedSecret
		}
	}

	// 2. Fall back to global .env config
	if oauthClientID == "" {
		oauthClientID = s.cfg.OAuth.Google.ClientID
		oauthClientSecret = s.cfg.OAuth.Google.ClientSecret
	}

	// 3. No credentials available at all
	if oauthClientID == "" {
		return nil, errors.New("no Google OAuth credentials configured for this client")
	}

	conf := &oauth2.Config{
		ClientID:     oauthClientID,
		ClientSecret: oauthClientSecret,
		RedirectURL:  s.cfg.OAuth.Google.CallbackURL,
		Scopes:       []string{"https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/userinfo.profile"},
		Endpoint:     google.Endpoint,
	}
	return conf, nil
}

func (s *OAuthService) getGitHubConfig(clientID string) (*oauth2.Config, error) {
	var oauthClientID, oauthClientSecret string

	// 1. Try per-client config from DB first
	if clientID != "" && s.providerRepo != nil {
		providerConf, err := s.providerRepo.FindByClientAndProvider(clientID, "github")
		if err == nil && providerConf != nil {
			decryptedSecret, err := utils.Decrypt(providerConf.ProviderClientSecret, s.cfg.Security.EncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt github client secret: %w", err)
			}
			oauthClientID = providerConf.ProviderClientID
			oauthClientSecret = decryptedSecret
		}
	}

	// 2. Fall back to global .env config
	if oauthClientID == "" {
		oauthClientID = s.cfg.OAuth.GitHub.ClientID
		oauthClientSecret = s.cfg.OAuth.GitHub.ClientSecret
	}

	// 3. No credentials available at all
	if oauthClientID == "" {
		return nil, errors.New("no GitHub OAuth credentials configured for this client")
	}

	conf := &oauth2.Config{
		ClientID:     oauthClientID,
		ClientSecret: oauthClientSecret,
		RedirectURL:  s.cfg.OAuth.GitHub.CallbackURL,
		Scopes:       []string{"user:email"},
		Endpoint:     github.Endpoint,
	}
	return conf, nil
}

// GetGoogleAuthURL returns the URL to redirect the user to for Google login
func (s *OAuthService) GetGoogleAuthURL(clientID, state string) (string, error) {
	conf, err := s.getGoogleConfig(clientID)
	if err != nil {
		return "", err
	}
	return conf.AuthCodeURL(state), nil
}

// GetGitHubAuthURL returns the URL to redirect the user to for GitHub login
func (s *OAuthService) GetGitHubAuthURL(clientID, state string) (string, error) {
	conf, err := s.getGitHubConfig(clientID)
	if err != nil {
		return "", err
	}
	return conf.AuthCodeURL(state), nil
}

// ExchangeGoogleCode exchanges the authorization code for a token
func (s *OAuthService) ExchangeGoogleCode(ctx context.Context, clientID, code string) (*oauth2.Token, error) {
	conf, err := s.getGoogleConfig(clientID)
	if err != nil {
		return nil, err
	}
	return conf.Exchange(ctx, code)
}

// ExchangeGitHubCode exchanges the authorization code for a token
func (s *OAuthService) ExchangeGitHubCode(ctx context.Context, clientID, code string) (*oauth2.Token, error) {
	conf, err := s.getGitHubConfig(clientID)
	if err != nil {
		return nil, err
	}
	return conf.Exchange(ctx, code)
}

// FetchGoogleUser fetches user info from Google
func (s *OAuthService) FetchGoogleUser(ctx context.Context, clientID string, token *oauth2.Token) (map[string]interface{}, error) {
	conf, err := s.getGoogleConfig(clientID)
	if err != nil {
		return nil, err
	}
	client := conf.Client(ctx, token)
	resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("failed to fetch google user info")
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	return data, nil
}

// FetchGitHubUser fetches user info from GitHub
func (s *OAuthService) FetchGitHubUser(ctx context.Context, clientID string, token *oauth2.Token) (map[string]interface{}, error) {
	conf, err := s.getGitHubConfig(clientID)
	if err != nil {
		return nil, err
	}
	client := conf.Client(ctx, token)

	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, errors.New("failed to fetch github user info")
	}

	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}

	// GitHub email might be private, need separate call if not in profile
	if email, ok := data["email"].(string); !ok || email == "" {
		if privateEmail := fetchGitHubPrivateEmail(client); privateEmail != "" {
			data["email"] = privateEmail
		}
	}

	return data, nil
}

func fetchGitHubPrivateEmail(client *http.Client) string {
	respEmails, err := client.Get("https://api.github.com/user/emails")
	if err != nil || respEmails.StatusCode != 200 {
		return ""
	}
	defer respEmails.Body.Close()

	var emails []map[string]interface{}
	if err := json.NewDecoder(respEmails.Body).Decode(&emails); err != nil {
		return ""
	}

	for _, e := range emails {
		if primary, ok := e["primary"].(bool); ok && primary {
			if verified, ok := e["verified"].(bool); ok && verified {
				if emailStr, ok := e["email"].(string); ok {
					return emailStr
				}
			}
		}
	}
	return ""
}
