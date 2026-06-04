package service_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestOAuthProviderService(t *testing.T) {
	_, db, _ := testutils.SetupIntegrationTest(t)

	db.Exec(`CREATE TABLE oauth_clients (
		id text PRIMARY KEY,
		name text NOT NULL,
		client_id text NOT NULL,
		client_secret text NOT NULL,
		redirect_uris text,
		scopes text,
		owner_id text,
		is_active boolean DEFAULT true,
		created_at datetime,
		updated_at datetime
	)`)
	db.Exec(`CREATE TABLE oauth_provider_configs (
		id text PRIMARY KEY,
		client_id text NOT NULL,
		provider text NOT NULL,
		provider_client_id text NOT NULL,
		provider_client_secret text NOT NULL,
		created_at datetime,
		updated_at datetime
	)`)

	clientRepo := repository.NewOAuthClientRepository(db)
	codeRepo := repository.NewAuthorizationCodeRepository(db)
	tokenRepo := repository.NewOAuthTokenRepository(db)
	consentRepo := repository.NewUserConsentRepository(db)
	configRepo := repository.NewOAuthProviderConfigRepository(db)

	cfg := &config.Config{
		Security: config.SecurityConfig{
			EncryptionKey: "12345678901234567890123456789012",
		},
	}
	tokenService := service.NewTokenService(cfg)

	providerService := service.NewOAuthProviderService(
		clientRepo, codeRepo, tokenRepo, consentRepo, configRepo, tokenService, cfg,
	)

	// Create a user and a client
	ownerID := "user1"
	otherOwnerID := "user2"

	client, _, err := providerService.CreateClient("test-client", []string{"http://localhost"}, []string{"read:profile"}, ownerID)
	assert.NoError(t, err)

	t.Run("CreateOrUpdateProviderConfig - Success", func(t *testing.T) {
		err := providerService.CreateOrUpdateProviderConfig(ownerID, client.ID, "google", "g-id", "g-secret")
		assert.NoError(t, err)

		conf, err := providerService.GetProviderConfig(ownerID, client.ID, "google")
		assert.NoError(t, err)
		assert.Equal(t, "g-id", conf.ProviderClientID)
		// It should be encrypted
		assert.NotEqual(t, "g-secret", conf.ProviderClientSecret)
	})

	t.Run("CreateOrUpdateProviderConfig - Unauthorized", func(t *testing.T) {
		err := providerService.CreateOrUpdateProviderConfig(otherOwnerID, client.ID, "google", "g-id", "g-secret")
		assert.ErrorIs(t, err, service.ErrUnauthorized)
	})

	t.Run("GetProviderConfig - Unauthorized", func(t *testing.T) {
		_, err := providerService.GetProviderConfig(otherOwnerID, client.ID, "google")
		assert.ErrorIs(t, err, service.ErrUnauthorized)
	})

	t.Run("DeleteProviderConfig - Success", func(t *testing.T) {
		err := providerService.DeleteProviderConfig(ownerID, client.ID, "google")
		assert.NoError(t, err)

		_, err = providerService.GetProviderConfig(ownerID, client.ID, "google")
		assert.Error(t, err)
	})

	t.Run("DeleteProviderConfig - Unauthorized", func(t *testing.T) {
		// recreate
		providerService.CreateOrUpdateProviderConfig(ownerID, client.ID, "google", "g-id", "g-secret")

		err := providerService.DeleteProviderConfig(otherOwnerID, client.ID, "google")
		assert.ErrorIs(t, err, service.ErrUnauthorized)
	})
}
