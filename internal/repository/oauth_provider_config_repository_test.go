package repository_test

import (
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
)

func TestOAuthProviderConfigRepository(t *testing.T) {
	_, db, _ := testutils.SetupIntegrationTest(t)
	db.Exec(`CREATE TABLE oauth_provider_configs (
		id text PRIMARY KEY,
		client_id text NOT NULL,
		provider text NOT NULL,
		provider_client_id text NOT NULL,
		provider_client_secret text NOT NULL,
		created_at datetime,
		updated_at datetime
	)`)
	repo := repository.NewOAuthProviderConfigRepository(db)

	config := &models.OAuthProviderConfig{
		ClientID:             "client1",
		Provider:             "google",
		ProviderClientID:     "g-client-id",
		ProviderClientSecret: "g-client-secret",
	}

	t.Run("Create", func(t *testing.T) {
		err := repo.Create(config)
		assert.NoError(t, err)
		assert.NotEmpty(t, config.ID)
	})

	t.Run("FindByClientAndProvider", func(t *testing.T) {
		found, err := repo.FindByClientAndProvider("client1", "google")
		assert.NoError(t, err)
		assert.NotNil(t, found)
		assert.Equal(t, "g-client-id", found.ProviderClientID)
	})

	t.Run("FindByClientAndProvider NotFound", func(t *testing.T) {
		found, err := repo.FindByClientAndProvider("client1", "github")
		assert.Error(t, err)
		assert.Nil(t, found)
	})

	t.Run("Update", func(t *testing.T) {
		config.ProviderClientID = "g-client-id-new"
		err := repo.Update(config)
		assert.NoError(t, err)

		found, _ := repo.FindByClientAndProvider("client1", "google")
		assert.Equal(t, "g-client-id-new", found.ProviderClientID)
	})

	t.Run("Delete", func(t *testing.T) {
		err := repo.Delete(config.ID)
		assert.NoError(t, err)

		found, err := repo.FindByClientAndProvider("client1", "google")
		assert.Error(t, err)
		assert.Nil(t, found)
	})
}
