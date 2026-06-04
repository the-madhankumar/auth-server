package service

import (
	"bytes"
	"encoding/base64"
	"github.com/pquerna/otp/totp"
	"github.com/roshankumar0036singh/auth-server/internal/config"
	"image/png"
)

type MFAService struct {
	config *config.Config
}

func NewMFAService(cfg *config.Config) *MFAService {
	return &MFAService{
		config: cfg,
	}
}

// GenerateMFA generates a new TOTP secret and QR code for the user
func (s *MFAService) GenerateMFA(userEmail string) (string, string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "GoAuthServer",
		AccountName: userEmail,
	})
	if err != nil {
		return "", "", err
	}

	// Convert image to base64 for frontend display
	var buf bytes.Buffer
	img, err := key.Image(200, 200)
	if err != nil {
		return "", "", err
	}

	if err := png.Encode(&buf, img); err != nil {
		return "", "", err
	}

	qrCodeBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	qrCodeURL := "data:image/png;base64," + qrCodeBase64

	return key.Secret(), qrCodeURL, nil
}

// VerifyMFA validates a TOTP code against a secret
func (s *MFAService) ValidateMFA(secret, code string) bool {
	valid := totp.Validate(code, secret)
	return valid
}

// GenerateValidationCode (Optional) - standard TOTP libraries handle validation
// We just need ValidateMFA for login/verification
