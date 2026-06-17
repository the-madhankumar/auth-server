package utils_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/roshankumar0036singh/auth-server/internal/utils"
)

func makeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

const validVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_extra12"

func TestS256_HappyPath(t *testing.T) {
	err := utils.VerifyPKCE(validVerifier, makeChallenge(validVerifier), "S256")
	if err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestS256_WrongVerifier(t *testing.T) {
	challenge := makeChallenge(validVerifier)
	wrong := "wrongverifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	if err := utils.VerifyPKCE(wrong, challenge, "S256"); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestS256_TooShort(t *testing.T) {
	if err := utils.VerifyPKCE("tooshort", "anychallenge", "S256"); err == nil {
		t.Fatal("expected error for short verifier")
	}
}

func TestPlain_HappyPath(t *testing.T) {
	if err := utils.VerifyPKCE(validVerifier, validVerifier, "plain"); err != nil {
		t.Fatalf("expected nil, got: %v", err)
	}
}

func TestPlain_WrongVerifier(t *testing.T) {
	wrong := "wrongverifier-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
	if err := utils.VerifyPKCE(wrong, validVerifier, "plain"); err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestUnsupportedMethod(t *testing.T) {
	if err := utils.VerifyPKCE(validVerifier, validVerifier, "RS256"); err == nil {
		t.Fatal("expected error for unsupported method")
	}
}

func TestEmptyVerifier(t *testing.T) {
	if err := utils.VerifyPKCE("", "anychallenge", "S256"); err == nil {
		t.Fatal("expected error for empty verifier")
	}
}
