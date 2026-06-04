package service

import (
	"bytes"
	"fmt"
	"html/template"
	"net/smtp"
	"path/filepath"

	"github.com/roshankumar0036singh/auth-server/internal/config"
)

type EmailSender interface {
	SendVerificationEmail(email, token, appURL string) error
	SendPasswordResetEmail(email, token, appURL string) error
}

type EmailService struct {
	config config.EmailConfig
}

func NewEmailService(cfg *config.Config) *EmailService {
	return &EmailService{
		config: cfg.Email,
	}
}

// SendEmail sends an email using SMTP
func (s *EmailService) SendEmail(to []string, subject string, templateName string, data interface{}) error {
	// Parse template
	// In production, templates should be cached on startup
	tmplPath := filepath.Join("templates", templateName)
	t, err := template.ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("failed to parse email template: %w", err)
	}

	var body bytes.Buffer
	if err := t.Execute(&body, data); err != nil {
		return fmt.Errorf("failed to execute email template: %w", err)
	}

	// Compose email headers and body
	headers := make(map[string]string)
	headers["From"] = s.config.FromEmail
	headers["To"] = to[0] // Simplify for single recipient
	headers["Subject"] = subject
	headers["MIME-Version"] = "1.0"
	headers["Content-Type"] = "text/html; charset=\"UTF-8\""

	message := ""
	for k, v := range headers {
		message += fmt.Sprintf("%s: %s\r\n", k, v)
	}
	message += "\r\n" + body.String()

	// Authenticate
	auth := smtp.PlainAuth("", s.config.SMTPUser, s.config.SMTPPassword, s.config.SMTPHost)

	// Send email
	addr := fmt.Sprintf("%s:%d", s.config.SMTPHost, s.config.SMTPPort)
	if err := smtp.SendMail(addr, auth, s.config.FromEmail, to, []byte(message)); err != nil {
		return fmt.Errorf("failed to send email: %w", err)
	}

	return nil
}

// SendVerificationEmail sends the email verification link
func (s *EmailService) SendVerificationEmail(email, token, appURL string) error {
	// Assuming frontend route is /verify-email?token=...
	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", appURL, token)

	data := struct {
		VerifyURL string
		AppName   string
	}{
		VerifyURL: verifyURL,
		AppName:   "Auth Server",
	}

	return s.SendEmail([]string{email}, "Verify your email", "verify_email.html", data)
}

// SendPasswordResetEmail sends the password reset link
func (s *EmailService) SendPasswordResetEmail(email, token, appURL string) error {
	// Assuming frontend route is /reset-password?token=...
	resetURL := fmt.Sprintf("%s/reset-password?token=%s", appURL, token)

	data := struct {
		ResetURL string
		AppName  string
	}{
		ResetURL: resetURL,
		AppName:  "Auth Server",
	}

	return s.SendEmail([]string{email}, "Reset your password", "reset_password.html", data)
}
