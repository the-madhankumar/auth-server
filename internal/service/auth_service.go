package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/roshankumar0036singh/auth-server/internal/config"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/utils"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrSelfLock      = errors.New("admin cannot lock their own account")
	ErrAdminLock     = errors.New("admin accounts cannot be locked")
	ErrAlreadyLocked = errors.New("account is already locked")
	ErrNotLocked     = errors.New("account is not locked")
)

const (
	errGenAccessToken    = "failed to generate access token"
	errGenRefreshToken   = "failed to generate refresh token"
	errStoreRefreshToken = "failed to store refresh token"
	errHashPassword      = "failed to hash password"
)

type AuthService struct {
	userRepo          *repository.UserRepository
	tokenRepo         *repository.TokenRepository
	verificationRepo  *repository.VerificationRepository
	passwordResetRepo *repository.PasswordResetRepository
	tokenService      *TokenService
	cacheService      *CacheService
	emailService      EmailSender
	auditService      *AuditService
	mfaService        *MFAService
	config            *config.Config
}

func NewAuthService(
	userRepo *repository.UserRepository,
	tokenRepo *repository.TokenRepository,
	verificationRepo *repository.VerificationRepository,
	passwordResetRepo *repository.PasswordResetRepository,
	tokenService *TokenService,
	cacheService *CacheService,
	emailService EmailSender,
	auditService *AuditService,
	mfaService *MFAService,
	cfg *config.Config,
) *AuthService {
	return &AuthService{
		userRepo:          userRepo,
		tokenRepo:         tokenRepo,
		verificationRepo:  verificationRepo,
		passwordResetRepo: passwordResetRepo,
		tokenService:      tokenService,
		cacheService:      cacheService,
		emailService:      emailService,
		auditService:      auditService,
		mfaService:        mfaService,
		config:            cfg,
	}
}

// ... Register and other methods remain same ...

// ForgotPassword initiates the password reset flow
func (s *AuthService) ForgotPassword(email string) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// Return nil to prevent email enumeration
		return nil
	}

	// Delete existing reset tokens
	s.passwordResetRepo.DeleteByUserID(user.ID)

	// Create new reset token
	token := &models.PasswordResetToken{
		UserID:    user.ID,
		Token:     s.tokenService.GenerateRandomString(32),
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}

	if err := s.passwordResetRepo.Create(token); err != nil {
		return err
	}

	// Send email
	err = s.emailService.SendPasswordResetEmail(user.Email, token.Token, s.config.App.URL)
	if err == nil {
		s.auditService.LogEvent(&user.ID, "PASSWORD_RESET_REQUESTED", "USER", user.ID, "", "", nil)
	}
	return err
}

// ResetPassword resets the user's password using a valid token
func (s *AuthService) ResetPassword(tokenString, newPassword string) error {
	// Find token
	token, err := s.passwordResetRepo.FindByToken(tokenString)
	if err != nil {
		return errors.New("invalid or expired reset token")
	}

	if token.IsExpired() {
		return errors.New("reset token has expired")
	}

	if token.Used {
		return errors.New("reset token has already been used")
	}

	// Validate password strength
	if err := utils.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New(errHashPassword)
	}

	// Update user password
	if err := s.userRepo.Update(token.UserID, map[string]interface{}{
		"password_hash": string(hashedPassword),
	}); err != nil {
		return errors.New("failed to update password")
	}

	// Mark token as used
	s.passwordResetRepo.MarkAsUsed(token.ID)

	// Revoke all existing sessions for security
	s.tokenRepo.RevokeAllUserTokens(token.UserID)

	// Audit Log
	s.auditService.LogEvent(&token.UserID, "PASSWORD_RESET_SUCCESS", "USER", token.UserID, "", "", nil)

	return nil
}

// UpdateProfile updates user profile information
func (s *AuthService) UpdateProfile(userID string, req *dto.UpdateProfileRequest) (*models.User, error) {
	updates := make(map[string]interface{})

	if req.FirstName != "" {
		updates["first_name"] = req.FirstName
	}
	if req.LastName != "" {
		updates["last_name"] = req.LastName
	}
	if req.Phone != "" {
		updates["phone"] = req.Phone
	}

	if len(updates) == 0 {
		return s.userRepo.FindByID(userID)
	}

	if err := s.userRepo.Update(userID, updates); err != nil {
		return nil, errors.New("failed to update profile")
	}

	// Audit Log
	s.auditService.LogEvent(&userID, "PROFILE_UPDATED", "USER", userID, "", "", nil)

	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetUserAuditLogs proxies the call to audit service
func (s *AuthService) GetUserAuditLogs(userID string) ([]models.AuditLog, error) {
	return s.auditService.GetUserAuditLogs(userID)
}

// ChangePassword changes the user's password
func (s *AuthService) ChangePassword(userID string, req *dto.ChangePasswordRequest) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	// Verify current password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		return errors.New("incorrect current password")
	}

	// Validate password strength
	if err := utils.ValidatePassword(req.NewPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New(errHashPassword)
	}

	// Update password
	if err := s.userRepo.Update(userID, map[string]interface{}{
		"password_hash": string(hashedPassword),
	}); err != nil {
		return errors.New("failed to update password")
	}

	// Revoke all other sessions? Maybe optional, but good practice for security.
	// For now, let's keep current session active.

	// Audit Log
	s.auditService.LogEvent(&userID, "PASSWORD_CHANGED", "USER", userID, "", "", nil)

	return nil
}

// DeleteAccount soft deletes the user account
func (s *AuthService) DeleteAccount(userID string) error {
	// Revoke all tokens first
	if err := s.tokenRepo.RevokeAllUserTokens(userID); err != nil {
		// Log error but proceed
	}

	// Delete user (Soft delete via GORM)
	err := s.userRepo.Delete(userID)
	if err != nil {
		return err
	}
	// Audit Log
	s.auditService.LogEvent(&userID, "ACCOUNT_DELETED", "USER", userID, "", "", nil)
	return nil
}

// EnableMFA generates a secret and returns it with QR code URL
func (s *AuthService) EnableMFA(userID string) (*dto.MFAEnableResponse, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if user.MFAEnabled {
		return nil, errors.New("MFA is already enabled")
	}

	secret, qrCodeURL, err := s.mfaService.GenerateMFA(user.Email)
	if err != nil {
		return nil, err
	}

	// Save temp secret
	if err := s.userRepo.Update(userID, map[string]interface{}{
		"mfa_secret": secret,
	}); err != nil {
		return nil, errors.New("failed to save temp MFA secret")
	}

	return &dto.MFAEnableResponse{
		Secret:    secret,
		QRCodeURL: qrCodeURL,
	}, nil
}

// VerifyEnableMFA verifies the code and enables MFA
func (s *AuthService) VerifyEnableMFA(userID, code string) error {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	if user.MFAEnabled {
		return errors.New("MFA is already enabled")
	}

	if user.MFASecret == "" {
		return errors.New("MFA setup not initiated")
	}

	if !s.mfaService.ValidateMFA(user.MFASecret, code) {
		return errors.New("invalid TOTP code")
	}

	// Enable MFA
	if err := s.userRepo.Update(userID, map[string]interface{}{
		"mfa_enabled": true,
	}); err != nil {
		return errors.New("failed to enable MFA")
	}

	s.auditService.LogEvent(&userID, "MFA_ENABLED", "USER", userID, "", "", nil)
	return nil
}

// VerifyLoginMFA completes the login process with MFA code
func (s *AuthService) VerifyLoginMFA(email, code, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return nil, ErrUserNotFound
	}

	if !user.MFAEnabled {
		return nil, errors.New("MFA not enabled for this user")
	}

	if !s.mfaService.ValidateMFA(user.MFASecret, code) {
		s.auditService.LogEvent(&user.ID, "MFA_LOGIN_FAILED", "USER", user.ID, ipAddress, userAgent, nil)
		return nil, errors.New("invalid TOTP code")
	}

	response, err := s.createLoginResponse(user, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	s.auditService.LogEvent(&user.ID, "USER_LOGIN_SUCCESS_MFA", "USER", user.ID, ipAddress, userAgent, nil)

	return response, nil

}

// Register creates a new user account and sends verification email
func (s *AuthService) Register(req *dto.RegisterRequest) (*models.User, error) {
	// Check if email already exists
	exists, err := s.userRepo.EmailExists(req.Email)
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New("email already registered")
	}

	// Validate password strength
	if err := utils.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New(errHashPassword)
	}

	// Create user
	user := &models.User{
		Email:         req.Email,
		PasswordHash:  string(hashedPassword),
		FirstName:     req.FirstName,
		LastName:      req.LastName,
		OAuthProvider: "local",
		IsActive:      true, // Can allow login but restrict features, or set false
		EmailVerified: false,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, errors.New("failed to create user")
	}

	// Generate and send verification email
	if err := s.sendVerificationEmail(user); err != nil {
		// Log error but don't fail registration
		log.Printf("Failed to send verification email to %s: %v", user.Email, err)
	}

	// Audit Log
	s.auditService.LogEvent(&user.ID, "USER_REGISTERED", "USER", user.ID, "", "", nil)

	return user, nil
}

func (s *AuthService) sendVerificationEmail(user *models.User) error {
	// Generate verification token
	token := &models.VerificationToken{
		UserID:    user.ID,
		Token:     s.tokenService.GenerateRandomString(32),
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	if err := s.verificationRepo.Create(token); err != nil {
		return err
	}

	// Send email
	return s.emailService.SendVerificationEmail(user.Email, token.Token, s.config.App.URL)
}

// VerifyEmail verifies a user's email address
func (s *AuthService) VerifyEmail(tokenString string) error {
	// Find token
	token, err := s.verificationRepo.FindByToken(tokenString)
	if err != nil {
		return errors.New("invalid or expired verification token")
	}

	// Check expiry
	if token.IsExpired() {
		return errors.New("verification token has expired")
	}

	// Update user
	if err := s.userRepo.Update(token.UserID, map[string]interface{}{
		"email_verified": true,
	}); err != nil {
		return errors.New("failed to verify email")
	}

	// Delete used token (and potentially all tokens for this user)
	s.verificationRepo.DeleteByUserID(token.UserID)

	return nil
}

// ResendVerification sends a new verification email
func (s *AuthService) ResendVerification(email string) error {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return ErrUserNotFound
	}

	if user.EmailVerified {
		return errors.New("email already verified")
	}

	// Delete existing tokens
	s.verificationRepo.DeleteByUserID(user.ID)

	// Send new email
	return s.sendVerificationEmail(user)
}

// Login authenticates a user and returns tokens with device tracking
func (s *AuthService) Login(req *dto.LoginRequest, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	ctx := context.Background()

	// Check login attempts (Redis - brute force mitigation for IP/User combination)
	attempts, err := s.cacheService.GetLoginAttempts(ctx, req.Email)
	if err == nil && attempts >= int64(s.config.Security.RateLimitMax) {
		return nil, errors.New("too many login attempts, please try again later")
	}

	user, err := s.userRepo.FindByEmail(req.Email)
	if err != nil {
		// Increment attempts even for non-existent users (to prevent enumeration)
		s.cacheService.IncrementLoginAttempts(ctx, req.Email)
		return nil, errors.New("invalid email or password")
	}

	// Check if account is locked (Database - persistent lock)
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		return nil, fmt.Errorf("account is locked until %v", user.LockedUntil)
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		s.handleFailedLogin(user, req.Email, ctx)
		return nil, errors.New("invalid email or password")
	}

	// Reset failed attempts on successful login
	if user.FailedLoginAttempts > 0 || user.LockedUntil != nil {
		s.userRepo.Update(user.ID, map[string]interface{}{
			"failed_login_attempts": 0,
			"locked_until":          nil,
		})
	}

	// Reset Redis attempts too
	s.cacheService.ResetLoginAttempts(ctx, req.Email)

	// Check if user is active
	if !user.IsActive {
		return nil, errors.New("account is deactivated")
	}

	// Check MFA
	if user.MFAEnabled {
		return nil, errors.New("mfa_required")
	}

	// Update last login
	if err := s.userRepo.Update(user.ID, map[string]interface{}{"last_login_at": time.Now()}); err != nil {
		log.Printf("Failed to update last login for user %s: %v", user.ID, err)
	}

	response, err := s.createLoginResponse(user, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	// Audit Log
	s.auditService.LogEvent(&user.ID, "USER_LOGIN_SUCCESS", "USER", user.ID, ipAddress, userAgent, nil)

	return response, nil
}

// LoginWithOAuth handles login or registration via OAuth provider
func (s *AuthService) LoginWithOAuth(email, oauthID, firstName, lastName, provider, ipAddress, userAgent string) (*dto.LoginResponse, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		// User does not exist, create new one
		password := s.tokenService.GenerateRandomString(32)
		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		user = &models.User{
			Email:         email,
			PasswordHash:  string(hashedPassword),
			FirstName:     firstName,
			LastName:      lastName,
			OAuthProvider: provider,
			OAuthID:       oauthID,
			IsActive:      true,
			EmailVerified: true, // Trusted from OAuth
		}

		if err := s.userRepo.Create(user); err != nil {
			return nil, errors.New("failed to create user")
		}

		s.auditService.LogEvent(&user.ID, "USER_REGISTERED_OAUTH", "USER", user.ID, "", "", map[string]interface{}{"provider": provider})
	} else {
		// User exists, link account if not generic local
		// For now simple logic: if email matches, we log them in and update OAuth info if missing
		updates := make(map[string]interface{})
		if user.OAuthID == "" {
			updates["oauth_provider"] = provider
			updates["oauth_id"] = oauthID
			// Also mark email as verified if not already
			if !user.EmailVerified {
				updates["email_verified"] = true
			}
			s.userRepo.Update(user.ID, updates)
			s.auditService.LogEvent(&user.ID, "ACCOUNT_LINKED_OAUTH", "USER", user.ID, "", "", map[string]interface{}{"provider": provider})
		}
	}

	response, err := s.createLoginResponse(user, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	s.auditService.LogEvent(&user.ID, "USER_LOGIN_SUCCESS_OAUTH", "USER", user.ID, ipAddress, userAgent, nil)

	return response, nil

}

func (s *AuthService) handleFailedLogin(user *models.User, email string, ctx context.Context) {
	// Increment Redis counter (cheap, fast)
	s.cacheService.IncrementLoginAttempts(ctx, email)

	// Increment Database counter (persistent)
	attempts := user.FailedLoginAttempts + 1
	updates := map[string]interface{}{
		"failed_login_attempts": attempts,
	}

	if attempts >= s.config.Security.AccountLockMaxAttempts {
		lockDuration := time.Duration(s.config.Security.AccountLockDuration) * time.Minute
		lockedUntil := time.Now().Add(lockDuration)
		updates["locked_until"] = lockedUntil
		// Audit Log Lock
		s.auditService.LogEvent(&user.ID, "ACCOUNT_LOCKED", "USER", user.ID, "", "", map[string]interface{}{"reason": "too_many_failed_attempts"})
	}

	s.userRepo.Update(user.ID, updates)

	// Audit Log Failed Login
	s.auditService.LogEvent(&user.ID, "USER_LOGIN_FAILED", "USER", user.ID, "", "", map[string]interface{}{"email": email})
}

// RefreshAccessToken generates a new access token using refresh token with rotation
func (s *AuthService) RefreshAccessToken(refreshTokenString string, ipAddress, userAgent string) (*dto.TokenRefreshResponse, error) {
	ctx := context.Background()

	// Validate refresh token JWT
	claims, err := s.tokenService.ValidateRefreshToken(refreshTokenString)
	if err != nil {
		return nil, errors.New("invalid or expired refresh token")
	}

	// Check if token is blacklisted
	blacklisted, err := s.cacheService.IsTokenBlacklisted(ctx, refreshTokenString)
	if err != nil {
		log.Printf("Warning: Failed to check token blacklist: %v", err)
	}
	if blacklisted {
		return nil, errors.New("refresh token has been revoked")
	}

	// Find refresh token in database
	storedToken, err := s.tokenRepo.FindRefreshToken(refreshTokenString)
	if err != nil {
		return nil, errors.New("refresh token not found")
	}

	// Verify token is valid (not revoked and not expired)
	if !storedToken.IsValid() {
		return nil, errors.New("refresh token is invalid or expired")
	}

	// Get user
	user, err := s.userRepo.FindByID(claims.UserID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	// Token rotation: Generate new refresh token
	newRefreshTokenString, err := s.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return nil, errors.New(errGenRefreshToken)
	}

	// Store new refresh token
	newRefreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     newRefreshTokenString,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	// Generate new access token
	newAccessToken, err := s.tokenService.GenerateAccessToken(user, newRefreshToken.ID)
	if err != nil {
		return nil, errors.New(errGenAccessToken)
	}

	// transaction handling creation and rotation of refresh tokens
	if err := s.tokenRepo.RotateRefreshToken(
		refreshTokenString,
		newRefreshToken,
	); err != nil {
		return nil, errors.New("failed to rotate refresh token")
	}

	return &dto.TokenRefreshResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshTokenString,
	}, nil
}

// Logout revokes the refresh token and blacklists the access token
func (s *AuthService) Logout(accessToken, refreshToken string) error {
	ctx := context.Background()

	// Blacklist access token (expires in 15 minutes)
	if accessToken != "" {
		if err := s.cacheService.BlacklistToken(ctx, accessToken, 15*time.Minute); err != nil {
			log.Printf("Warning: Failed to blacklist access token: %v", err)
		}
	}

	// Revoke refresh token in database
	if refreshToken != "" {
		if err := s.tokenRepo.RevokeRefreshToken(refreshToken); err != nil {
			log.Printf("Warning: Failed to revoke refresh token: %v", err)
		}
	}

	return nil
}

// LogoutAll revokes all refresh tokens for a user
func (s *AuthService) LogoutAll(userID string, currentAccessToken string) error {
	ctx := context.Background()

	// Blacklist current access token
	if currentAccessToken != "" {
		if err := s.cacheService.BlacklistToken(ctx, currentAccessToken, 15*time.Minute); err != nil {
			log.Printf("Warning: Failed to blacklist access token: %v", err)
		}
	}

	// Revoke all user refresh tokens
	if err := s.tokenRepo.RevokeAllUserTokens(userID); err != nil {
		return errors.New("failed to revoke all sessions")
	}

	return nil
}

// GetUserByID retrieves a user by ID
func (s *AuthService) GetUserByID(userID string) (*models.User, error) {
	user, err := s.userRepo.FindByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}
	return user, nil
}

// GetUserSessions retrieves all active sessions for a user
func (s *AuthService) GetUserSessions(userID string) ([]models.RefreshToken, error) {
	tokens, err := s.tokenRepo.FindUserRefreshTokens(userID)
	if err != nil {
		return nil, errors.New("failed to retrieve sessions")
	}
	return tokens, nil
}

// RevokeSession revokes a specific session by token ID
func (s *AuthService) RevokeSession(userID, tokenID string) error {
	// Verify the token belongs to the user
	token, err := s.tokenRepo.FindRefreshTokenByID(tokenID)
	if err != nil {
		return errors.New("session not found")
	}

	if token.UserID != userID {
		return errors.New("unauthorized to revoke this session")
	}

	if err := s.tokenRepo.RevokeRefreshTokenByID(tokenID); err != nil {
		return errors.New("failed to revoke session")
	}

	return nil
}

type userLocker interface {
	FindByID(id string) (*models.User, error)
}

func validateLockUser(repo userLocker, userID string) error {
	user, err := repo.FindByID(userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return ErrUserNotFound
		}
		return err
	}
	if user.Role == "admin" {
		return ErrAdminLock
	}
	if user.IsLocked() {
		return ErrAlreadyLocked
	}
	return nil
}

func (s *AuthService) LockUser(userID, adminID, ipAddress, userAgent string) error {
	if userID == adminID {
		return ErrSelfLock
	}

	var lockedUntil time.Time

	err := s.userRepo.RunInTx(func(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository) error {
		if err := validateLockUser(userRepo, userID); err != nil {
			return err
		}

		lockedUntil = time.Now().AddDate(100, 0, 0)

		if err := userRepo.LockUser(userID, lockedUntil); err != nil {
			return fmt.Errorf("lock user: %w", err)
		}

		if err := userRepo.Update(userID, map[string]interface{}{
			"failed_login_attempts": 0,
		}); err != nil {
			return fmt.Errorf("reset failed login attempts: %w", err)
		}

		if err := tokenRepo.RevokeAllUserTokens(userID); err != nil {
			return fmt.Errorf("revoke user tokens: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := s.auditService.LogEvent(
		&adminID,
		"USER_LOCKED",
		"USER",
		userID,
		ipAddress,
		userAgent,
		map[string]interface{}{"locked_until": lockedUntil},
	); err != nil {
		log.Printf("failed to write USER_LOCKED audit log: %v", err)
	}

	return nil
}

// UnlockUser removes the account lock state.
// Previously revoked refresh tokens remain revoked and are not restored.
// Users must log in again after the account is unlocked.
func (s *AuthService) UnlockUser(userID, adminID, ipAddress, userAgent string) error {
	err := s.userRepo.RunInTx(func(userRepo *repository.UserRepository, tokenRepo *repository.TokenRepository) error {
		user, err := userRepo.FindByID(userID)
		if err != nil {
			return err
		}

		if !user.IsLocked() {
			return ErrNotLocked
		}

		if err := userRepo.UnlockUser(userID); err != nil {
			return fmt.Errorf("unlock user: %w", err)
		}

		return nil
	})

	if err != nil {
		return err
	}

	if err := s.auditService.LogEvent(
		&adminID,
		"USER_UNLOCKED",
		"USER",
		userID,
		ipAddress,
		userAgent,
		map[string]interface{}{"locked_until": nil},
	); err != nil {
		log.Printf("failed to write USER_UNLOCKED audit log: %v", err)
	}

	return nil
}

func (s *AuthService) createLoginResponse(
	user *models.User,
	ipAddress string,
	userAgent string,
) (*dto.LoginResponse, error) {

	refreshTokenString, err := s.tokenService.GenerateRefreshToken(user)
	if err != nil {
		return nil, errors.New("failed to generate refresh token")
	}

	refreshToken := &models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshTokenString,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		IPAddress: ipAddress,
		UserAgent: userAgent,
	}

	if err := s.tokenRepo.CreateRefreshToken(refreshToken); err != nil {
		return nil, errors.New(errStoreRefreshToken)
	}

	accessToken, err := s.tokenService.GenerateAccessToken(user, refreshToken.ID)
	if err != nil {
		return nil, errors.New(errGenAccessToken)
	}

	return &dto.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshTokenString,
		User:         user.ToPublic(),
	}, nil
}
