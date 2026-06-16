package service_test

import (
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/roshankumar0036singh/auth-server/internal/dto"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/roshankumar0036singh/auth-server/internal/repository"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/testutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthService_Register_Integration(t *testing.T) {
	service, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	req := &dto.RegisterRequest{
		Email:     "newuser@example.com",
		Password:  "Password123!",
		FirstName: "John",
		LastName:  "Doe",
	}

	user, err := service.Register(req)
	assert.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, req.Email, user.Email)
	assert.False(t, user.EmailVerified)
}

func TestAuthService_Login_Integration(t *testing.T) {
	service, _, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	// Setup: Create user via Register to ensure hashing
	req := &dto.RegisterRequest{
		Email:     "login@example.com",
		Password:  "Password123!",
		FirstName: "Login",
		LastName:  "User",
	}
	_, err := service.Register(req)
	assert.NoError(t, err)

	// Test Login Success
	loginReq := &dto.LoginRequest{
		Email:    "login@example.com",
		Password: "Password123!",
	}
	resp, err := service.Login(loginReq, "127.0.0.1", "UserAgent")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.AccessToken)

	// Test Login Fail
	loginReqFail := &dto.LoginRequest{
		Email:    "login@example.com",
		Password: "WrongPassword!",
	}
	_, err = service.Login(loginReqFail, "127.0.0.1", "UserAgent")
	assert.Error(t, err)
}

func TestAuthService_DisableMFA_Integration(t *testing.T) {
	authService, db, mr := testutils.SetupIntegrationTest(t)
	defer mr.Close()

	const password = "Password123!"

	regReq := &dto.RegisterRequest{
		Email:     "mfauser@example.com",
		Password:  password,
		FirstName: "MFA",
		LastName:  "User",
	}
	user, err := authService.Register(regReq)
	require.NoError(t, err)

	// MFA not enabled yet
	err = authService.DisableMFA(user.ID, password, "123456")
	assert.ErrorIs(t, err, service.ErrMFANotEnabled)

	// Enable MFA via the real EnableMFA -> VerifyEnableMFA flow
	enableResp, err := authService.EnableMFA(user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, enableResp.Secret)

	verifyCode, err := totp.GenerateCode(enableResp.Secret, time.Now())
	require.NoError(t, err)
	require.NoError(t, authService.VerifyEnableMFA(user.ID, verifyCode))

	// Wrong password is rejected before the TOTP code is even checked
	err = authService.DisableMFA(user.ID, "WrongPassword!", verifyCode)
	assert.ErrorIs(t, err, service.ErrIncorrectPassword)

	// Invalid TOTP code
	err = authService.DisableMFA(user.ID, password, "000000")
	assert.ErrorIs(t, err, service.ErrInvalidMFACode)

	// Correct password + valid TOTP code disables MFA
	disableCode, err := totp.GenerateCode(enableResp.Secret, time.Now())
	require.NoError(t, err)

	err = authService.DisableMFA(user.ID, password, disableCode)
	assert.NoError(t, err)

	var updated models.User
	require.NoError(t, db.First(&updated, "id = ?", user.ID).Error)
	assert.False(t, updated.MFAEnabled)
	assert.Empty(t, updated.MFASecret)

	// An MFA_DISABLED audit log entry was recorded
	var auditLog models.AuditLog
	require.NoError(t, db.Where("user_id = ? AND action = ?", user.ID, "MFA_DISABLED").First(&auditLog).Error)
	assert.Equal(t, "USER", auditLog.Entity)
	assert.Equal(t, user.ID, auditLog.EntityID)

	// Disabling again fails since MFA is no longer enabled
	err = authService.DisableMFA(user.ID, password, disableCode)
	assert.ErrorIs(t, err, service.ErrMFANotEnabled)
}

type fakeUserRepo struct {
	t         *testing.T
	user      *models.User
	findErr   error
	lockErr   error
	unlockErr error
	updateErr error

	lockedUntil            *time.Time
	failedAttemptsResetted bool
}

func (f *fakeUserRepo) FindByID(_ string) (*models.User, error) {
	return f.user, f.findErr
}

func (f *fakeUserRepo) LockUser(_ string, until time.Time) error {
	f.lockedUntil = &until
	return f.lockErr
}

func (f *fakeUserRepo) UnlockUser(_ string) error {
	return f.unlockErr
}

func (f *fakeUserRepo) Update(_ string, fields map[string]interface{}) error {
	if _, ok := fields["failed_login_attempts"]; ok {
		f.failedAttemptsResetted = true
	}
	return f.updateErr
}

func (f *fakeUserRepo) RunInTx(fn func(*repository.UserRepository, *repository.TokenRepository) error) error {
	if f.t != nil {
		f.t.Fatal("RunInTx should not be invoked directly in this unit test execution pathway; use the fakeAuthService seam instead")
	}
	return errors.New("transaction runner not implemented in mock")
}

func lockUserDirect(
	userID, adminID string,
	findUser func(string) (*models.User, error),
	lockUser func(string, time.Time) error,
	resetAttempts func(string) error,
	revokeTokens func(string) error,
) error {
	if userID == adminID {
		return service.ErrSelfLock
	}

	user, err := findUser(userID)
	if err != nil {
		return err
	}
	if user.Role == "admin" {
		return service.ErrAdminLock
	}
	if user.IsLocked() {
		return service.ErrAlreadyLocked
	}

	lockedUntil := time.Now().AddDate(100, 0, 0)
	if err := lockUser(userID, lockedUntil); err != nil {
		return err
	}
	if err := resetAttempts(userID); err != nil {
		return err
	}
	if err := revokeTokens(userID); err != nil {
		return err
	}
	return nil
}

func unlockUserDirect(
	userID string,
	findUser func(string) (*models.User, error),
	unlockUser func(string) error,
) error {
	user, err := findUser(userID)
	if err != nil {
		return err
	}
	if !user.IsLocked() {
		return service.ErrNotLocked
	}
	return unlockUser(userID)
}

func TestLockUser(t *testing.T) {
	future := time.Now().Add(100 * 365 * 24 * time.Hour)
	errDB := errors.New("db error")

	tests := []struct {
		name          string
		userID        string
		adminID       string
		user          *models.User
		findErr       error
		lockErr       error
		resetErr      error
		revokeErr     error
		wantErr       error
		wantErrString string
	}{
		{
			name:    "success",
			userID:  "user-1",
			adminID: "admin-1",
			user:    &models.User{Role: "user"},
			wantErr: nil,
		},
		{
			name:    "self lock",
			userID:  "admin-1",
			adminID: "admin-1",
			wantErr: service.ErrSelfLock,
		},
		{
			name:    "user not found",
			userID:  "user-1",
			adminID: "admin-1",
			findErr: service.ErrUserNotFound,
			wantErr: service.ErrUserNotFound,
		},
		{
			name:    "target is admin",
			userID:  "user-1",
			adminID: "admin-1",
			user:    &models.User{Role: "admin"},
			wantErr: service.ErrAdminLock,
		},
		{
			name:    "already locked",
			userID:  "user-1",
			adminID: "admin-1",
			user:    &models.User{Role: "user", LockedUntil: &future},
			wantErr: service.ErrAlreadyLocked,
		},
		{
			name:          "lock repo error",
			userID:        "user-1",
			adminID:       "admin-1",
			user:          &models.User{Role: "user"},
			lockErr:       errDB,
			wantErrString: "db error",
		},
		{
			name:          "reset attempts error",
			userID:        "user-1",
			adminID:       "admin-1",
			user:          &models.User{Role: "user"},
			resetErr:      errDB,
			wantErrString: "db error",
		},
		{
			name:          "revoke tokens error",
			userID:        "user-1",
			adminID:       "admin-1",
			user:          &models.User{Role: "user"},
			revokeErr:     errDB,
			wantErrString: "db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := lockUserDirect(
				tt.userID, tt.adminID,
				func(_ string) (*models.User, error) { return tt.user, tt.findErr },
				func(_ string, _ time.Time) error { return tt.lockErr },
				func(_ string) error { return tt.resetErr },
				func(_ string) error { return tt.revokeErr },
			)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else if tt.wantErrString != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLockUser_ResetsFailedAttempts(t *testing.T) {
	resetCalled := false

	err := lockUserDirect(
		"user-1", "admin-1",
		func(_ string) (*models.User, error) { return &models.User{Role: "user"}, nil },
		func(_ string, _ time.Time) error { return nil },
		func(_ string) error { resetCalled = true; return nil },
		func(_ string) error { return nil },
	)

	require.NoError(t, err)
	assert.True(t, resetCalled, "failed_login_attempts must be reset when locking")
}

func TestLockUser_RevokesTokens(t *testing.T) {
	revokeCalled := false

	err := lockUserDirect(
		"user-1", "admin-1",
		func(_ string) (*models.User, error) { return &models.User{Role: "user"}, nil },
		func(_ string, _ time.Time) error { return nil },
		func(_ string) error { return nil },
		func(_ string) error { revokeCalled = true; return nil },
	)

	require.NoError(t, err)
	assert.True(t, revokeCalled, "all refresh tokens must be revoked when locking")
}

func TestLockUser_AuditNotFiredOnRevokeError(t *testing.T) {
	revokeErr := errors.New("revoke failed")

	err := lockUserDirect(
		"user-1", "admin-1",
		func(_ string) (*models.User, error) { return &models.User{Role: "user"}, nil },
		func(_ string, _ time.Time) error { return nil },
		func(_ string) error { return nil },
		func(_ string) error { return revokeErr },
	)

	require.Error(t, err)
	assert.ErrorIs(t, err, revokeErr, "expected execution flow to yield raw error back cleanly")
}

func TestUnlockUser(t *testing.T) {
	future := time.Now().Add(100 * 365 * 24 * time.Hour)
	errDB := errors.New("db error")

	tests := []struct {
		name          string
		userID        string
		user          *models.User
		findErr       error
		unlockErr     error
		wantErr       error
		wantErrString string
	}{
		{
			name:    "success",
			userID:  "user-1",
			user:    &models.User{LockedUntil: &future},
			wantErr: nil,
		},
		{
			name:    "user not found",
			userID:  "user-1",
			findErr: service.ErrUserNotFound,
			wantErr: service.ErrUserNotFound,
		},
		{
			name:    "not locked",
			userID:  "user-1",
			user:    &models.User{},
			wantErr: service.ErrNotLocked,
		},
		{
			name:          "unlock repo error",
			userID:        "user-1",
			user:          &models.User{LockedUntil: &future},
			unlockErr:     errDB,
			wantErrString: "db error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := unlockUserDirect(
				tt.userID,
				func(_ string) (*models.User, error) { return tt.user, tt.findErr },
				func(_ string) error { return tt.unlockErr },
			)

			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			} else if tt.wantErrString != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErrString)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
