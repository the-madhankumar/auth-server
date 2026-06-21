package handler_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/roshankumar0036singh/auth-server/internal/handler"
	"github.com/roshankumar0036singh/auth-server/internal/service"
	"github.com/roshankumar0036singh/auth-server/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockAdminSvc struct {
	lockErr   error
	unlockErr error
	deleteErr error
	users      models.PaginatedUsers
    getUsersErr error
}

func (m *mockAdminSvc) LockUser(userID, adminID, ipAddress, userAgent string) error {
	return m.lockErr
}

func (m *mockAdminSvc) UnlockUser(userID, adminID, ipAddress, userAgent string) error {
	return m.unlockErr
}

func (m *mockAdminSvc) DeleteAccount(userID string) error {
	return m.deleteErr
}

func (m *mockAdminSvc) GetUsers(limit, offset int) (models.PaginatedUsers, error) {
    return m.users, m.getUsersErr
}

const (
	testAdminID = "admin-uuid-1234"
	testUserID  = "user-uuid-5678"
)

func newRouter(svc handler.AdminAuthService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()

	// Simulate what AuthMiddleware + RequireRole would set; no token parsing needed.
	r.Use(func(c *gin.Context) {
		c.Set("userID", testAdminID)
		c.Set("role", "admin")
		c.Next()
	})

	h := handler.NewAdminHandler(svc)
	r.POST("/api/admin/users/:id/lock", h.LockUser)
	r.POST("/api/admin/users/:id/unlock", h.UnlockUser)
	r.DELETE("/api/admin/users/:id", h.DeleteUser)

	return r
}

func doRequest(r *gin.Engine, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func responseCode(t *testing.T, w *httptest.ResponseRecorder) int {
	t.Helper()
	return w.Code
}

func TestAdminHandler_LockUser_Success(t *testing.T) {
	r := newRouter(&mockAdminSvc{lockErr: nil})
	w := doRequest(r, http.MethodPost, "/api/admin/users/"+testUserID+"/lock")

	assert.Equal(t, http.StatusOK, responseCode(t, w))

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, testUserID, body["data"].(map[string]interface{})["userID"])
}

func TestAdminHandler_LockUser_Errors(t *testing.T) {
	tests := []struct {
		name       string
		lockErr    error
		wantStatus int
	}{
		{"user not found", service.ErrUserNotFound, http.StatusNotFound},
		{"self lock", service.ErrSelfLock, http.StatusBadRequest},
		{"admin account", service.ErrAdminLock, http.StatusForbidden},
		{"already locked", service.ErrAlreadyLocked, http.StatusConflict},
		{"unexpected error", assert.AnError, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRouter(&mockAdminSvc{lockErr: tt.lockErr})
			w := doRequest(r, http.MethodPost, "/api/admin/users/"+testUserID+"/lock")
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}

func TestAdminHandler_UnlockUser_Success(t *testing.T) {
	r := newRouter(&mockAdminSvc{unlockErr: nil})
	w := doRequest(r, http.MethodPost, "/api/admin/users/"+testUserID+"/unlock")

	assert.Equal(t, http.StatusOK, responseCode(t, w))

	var body map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&body))
	assert.Equal(t, testUserID, body["data"].(map[string]interface{})["userID"])
}

func TestAdminHandler_UnlockUser_Errors(t *testing.T) {
	tests := []struct {
		name       string
		unlockErr  error
		wantStatus int
	}{
		{"user not found", service.ErrUserNotFound, http.StatusNotFound},
		{"not locked", service.ErrNotLocked, http.StatusBadRequest},
		{"unexpected error", assert.AnError, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRouter(&mockAdminSvc{unlockErr: tt.unlockErr})
			w := doRequest(r, http.MethodPost, "/api/admin/users/"+testUserID+"/unlock")
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
