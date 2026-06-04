package utils

import "github.com/gin-gonic/gin"

// Response structures for consistent API responses

type Response struct {
	Success bool         `json:"success"`
	Message string       `json:"message,omitempty"`
	Data    interface{}  `json:"data,omitempty"`
	Error   *ErrorDetail `json:"error,omitempty"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// SuccessResponse creates a success response
func SuccessResponse(message string, data interface{}) Response {
	return Response{
		Success: true,
		Message: message,
		Data:    data,
	}
}

// ErrorResponse creates an error response
func ErrorResponse(message string, err error) Response {
	var errMsg string
	if err != nil {
		errMsg = err.Error()
	} else {
		errMsg = message
	}

	return Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "ERROR",
			Message: errMsg,
		},
	}
}

// ValidationErrorResponse creates a validation error response
func ValidationErrorResponse(message string) Response {
	return Response{
		Success: false,
		Error: &ErrorDetail{
			Code:    "VALIDATION_ERROR",
			Message: message,
		},
	}
}

// UnauthorizedResponse returns a 401 Unauthorized response
func UnauthorizedResponse(message string) Response {
	return Response{
		Success: false,
		Message: message,
	}
}

// ForbiddenResponse returns a 403 Forbidden response
func ForbiddenResponse(message string) Response {
	return Response{
		Success: false,
		Message: message,
	}
}

// BadRequestResponse returns a 400 Bad Request response
func BadRequestResponse(c interface{}, message string) {
	// Type assertion to *gin.Context
	if ctx, ok := c.(*gin.Context); ok {
		ctx.JSON(400, Response{
			Success: false,
			Message: message,
		})
	}
}

// InternalServerErrorResponse returns a 500 Internal Server Error response
func InternalServerErrorResponse(c interface{}, message string) {
	// Type assertion to *gin.Context
	if ctx, ok := c.(*gin.Context); ok {
		ctx.JSON(500, Response{
			Success: false,
			Message: message,
		})
	}
}
