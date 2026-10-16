package onlydns

import (
	"fmt"
	"strings"
)

// APIError represents an error returned by the OnlyDNS API.
type APIError struct {
	StatusCode int
	Message    string
	Details    []string
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("[%d] %s", e.StatusCode, e.Message)
	if len(e.Details) > 0 {
		msg += fmt.Sprintf(" - Details: %s", strings.Join(e.Details, "; "))
	}
	return msg
}

// AuthenticationError is returned when authentication fails (HTTP 401).
type AuthenticationError struct {
	APIError
}

func (e *AuthenticationError) Error() string {
	return e.APIError.Error()
}

// NotFoundError is returned when a requested domain or key is not found (HTTP 404).
type NotFoundError struct {
	APIError
}

func (e *NotFoundError) Error() string {
	return e.APIError.Error()
}

// ValidationError is returned when request parameters are invalid (HTTP 400).
type ValidationError struct {
	APIError
}

func (e *ValidationError) Error() string {
	return e.APIError.Error()
}
