package oauth2

import (
	"fmt"
	"net/http"
)

// Error interface for most error types, particularly new ones.
type Error interface {
	Error() string

	GetErrorCode() string
	GetErrorDescription() string
	GetErrorURI() string
	GetResponse() *http.Response
	GetBody() []byte
}

type BaseError struct {
	Response *http.Response

	Body []byte

	// ErrorCode is RFC 6749's 'error' parameter.
	ErrorCode string
	// ErrorDescription is RFC 6749's 'error_description' parameter.
	ErrorDescription string
	// ErrorURI is RFC 6749's 'error_uri' parameter.
	ErrorURI string
}

func (r *BaseError) GetErrorCode() string {
	return r.ErrorCode
}

func (r *BaseError) GetErrorDescription() string {
	return r.ErrorDescription
}

func (r *BaseError) GetErrorURI() string {
	return r.ErrorURI
}

func (r *BaseError) GetResponse() *http.Response {
	return r.Response
}

func (r *BaseError) GetBody() []byte {
	return r.Body
}

func (r *BaseError) Error() string {
	if r.ErrorCode != "" {
		s := fmt.Sprintf("oauth2: %q", r.ErrorCode)
		if r.ErrorDescription != "" {
			s += fmt.Sprintf(" %q", r.ErrorDescription)
		}
		if r.ErrorURI != "" {
			s += fmt.Sprintf(" %q", r.ErrorURI)
		}
		return s
	}

	if r.Response == nil {
		return fmt.Sprintf("oauth2: request failed")
	}

	return fmt.Sprintf("oauth2: request failed: %v\nResponse: %s", r.Response.Status, r.Body)
}
