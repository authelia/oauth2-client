package oauth2

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPushAuthRequest(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.String() != "/par" {
			t.Errorf("Unexpected par URL %q", r.URL)
		}
		headerAuth := r.Header.Get("Authorization")
		if want := "Basic Q0xJRU5UX0lEOkNMSUVOVF9TRUNSRVQ="; headerAuth != want {
			t.Errorf("Unexpected authorization header %q, want %q", headerAuth, want)
		}
		headerContentType := r.Header.Get("Content-Type")
		if headerContentType != "application/x-www-form-urlencoded" {
			t.Errorf("Unexpected Content-Type header %q", headerContentType)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("Failed reading request body: %s.", err)
		}
		if string(body) != "client_id=CLIENT_ID&redirect_uri=REDIRECT_URL&response_type=code&scope=scope1+scope2&state=state" {
			t.Errorf("Unexpected par payload; got %q", body)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"request_uri": "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c", "expires_in": 60}`))
	}))
	defer ts.Close()
	conf := newConf(ts.URL)
	authURL, _, err := conf.PushedAuth(context.Background(), "state")
	if err != nil {
		t.Fatal(err)
	}
	params := authURL.Query()
	if got := params.Get("client_id"); got != conf.ClientID {
		t.Fatalf("Unexpected client_id; got %s", got)
	}
	if got := params.Get("request_uri"); got != "urn:ietf:params:oauth:request_uri:6esc_11ACC5bwc014ltc14eY22c" {
		t.Errorf("Unexpected request_uri; got %s", got)
	}
}
func TestPushAuthRequestErrorResponse(t *testing.T) {
	type testCase struct {
		name                string
		statusCode          int
		contentType         string
		responseBody        string
		expectRetrieveError bool
	}
	testCases := []testCase{
		{
			name:                "JSON Error Response",
			statusCode:          http.StatusBadRequest,
			contentType:         "application/json",
			responseBody:        `{"error":"invalid_request","error_description":"Invalid request"}`,
			expectRetrieveError: true,
		},
		{
			name:                "x-www-form-urlencoded Error Response",
			statusCode:          http.StatusBadRequest,
			contentType:         "application/x-www-form-urlencoded",
			responseBody:        "error=invalid_request&error_description=Invalid+request",
			expectRetrieveError: true,
		},
		{
			name:                "Unexpected Success Status Code",
			statusCode:          http.StatusAccepted,
			contentType:         "application/json",
			responseBody:        `{"unexpected": "success"}`,
			expectRetrieveError: false,
		},
		{
			name:                "Text Plain Content Type",
			statusCode:          http.StatusBadRequest,
			contentType:         "text/plain",
			responseBody:        "error=invalid_request&error_description=Invalid+request",
			expectRetrieveError: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.String() != "/par" {
					t.Errorf("Unexpected par URL %q", r.URL)
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.statusCode)
				w.Write([]byte(tc.responseBody))
			}))
			defer ts.Close()
			conf := newConf(ts.URL)
			_, _, err := conf.PushedAuth(context.Background(), "state")
			if err == nil {
				t.Errorf("Expected an error, but got none")
			} else {
				fmt.Println("EE")
				re, ok := err.(*RetrieveError)
				if !ok && tc.expectRetrieveError {
					t.Errorf("got %T error, expected *RetrieveError; error was: %v", err, err)
				}
				if tc.expectRetrieveError {
					if expected := "invalid_request"; re.ErrorCode != expected {
						t.Errorf("got %#v, expected %#v", re.ErrorCode, expected)
					}
				}
			}
		})
	}
}
