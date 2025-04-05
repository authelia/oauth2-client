package internal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
)

// PushedAuthResponse describes a successful RFC 8628 Device Authorization Response
// https://datatracker.ietf.org/doc/html/rfc8628#section-3.2
type PushedAuthResponse struct {
	// RequestURI is the request URI corresponding to the authorization request posted. This URI is a single-use
	// reference to the respective request data in the subsequent authorization request. The way the authorization
	// process obtains the authorization request data is at the discretion of the authorization server and is out of
	// scope of this specification. There is no need to make the authorization request data available to other parties
	// via this URI.
	RequestURI string `json:"request_uri"`

	// Interval is a JSON number that represents the lifetime of the request URI in seconds as a positive integer. The
	// request URI lifetime is at the discretion of the authorization server but will typically be relatively short
	// (e.g., between 5 and 600 seconds).
	ExpiresIn int64 `json:"expires_in"`
}

// RetrievePushedAuthResponse performs an OAuth 2.0 Pushed Authorization Request (PAR) by sending
// the authorization request parameters to the PAR endpoint.
//
// the 'request_uri' is a one-time use reference to the authorization request
// and must be used within 'expires_in'
//
// Client authentication is handled similar to the token endpoint. See https://datatracker.ietf.org/doc/html/rfc9126#section-2.
func RetrievePushedAuthResponse(ctx context.Context, clientID, clientSecret, parURL string, v url.Values, authStyle AuthStyle, styleCache *AuthStyleCache) (*PushedAuthResponse, error) {
	// Client authentication for the PAR Endpoint follows the same rules as the token endpoint.
	// A separate key (parURL) is used in the authStyle cache to account for potential variations in authorization server implementations.
	needsAuthStyleProbe := authStyle == 0
	if needsAuthStyleProbe {
		if style, ok := styleCache.lookupAuthStyle(parURL); ok {
			authStyle = style
			needsAuthStyleProbe = false
		} else {
			authStyle = AuthStyleInHeader // the first way we'll try
		}
	}

	// PAR request is identical to token request except for URL.
	req, err := newPOSTRequest(parURL, clientID, clientSecret, v, authStyle)
	if err != nil {
		return nil, err
	}

	parResponse, err := doPARRoundTrip(ctx, req)
	if err != nil && needsAuthStyleProbe {
		authStyle = AuthStyleInParams // the second way we'll try
		req, _ = newPOSTRequest(parURL, clientID, clientSecret, v, authStyle)
		parResponse, err = doPARRoundTrip(ctx, req)
	}

	if needsAuthStyleProbe && err == nil {
		styleCache.setAuthStyle(parURL, authStyle)
	}

	return parResponse, err
}

func doPARRoundTrip(ctx context.Context, req *http.Request) (*PushedAuthResponse, error) {
	r, err := ContextClient(ctx).Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: failed to read PAR response body: %v", err)
	}

	// PAR Successful Response is always returned with 201 HTTP status code
	// and application/json media type. See RFC 9126 section 2.2
	if r.StatusCode == http.StatusCreated {
		var parResponse PushedAuthResponse
		if err = json.Unmarshal(body, &parResponse); err != nil {
			return nil, fmt.Errorf("oauth2: failed to parse PAR response: %v", err)
		}

		if parResponse.RequestURI == "" || parResponse.ExpiresIn <= 0 {
			return nil, fmt.Errorf("oauth2: invalid PAR response")
		}

		return &parResponse, nil
	} else if r.StatusCode >= 200 && r.StatusCode < 300 {
		return nil, fmt.Errorf("oauth2: unexpected PAR response status code %d, expected 201", r.StatusCode)
	}

	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	switch content {
	case "application/json":
		// PAR error response has the same format as token error
		// https://datatracker.ietf.org/doc/html/rfc9126#section-2.3
		var errorResponse struct {
			ErrorCode        string `json:"error"`
			ErrorDescription string `json:"error_description"`
			ErrorURI         string `json:"error_uri"`
		}

		if err = json.Unmarshal(body, &errorResponse); err != nil {
			return nil, fmt.Errorf("oauth2: cannot parse PAR JSON error response: %v", err)
		}

		return nil, &RetrieveError{
			ErrorCode:        errorResponse.ErrorCode,
			ErrorDescription: errorResponse.ErrorDescription,
			ErrorURI:         errorResponse.ErrorURI,
			Response:         r,
			Body:             body,
		}
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, fmt.Errorf("oauth2: cannot parse PAR form-encoded error response: %v", err)
		}

		return nil, &RetrieveError{
			ErrorCode:        vals.Get("error"),
			ErrorDescription: vals.Get("error_description"),
			ErrorURI:         vals.Get("error_uri"),
			Response:         r,
			Body:             body,
		}
	default:
		return nil, fmt.Errorf("oauth2: unrecognized content type %q in PAR error response", content)
	}
}
