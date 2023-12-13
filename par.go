package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"authelia.com/client/oauth2/internal"
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

// PushedAuth returns a pushed auth struct which contains a request uri and expires in information after making a HTTP
// POST request to the configured Pushed Auth URL. In addition, it returns the *url.URL of the properly formatted AuthURL
// for the PAR session provided the AuthURL Endpoint is configured.
func (c *Config) PushedAuth(ctx context.Context, state string, opts ...AuthCodeOption) (authURL *url.URL, par *PushedAuthResponse, err error) {
	if c.Endpoint.PushedAuthURL == "" {
		return nil, nil, errors.New("endpoint missing PushedAuthURL")
	}

	var v url.Values

	if authURL, v, err = c.getPushedAuthCodeValues(state, opts...); err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequest("POST", c.Endpoint.PushedAuthURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	r, err := internal.ContextClient(ctx).Do(req)
	if err != nil {
		return nil, nil, err
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return nil, nil, fmt.Errorf("oauth2: cannot push auth: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, nil, &RetrieveError{
			Response: r,
			Body:     body,
		}
	}

	par = &PushedAuthResponse{}
	err = json.Unmarshal(body, &par)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal %s", err)
	}

	fv := url.Values{
		"client_id":   {c.ClientID},
		"request_uri": {par.RequestURI},
	}

	authURL.RawQuery = fv.Encode()

	return authURL, par, nil
}

func (c *Config) getPushedAuthCodeValues(state string, opts ...AuthCodeOption) (authURL *url.URL, v url.Values, err error) {
	if c.Endpoint.AuthURL != "" {
		if authURL, err = url.ParseRequestURI(c.Endpoint.AuthURL); err != nil {
			return nil, url.Values{}, fmt.Errorf("failed to parse AuthURL: %w", err)
		}

		v = authURL.Query()

		authURL.RawQuery = ""
		authURL.RawFragment = ""
	} else {
		v = url.Values{}
	}

	if c.ClientSecret != "" {
		v.Set("client_secret", c.ClientSecret)
	}

	xv := c.getAuthCodeValues(state, opts...)

	for key, value := range xv {
		v[key] = value
	}

	return authURL, v, nil
}
