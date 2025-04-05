package oauth2

import (
	"authelia.com/client/oauth2/internal"
	"context"
	"errors"
	"fmt"
	"net/url"
)

// PushedAuth returns a pushed auth struct which contains a request uri and expires in information after making a HTTP
// POST request to the configured Pushed Auth URL. In addition, it returns the *url.URL of the properly formatted AuthURL
// for the PAR session provided the AuthURL Endpoint is configured.
func (c *Config) PushedAuth(ctx context.Context, state string, opts ...AuthCodeOption) (authURL *url.URL, par *internal.PushedAuthResponse, err error) {
	if c.Endpoint.PushedAuthURL == "" {
		return nil, nil, errors.New("endpoint missing PushedAuthURL")
	}

	var v url.Values

	if authURL, v, err = c.getPushedAuthCodeValues(state, opts...); err != nil {
		return nil, nil, err
	}

	if par, err = internal.RetrievePushedAuthResponse(ctx, c.ClientID, c.ClientSecret, c.Endpoint.PushedAuthURL, v, internal.AuthStyle(c.Endpoint.AuthStyle), c.authStyleCache.Get()); err != nil {
		var rErr *internal.RetrieveError

		if errors.As(err, &rErr) {
			return nil, nil, &RetrieveError{BaseError: (*BaseError)(rErr)}
		}

		return nil, nil, err
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

	xv := c.getAuthCodeValues(state, opts...)

	for key, value := range xv {
		v[key] = value
	}

	return authURL, v, nil
}
