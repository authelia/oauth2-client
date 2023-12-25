package oauth2

import (
	"context"
	"fmt"
	"net/url"

	"authelia.com/client/oauth2/internal"
)

// RevokeToken allows for simple token revocation.
func (c *Config) RevokeToken(ctx context.Context, token *Token, opts ...RevocationOption) (err error) {
	if token == nil {
		return fmt.Errorf("error revoking token: no token was provided")
	}

	if c.Endpoint.RevocationURL == "" {
		return fmt.Errorf("error revoking token: no revocation endpoint URL was provided")
	}

	tths := []string{}

	for _, opt := range opts {
		tths = opt.appendTokenTypeHints(tths)
	}

	if len(tths) == 0 {
		tths = []string{"access_token"}
	}

	vals := make([]url.Values, len(tths))

	for i, tth := range tths {
		xvals := url.Values{
			"token_type_hint": []string{tth},
		}

		switch tth {
		case "access_token":
			if len(token.AccessToken) == 0 {
				return fmt.Errorf("error revoking token: token type hint '%s' can only be revoked for a token that has an access token", tth)
			}

			xvals.Set("token", token.AccessToken)
		case "refresh_token":
			if len(token.AccessToken) == 0 {
				return fmt.Errorf("error revoking token: token type hint '%s' can only be revoked for a token that has a refresh token", tth)
			}

			xvals.Set("token", token.RefreshToken)
		default:
			return fmt.Errorf("error revoking token: token type hint '%s' isn't known", tth)
		}

		for _, opt := range opts {
			opt.setValue(xvals)
		}

		vals[i] = xvals
	}

	for _, v := range vals {
		if err = internal.RevokeToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.RevocationURL, v, internal.AuthStyle(c.Endpoint.AuthStyle), c.authStyleCache.Get()); err != nil {
			if rErr, ok := err.(*internal.RevokeError); ok {
				xErr := (*BaseError)(rErr)

				return &RevokeError{xErr}
			}
			return err
		}
	}

	return nil
}

type RevokeError struct {
	*BaseError
}

type RevocationOption interface {
	setValue(vals url.Values)
	appendTokenTypeHints(tths []string) []string
}

// SetRevocationURLParam builds a RevocationOption which passes key/value parameters
// to a provider's revocation endpoint.
func SetRevocationURLParam(key, value string) RevocationOption {
	return setRevocationValue{key, value}
}

// AddRevocationTokenTypes builds a RevocationOption which explicitly adds a token
// type hint to the revocation process. By default the oauth2.RevokeToken method
// will perform the access token revocation. If the authorization server requires
// the refresh token is revoked manually then use this option like
// oauth.AddRevocationTokenTypes("access_token", "refresh_token").
func AddRevocationTokenTypes(values ...string) RevocationOption {
	return addRevocationTokenTypeHints{values: values}
}

type setRevocationValue struct{ key, value string }

func (m setRevocationValue) setValue(vals url.Values) { vals.Set(m.key, m.value) }

func (m setRevocationValue) appendTokenTypeHints(tths []string) []string { return tths }

type addRevocationTokenTypeHints struct{ values []string }

func (m addRevocationTokenTypeHints) setValue(vals url.Values) {}

func (m addRevocationTokenTypeHints) appendTokenTypeHints(tths []string) []string {
outer:
	for _, value := range m.values {
		for _, tth := range tths {
			if tth == value {
				continue outer
			}
		}

		tths = append(tths, value)
	}

	return tths
}
