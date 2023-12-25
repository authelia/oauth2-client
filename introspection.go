package oauth2

import (
	"context"
	"fmt"
	"net/url"

	"authelia.com/client/oauth2/internal"
)

type IntrospectionResult struct {
	Introspection *internal.Introspection
	Error         error
}

// IntrospectToken allows for simple token introspection.
func (c *Config) IntrospectToken(ctx context.Context, token *Token, opts ...IntrospectionRevocationOption) (results []IntrospectionResult, err error) {
	if token == nil {
		return nil, fmt.Errorf("error introspecting token: no token was provided")
	}

	if c.Endpoint.IntrospectionURL == "" {
		return nil, fmt.Errorf("error introspecting token: no introspection endpoint URL was provided")
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
				return nil, fmt.Errorf("error introspecting token: token type hint '%s' can only be introspected for a token that has an access token", tth)
			}

			xvals.Set("token", token.AccessToken)
		case "refresh_token":
			if len(token.AccessToken) == 0 {
				return nil, fmt.Errorf("error introspecting token: token type hint '%s' can only be introspected for a token that has a refresh token", tth)
			}

			xvals.Set("token", token.RefreshToken)
		default:
			return nil, fmt.Errorf("error introspecting token: token type hint '%s' isn't known", tth)
		}

		for _, opt := range opts {
			opt.setValue(xvals)
		}

		vals[i] = xvals
	}

	var (
		introspection *internal.Introspection
		errored       bool
	)

	for _, v := range vals {
		if introspection, err = internal.IntrospectToken(ctx, c.ClientID, c.ClientSecret, c.Endpoint.IntrospectionURL, v, internal.AuthStyle(c.Endpoint.AuthStyle), c.authStyleCache.Get()); err != nil {
			errored = true

			if rErr, ok := err.(*internal.BaseError); ok {
				results = append(results, IntrospectionResult{Introspection: introspection, Error: (*BaseError)(rErr)})

				continue
			}

			results = append(results, IntrospectionResult{Introspection: introspection, Error: err})
		}

		results = append(results, IntrospectionResult{Introspection: introspection})
	}

	if errored {
		return results, fmt.Errorf("error introspecting token: one or more errors occurred check the results for details")
	}

	return results, nil
}
