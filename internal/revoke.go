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

func RevokeToken(ctx context.Context, clientID, clientSecret, revocationURL string, v url.Values, authStyle AuthStyle, styleCache *AuthStyleCache) error {
	needsAuthStyleProbe := authStyle == 0
	if needsAuthStyleProbe {
		if style, ok := styleCache.lookupAuthStyle(revocationURL); ok {
			authStyle = style
			needsAuthStyleProbe = false
		} else {
			authStyle = AuthStyleInHeader // the first way we'll try
		}
	}
	req, err := newPOSTRequest(revocationURL, clientID, clientSecret, v, authStyle)
	if err != nil {
		return err
	}

	if err = doRevokeRoundTrip(ctx, req); err != nil && needsAuthStyleProbe {
		authStyle = AuthStyleInParams // the second way we'll try
		req, _ = newPOSTRequest(revocationURL, clientID, clientSecret, v, authStyle)
		err = doRevokeRoundTrip(ctx, req)
	}
	if needsAuthStyleProbe && err == nil {
		styleCache.setAuthStyle(revocationURL, authStyle)
	}

	return err
}

func doRevokeRoundTrip(ctx context.Context, req *http.Request) error {
	r, err := ContextClient(ctx).Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return fmt.Errorf("oauth2: cannot revoke token: %v", err)
	}

	failureStatus := r.StatusCode < 200 || r.StatusCode > 299

	if !failureStatus {
		return nil
	}

	revokeError := &RevokeError{
		Response: r,
		Body:     body,
		// attempt to populate error detail below
	}

	content, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))

	switch content {
	case "application/x-www-form-urlencoded", "text/plain":
		vals, err := url.ParseQuery(string(body))
		if err != nil {
			return revokeError
		}

		revokeError.ErrorCode = vals.Get("error")
		revokeError.ErrorDescription = vals.Get("error_description")
		revokeError.ErrorURI = vals.Get("error_uri")
	default:
		var rj errorJSON
		if err = json.Unmarshal(body, &rj); err != nil {
			return revokeError
		}

		revokeError.ErrorCode = rj.ErrorCode
		revokeError.ErrorDescription = rj.ErrorDescription
		revokeError.ErrorURI = rj.ErrorURI
	}

	return revokeError
}
