// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package hipchat provides constants for using OAuth2 to access HipChat.
package hipchat // import "authelia.com/client/oauth2/hipchat"

import (
	"encoding/json"
	"errors"

	"authelia.com/client/oauth2/clientcredentials"
)

// ClientCredentialsConfigFromCaps generates a Config from a HipChat API
// capabilities descriptor. It does not verify the scopes against the
// capabilities document at this time.
//
// For more information see: https://www.hipchat.com/docs/apiv2/method/get_capabilities
func ClientCredentialsConfigFromCaps(capsJSON []byte, clientID, clientSecret string, scopes ...string) (*clientcredentials.Config, error) {
	var caps struct {
		Caps struct {
			Endpoint struct {
				TokenURL string `json:"tokenUrl"`
			} `json:"oauth2Provider"`
		} `json:"capabilities"`
	}

	if err := json.Unmarshal(capsJSON, &caps); err != nil {
		return nil, err
	}

	// Verify required fields.
	if caps.Caps.Endpoint.TokenURL == "" {
		return nil, errors.New("oauth2/hipchat: missing OAuth2 token URL in the capabilities descriptor JSON")
	}

	return &clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Scopes:       scopes,
		TokenURL:     caps.Caps.Endpoint.TokenURL,
	}, nil
}
