// Copyright 2019 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package endpoints

import (
	"github.com/stretchr/testify/assert"
	"net/url"
	"testing"

	"authelia.com/client/oauth2"
)

func TestAWSCognitoEndpoint(t *testing.T) {
	var endpointTests = []struct {
		in  string
		out oauth2.Endpoint
	}{
		{
			in: "https://testing.auth.us-east-1.amazoncognito.com",
			out: oauth2.Endpoint{
				AuthURL:  "https://testing.auth.us-east-1.amazoncognito.com/oauth2/authorize",
				TokenURL: "https://testing.auth.us-east-1.amazoncognito.com/oauth2/token",
			},
		},
		{
			in: "https://testing.auth.us-east-1.amazoncognito.com/",
			out: oauth2.Endpoint{
				AuthURL:  "https://testing.auth.us-east-1.amazoncognito.com/oauth2/authorize",
				TokenURL: "https://testing.auth.us-east-1.amazoncognito.com/oauth2/token",
			},
		},
	}

	for _, tt := range endpointTests {
		t.Run(tt.in, func(t *testing.T) {
			endpoint := AWSCognito(tt.in)
			if endpoint != tt.out {
				t.Errorf("got %q, want %q", endpoint, tt.out)
			}
		})
	}
}

func TestAuthelia(t *testing.T) {
	testCases := []struct {
		name     string
		have     *url.URL
		expected oauth2.Endpoint
	}{
		{
			"ShouldHandleNil",
			nil,
			oauth2.Endpoint{},
		},
		{
			"ShouldHandleExample",
			&url.URL{Scheme: "https", Host: "auth.example.com"},
			oauth2.Endpoint{
				AuthURL:          "https://auth.example.com/api/oidc/authorization",
				DeviceAuthURL:    "https://auth.example.com/api/oidc/device-authorization",
				PushedAuthURL:    "https://auth.example.com/api/oidc/pushed-authorization-request",
				TokenURL:         "https://auth.example.com/api/oidc/token",
				IntrospectionURL: "https://auth.example.com/api/oidc/introspection",
				RevocationURL:    "https://auth.example.com/api/oidc/revocation",
				UserinfoURL:      "https://auth.example.com/api/oidc/userinfo",
				JWKSURL:          "https://auth.example.com/jwks.json",
				AuthStyle:        oauth2.AuthStyleInParams,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := Authelia(tc.have)

			assert.Equal(t, tc.expected, actual)
		})
	}
}
