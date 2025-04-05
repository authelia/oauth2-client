// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
package oauth2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
)

const (
	codeChallengeKey       = "code_challenge"
	codeChallengeMethodKey = "code_challenge_method"
	codeVerifierKey        = "code_verifier"
)

func NewPKCE() (pkce *PKCE, err error) {
	var verifier []byte

	if verifier, err = getRandomBytes(128, charsetRFC3986Unreserved); err != nil {
		return nil, fmt.Errorf("error occurred generating random verifier for PKCE: %w", err)
	}

	pkce = &PKCE{
		verifier: verifier,
	}

	return pkce, nil
}

func NewPKCEWithValues(verifier []byte, plain bool) (pkce *PKCE) {
	return &PKCE{
		verifier: verifier,
		plain:    plain,
	}
}

type PKCE struct {
	verifier []byte
	plain    bool
}

// ChallengeMethod returns a string representation of the current challenge method.
func (pkce *PKCE) ChallengeMethod() string {
	if pkce.plain {
		return "plain"
	}

	return "S256"
}

// Verifier returns a copy of the current verifier value.
func (pkce *PKCE) Verifier() []byte {
	verifier := make([]byte, len(pkce.verifier))

	copy(verifier, pkce.verifier)

	return verifier
}

// UsePlain disables the requirement for S256 and uses the code challenge method plain instead.
func (pkce *PKCE) UsePlain() {
	pkce.plain = true
}

// AuthCodeOptionChallenge returns the option used for the challenge phase of PKCE i.e. the Config.PushedAuth or
// Config.AuthCodeURL functions.
func (pkce *PKCE) AuthCodeOptionChallenge() AuthCodeOption {
	if pkce.plain {
		return challengeOption{"plain", string(pkce.verifier)}
	}

	verifier := sha256.Sum256(pkce.verifier)

	return challengeOption{"S256", base64.RawURLEncoding.EncodeToString(verifier[:])}
}

// AuthCodeOptionVerifier returns the option used for the verifier phase of PKCE i.e. the Config.Exchange function.
func (pkce *PKCE) AuthCodeOptionVerifier() AuthCodeOption {
	return setParam{k: codeVerifierKey, v: string(pkce.verifier)}
}

// GenerateVerifier generates a PKCE code verifier with 32 octets of randomness.
// This follows recommendations in RFC 7636.
//
// A fresh verifier should be generated for each authorization.
// S256ChallengeOption(verifier) should then be passed to Config.AuthCodeURL
// (or Config.DeviceAuth) and VerifierOption(verifier) to Config.Exchange
// (or Config.DeviceAccessToken).
func GenerateVerifier() string {
	// "RECOMMENDED that the output of a suitable random number generator be
	// used to create a 32-octet sequence.  The octet sequence is then
	// base64url-encoded to produce a 43-octet URL-safe string to use as the
	// code verifier."
	// https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}

// VerifierOption returns a PKCE code verifier AuthCodeOption. It should be
// passed to Config.Exchange or Config.DeviceAccessToken only.
func VerifierOption(verifier string) AuthCodeOption {
	return setParam{k: codeVerifierKey, v: verifier}
}

// S256ChallengeFromVerifier returns a PKCE code challenge derived from verifier with method S256.
//
// Prefer to use S256ChallengeOption where possible.
func S256ChallengeFromVerifier(verifier string) string {
	sha := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sha[:])
}

// S256ChallengeOption derives a PKCE code challenge derived from verifier with
// method S256. It should be passed to Config.AuthCodeURL or Config.DeviceAuth
// only.
func S256ChallengeOption(verifier string) AuthCodeOption {
	return challengeOption{
		challenge_method: "S256",
		challenge:        S256ChallengeFromVerifier(verifier),
	}
}

type challengeOption struct{ challenge_method, challenge string }

func (p challengeOption) setValue(m url.Values) {
	m.Set(codeChallengeMethodKey, p.challenge_method)
	m.Set(codeChallengeKey, p.challenge)
}
