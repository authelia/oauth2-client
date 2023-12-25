# OAuth2 for Go

[![Go Reference](https://pkg.go.dev/badge/authelia.com/client/oauth2.svg)](https://pkg.go.dev/authelia.com/client/oauth2)

oauth2 package contains a client implementation for OAuth 2.0 spec. This is a fork of `golang.org/x/oauth2`. We
graciously acknowledge and appreciate the hard work of the go maintainers for producing this package and hope to do it
justice in the future.

## Differences

Several differences or intended differences exist between this package and the go maintained package.

- Update go version support:
  - [x] Module version go 1.21.
  - [x] Supported version go 1.20 or newer.
- Remove deprecated usage:
  - [x] Usage of `io/ioutil` package.
  - [x] Usage and existence of `oauth2.NoContext`.
  - [x] Existence of `oauth2.RegisterBrokenAuthHeaderProvider`.
  - [x] Support for appengine gen1. 
- Move packages:
  - [x] Move `golang.org/x/oauth2` to `authelia.com/client/oauth2`.
  - [x] Move and no longer export the `golang.org/x/oauth2/jws` package to `authelia.com/client/oauth2/internal/jws`.
  - [x] Move and no longer export the `golang.org/x/oauth2/jwt` package to `authelia.com/client/oauth2/internal/jwt`.
- Remove packages:
  - [x] Endpoint specific packages.
- Add support for:
  - [ ] [JWT Secured Authorization Response Mode for OAuth 2.0](https://openid.net/specs/oauth-v2-jarm.html) (JARM) implementation.
  - [ ] [OpenID Connect 1.0 Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) implementation.
  - [x] [RFC7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662)
  - [x] [RFC7009: OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
  - [ ] [RFC8414: OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) 
  - [x] [RFC9126: OAuth 2.0 Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126) 
  - [ ] [RFC7523: OAuth 2.0 JWT Profile for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7523)
  - [ ] [RFC7521: OAuth 2.0 Assertion Framework for Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521)
  - [ ] [RFC9207: OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
  - [ ] [RFC9101: OAuth 2.0 JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101)
  - [ ] [OAuth 2.0 JWT-Secured Authorization Response Mode](https://openid.net/specs/oauth-v2-jarm.html)
- Leverage well maintained packages:
  - [ ] JWS/JWT package.
- Add tenant/server based providers/endpoints:
  - [x] Authelia
- Miscellaneous:
  - [ ] Create module shared between client and provider.

## Installation

~~~~
go get authelia.com/client/oauth2
~~~~

Or you can manually git clone the repository to
`$(go env GOPATH)/src/authelia.com/client/oauth2`.

See pkg.go.dev for further documentation and examples.

* [pkg.go.dev/authelia.com/client/oauth2](https://pkg.go.dev/authelia.com/client/oauth2)
* [pkg.go.dev/authelia.com/client/oauth2/google](https://pkg.go.dev/authelia.com/client/oauth2/google)

## Policy for new endpoints

We no longer accept new provider-specific packages in this repo if all
they do is add a single endpoint variable. If you just want to add a
single endpoint, add it to the
[pkg.go.dev/authelia.com/client/oauth2/endpoints](https://pkg.go.dev/authelia.com/client/oauth2/endpoints)
package.

_**Addendum:** Authelia has removed these legacy endpoint packages and is not backwards compatible with this element of
the go maintained package._

## Report Issues / Send Patches

The main issue tracker for the oauth2 repository is located at
https://github.com/authelia/client-oauth2/issues.
