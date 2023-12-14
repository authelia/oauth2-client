# OAuth 2.0 Framework for Go (Client Role)

[![Go Reference](https://pkg.go.dev/badge/authelia.com/client/oauth2.svg)](https://pkg.go.dev/authelia.com/client/oauth2)

The `authelia.com/client/oauth2` module contains a client implementation for OAuth 2.0 spec. This is a fork of 
`golang.org/x/oauth2`. We graciously acknowledge and appreciate the hard work of the go maintainers for producing this
package and hope to do it justice in the future. 

Modifications to this package should not reflect anything about the original work and we would graciously welcome any
changes we make being contributed to the `golang.org/x/oauth2` module without credit.

We do not have any goals of backwards compatibility, breaking changes are expected, and this library is at this time not
meant for public consumption. Use at your own risk. Any PR which is aimed at preventing or reverting a breaking change
which does not have adequate testing will be rejected.

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
  - [ ] [JWT Secured Authorization Response Mode for OAuth 2.0 (JARM)](https://openid.net/specs/oauth-v2-jarm.html) implementation.
  - [ ] [OpenID Connect 1.0 Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) implementation.
  - [ ] [RFC7009: OAuth 2.0 Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009) implementation.
  - [ ] [RFC7521: Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants](https://datatracker.ietf.org/doc/html/rfc7521) implementation.
  - [ ] [RFC7592: OAuth 2.0 Dynamic Client Registration Management Protocol](https://datatracker.ietf.org/doc/html/rfc7592) implementation.
  - [ ] [RFC7662: OAuth 2.0 Token Introspection](https://datatracker.ietf.org/doc/html/rfc7662) implementation.
  - [ ] [RFC8414: OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) implementation.
  - [ ] [RFC9101: OAuth 2.0 Authorization Framework: JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101) implementation.
  - [x] [RFC9126: OAuth 2.0 Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126)  implementation.
  - 
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
