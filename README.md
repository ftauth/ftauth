# FTOAuth
Secure, lightweight OAuth 2.1 server, written in Go.

## Features
FTOAuth supports the OAuth 2.1 protocol, currently in [draft](https://tools.ietf.org/html/draft-ietf-oauth-v2-1-00), which slims the original OAuth 2.0 spec to incorporate best practices for security.

Features include:
- JSON Web Tokens (JWT) & JSON Web Keys (JWK)

JWTs improve performance by allowing clients to introspect the token without querying the authorization server. JWKs allow clients to validate the claims embedded within the JWT by verifying the signature of the JWT.

- Demonstrated Proof-of-Possession ([DPoP](https://tools.ietf.org/html/draft-ietf-oauth-dpop-01))

While OAuth best practices require that clients mutually authenticate (e.g. via mutual TLS ([mTLS](https://tools.ietf.org/html/rfc8705))), this is not possible for public clients (i.e. Web apps, native apps) which encompass the majority of common use cases.

As an alternative, DPoP or Demonstrated Proof-of-Possession is implemented for all clients (public and confidential) which protects against some common attacks [^1].

[^1]: https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16