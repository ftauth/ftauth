# FTAuth [![codecov](https://codecov.io/gh/ftauth/ftauth/branch/main/graph/badge.svg?token=G9KXI1UAGB)](https://codecov.io/gh/ftauth/ftauth)
FTAuth (Fault-Tolerant Auth) is a secure, lightweight OAuth 2.1 server, written in Go.

## Quick Start
Run the following command to create a local instance of FTAuth:

```sh
docker run --rm -it \
    -e FTAUTH_OAUTH_ADMIN_USERNAME=admin \
    -e FTAUTH_OAUTH_ADMIN_PASSWORD=password \
    -p 8000:8000 ftauth/ftauth:latest
```

The process will print client info in JSON to the terminal which can be used with a client SDK to connect to the running server.

```sh
Admin client: {"uid":"5b8b954c-7a43-42f8-bc76-a5df26abd2f6","client_name":"Admin","client_type":"public","client_secret_expires_at":"0001-01-01T00:00:00Z","redirect_uris":["localhost","myapp://auth"],"scopes":[{"name":"default"},{"name":"admin"}],"grant_types":["authorization_code","client_credentials","refresh_token"],"access_token_life":3600,"refresh_token_life":86400}
```

## Client SDKs

- Dart/Flutter: https://github.com/ftauth/sdk-dart

## Features
FTAuth supports the OAuth 2.1 protocol, currently in [draft](https://tools.ietf.org/html/draft-ietf-oauth-v2-1-00), which slims the original OAuth 2.0 spec to incorporate best practices for security.

Features include:
- JSON Web Tokens (JWT) & JSON Web Keys (JWK)

JWTs improve performance by allowing clients to introspect the token without querying the authorization server. JWKs allow clients to validate the claims embedded within the JWT by verifying the signature against a public key set.

- Demonstrated Proof-of-Possession (DPoP) - [RFC](https://tools.ietf.org/html/draft-ietf-oauth-dpop-02)

While OAuth best practices mandate that clients mutually authenticate (e.g. via mutual TLS ([mTLS](https://tools.ietf.org/html/rfc8705))), this is not possible for public clients (i.e. Web apps, native apps) which encompass the majority of common use cases.

As an alternative, DPoP or Demonstrated Proof-of-Possession is implemented for all clients (public and confidential) which protects against [many of the same attacks](https://tools.ietf.org/html/draft-ietf-oauth-security-topics-16). The disadvantage of DPoP is that the public client cannot be initially authenticated, i.e. anyone can impersonate a trusted client.

It is recommended that mTLS is implemented when possible, e.g. in the service mesh.

- Proof Key for Code Exchange (PKCE) - [RFC](https://tools.ietf.org/html/rfc7636)

An added layer of protection for public clients, this standard protects against authorization code intercepts by establishing a secret on the client which is used later when exchanging the authorization code. In the same way DPoP protects access tokens, PKCE protects authorization codes from interception and replay attacks.

