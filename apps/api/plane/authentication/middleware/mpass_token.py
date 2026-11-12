# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import jwt

JWKS_LIFESPAN_SECONDS = 3600
JWKS_FETCH_TIMEOUT_SECONDS = 5
CLOCK_SKEW_LEEWAY_SECONDS = 60
REQUIRED_CLAIMS = ["exp", "iat", "iss", "token_use"]


class InvalidMpassToken(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def cognito_issuer(region: str, pool_id: str) -> str:
    if not region or not pool_id:
        return ""
    return f"https://cognito-idp.{region}.amazonaws.com/{pool_id}"


def jwks_url(issuer: str) -> str:
    return issuer.rstrip("/") + "/.well-known/jwks.json"


def default_jwks_client(issuer: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(
        jwks_url(issuer),
        cache_keys=True,
        lifespan=JWKS_LIFESPAN_SECONDS,
        timeout=JWKS_FETCH_TIMEOUT_SECONDS,
    )


def audience_matches(claims: dict, client_id: str) -> bool:
    """Cognito access tokens name the client in ``client_id``; id_tokens in ``aud``."""
    token_use = claims.get("token_use")
    if token_use == "access":
        return claims.get("client_id") == client_id
    if token_use == "id":
        audience = claims.get("aud")
        audiences = audience if isinstance(audience, list) else [audience]
        return client_id in audiences
    return False


def _unverified_issuer(token: str) -> str:
    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as exc:
        raise InvalidMpassToken("malformed") from exc
    return claims.get("iss") or ""


class MpassTokenVerifier:
    """Verifies the mPass token oauth2-proxy forwards in X-Auth-Request-Access-Token.

    A browser session forwards the Cognito access token; a Bearer caller such as
    plane-mcp forwards its id_token, which mpass-auth-proxy re-signs under its
    own issuer when email capture is on. Both issuers are trusted, each against
    its own JWKS, and nothing else is.
    """

    def __init__(self, issuers, client_id: str, jwks_client_factory=default_jwks_client):
        self._issuers = frozenset(issuer for issuer in issuers if issuer)
        self._client_id = client_id
        self._jwks_client_factory = jwks_client_factory
        self._jwks_clients = {}

    @classmethod
    def from_settings(cls, settings):
        issuers = (
            cognito_issuer(
                getattr(settings, "COGNITO_AWS_REGION", ""),
                getattr(settings, "COGNITO_USER_POOL_ID", ""),
            ),
            getattr(settings, "MPASS_TOKEN_ISSUER_URL", ""),
        )
        return cls(issuers, getattr(settings, "MPASS_OIDC_CLIENT_ID", ""))

    def verify(self, token: str) -> dict:
        if not self._issuers or not self._client_id:
            raise InvalidMpassToken("verifier_unconfigured")
        issuer = _unverified_issuer(token)
        if issuer not in self._issuers:
            raise InvalidMpassToken("untrusted_issuer")
        claims = self._decode(token, issuer)
        if not audience_matches(claims, self._client_id):
            raise InvalidMpassToken("wrong_audience")
        return claims

    def _decode(self, token: str, issuer: str) -> dict:
        signing_key = self._signing_key(token, issuer)
        try:
            return jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                issuer=issuer,
                leeway=CLOCK_SKEW_LEEWAY_SECONDS,
                options={"verify_aud": False, "require": REQUIRED_CLAIMS},
            )
        except jwt.ExpiredSignatureError as exc:
            raise InvalidMpassToken("expired") from exc
        except jwt.InvalidIssuerError as exc:
            raise InvalidMpassToken("untrusted_issuer") from exc
        except jwt.InvalidSignatureError as exc:
            raise InvalidMpassToken("bad_signature") from exc
        except jwt.PyJWTError as exc:
            raise InvalidMpassToken("invalid") from exc

    def _signing_key(self, token: str, issuer: str):
        try:
            return self._jwks_client(issuer).get_signing_key_from_jwt(token).key
        except jwt.PyJWKClientConnectionError as exc:
            raise InvalidMpassToken("jwks_unavailable") from exc
        except jwt.PyJWTError as exc:
            raise InvalidMpassToken("unknown_signing_key") from exc

    def _jwks_client(self, issuer: str):
        if issuer not in self._jwks_clients:
            self._jwks_clients[issuer] = self._jwks_client_factory(issuer)
        return self._jwks_clients[issuer]
