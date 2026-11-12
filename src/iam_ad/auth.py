"""Authentification des appelants de l'API.

Deux modes, tous deux présentés dans l'en-tête `Authorization: Bearer <jeton>` :

- `oidc` (recommandé) : jeton d'accès JWT émis par le fournisseur d'identité (Entra ID,
  AD FS, Keycloak…), signature vérifiée avec ses clés publiques, rôle exigé ;
- `api_key` : clé aléatoire par application cliente ; seule son empreinte SHA-256 est configurée.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import jwt
from jwt import PyJWKClient
from jwt.exceptions import PyJWKClientConnectionError

from iam_ad.config import Settings

_CLOCK_SKEW_SECONDS = 30
_API_KEY_BYTES = 32


@dataclass(frozen=True, slots=True)
class Principal:
    subject: str
    method: str


class AuthError(Exception):
    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.message = message


class Authenticator(Protocol):
    def authenticate(self, token: str) -> Principal: ...


def hash_api_key(key: str) -> str:
    # Les clés font 256 bits d'aléa : une empreinte rapide suffit, il n'y a rien à « casser ».
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def new_api_key() -> tuple[str, str]:
    """Retourne (clé à remettre au client, empreinte à placer dans IAM_API_KEYS)."""
    key = secrets.token_urlsafe(_API_KEY_BYTES)
    return key, hash_api_key(key)


class ApiKeyAuthenticator:
    def __init__(self, keys: dict[str, str]) -> None:
        self._keys = dict(keys)

    def authenticate(self, token: str) -> Principal:
        digest = hash_api_key(token)
        matched: str | None = None
        # Parcours complet et comparaison à temps constant : pas de fuite par le temps de réponse.
        for name, expected in self._keys.items():
            if hmac.compare_digest(digest, expected):
                matched = name
        if matched is None:
            raise AuthError(401, "Clé d'API invalide.")
        return Principal(subject=matched, method="api_key")


class OidcAuthenticator:
    def __init__(
        self,
        issuer: str,
        audience: str,
        required_role: str,
        algorithms: list[str],
        signing_key_resolver: Callable[[str], Any],
    ) -> None:
        self._issuer = issuer
        self._audience = audience
        self._required_role = required_role
        self._algorithms = algorithms
        self._resolve_signing_key = signing_key_resolver

    def authenticate(self, token: str) -> Principal:
        try:
            signing_key = self._resolve_signing_key(token)
            claims = jwt.decode(
                token,
                signing_key,
                algorithms=self._algorithms,
                audience=self._audience,
                issuer=self._issuer,
                leeway=_CLOCK_SKEW_SECONDS,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except PyJWKClientConnectionError as error:
            raise AuthError(503, "Fournisseur d'identité injoignable.") from error
        except jwt.PyJWTError as error:
            raise AuthError(401, "Jeton d'accès invalide ou expiré.") from error

        if self._required_role not in _granted_roles(claims):
            raise AuthError(403, f"Le rôle « {self._required_role} » est requis.")
        subject = claims.get("preferred_username") or claims.get("azp") or claims["sub"]
        return Principal(subject=str(subject), method="oidc")


def _granted_roles(claims: dict[str, Any]) -> set[str]:
    """Rôles et périmètres du jeton, selon les conventions Entra ID, OAuth 2.0 et Keycloak."""
    granted: set[str] = set()
    for claim in ("roles", "scp", "scope"):
        value = claims.get(claim)
        if isinstance(value, str):
            granted.update(value.split())
        elif isinstance(value, list):
            granted.update(str(item) for item in value)
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict) and isinstance(realm_access.get("roles"), list):
        granted.update(str(item) for item in realm_access["roles"])
    return granted


def build_authenticator(settings: Settings) -> Authenticator:
    if settings.auth_mode == "api_key":
        return ApiKeyAuthenticator(settings.api_keys)
    jwks_client = PyJWKClient(settings.oidc_jwks_url, cache_keys=True, timeout=5)
    return OidcAuthenticator(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        required_role=settings.oidc_required_role,
        algorithms=settings.oidc_algorithms,
        signing_key_resolver=lambda token: jwks_client.get_signing_key_from_jwt(token).key,
    )
