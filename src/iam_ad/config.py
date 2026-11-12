"""Configuration de l'application, lue depuis les variables d'environnement `IAM_*`.

Les secrets peuvent aussi être fournis sous forme de fichiers (secrets Docker/Kubernetes) :
un fichier `/run/secrets/iam_ad_bind_password` alimente `IAM_AD_BIND_PASSWORD`.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SECRETS_DIR = Path("/run/secrets")

CsvList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="IAM_",
        env_file=".env",
        env_file_encoding="utf-8",
        secrets_dir=_SECRETS_DIR if _SECRETS_DIR.is_dir() else None,
        extra="ignore",
    )

    # --- Authentification de l'API -------------------------------------------------
    auth_mode: Literal["oidc", "api_key"] = "oidc"
    # Mode api_key : {"nom-du-client": "<sha256 hexadécimal de la clé>"}. Jamais la clé en clair.
    api_keys: dict[str, str] = Field(default_factory=dict)
    # Mode oidc : validation des jetons d'accès JWT émis par le fournisseur d'identité.
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    oidc_required_role: str = "iam.users.create"
    oidc_algorithms: CsvList = ["RS256", "ES256", "PS256"]

    # --- Annuaire -----------------------------------------------------------------
    directory_backend: Literal["ldap", "memory"] = "ldap"
    ad_servers: CsvList = []
    ad_port: int = 636
    ad_base_dn: str | None = None
    ad_users_ou: str | None = None
    ad_upn_suffix: str | None = None
    ad_bind_user: str | None = None
    ad_bind_password: SecretStr | None = None
    ad_ca_cert_file: Path | None = None
    ad_timeout_seconds: int = Field(default=10, ge=1, le=120)

    # --- Règles de nommage et de mot de passe -------------------------------------
    login_first_name_letters: int = Field(default=3, ge=1, le=10)
    login_last_name_letters: int = Field(default=3, ge=1, le=10)
    password_length: int = Field(default=10, ge=10, le=127)
    matricule_pattern: str = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,15}$"
    mail_allowed_domains: CsvList = []

    # --- Divers -------------------------------------------------------------------
    # Page interactive /docs (Swagger UI) : elle charge ses scripts depuis un CDN public,
    # d'où sa désactivation par défaut. Le contrat /openapi.json reste toujours disponible.
    enable_docs: bool = False

    @field_validator("ad_servers", "mail_allowed_domains", "oidc_algorithms", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("mail_allowed_domains")
    @classmethod
    def _lowercase_domains(cls, value: list[str]) -> list[str]:
        return [domain.lower().lstrip("@") for domain in value]

    @field_validator("matricule_pattern")
    @classmethod
    def _valid_regex(cls, value: str) -> str:
        re.compile(value)
        return value

    @field_validator("oidc_algorithms")
    @classmethod
    def _asymmetric_only(cls, value: list[str]) -> list[str]:
        # Les algorithmes symétriques (HS*) et "none" permettraient de forger des jetons.
        allowed = {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"}
        rejected = [alg for alg in value if alg not in allowed]
        if rejected or not value:
            raise ValueError(f"algorithmes JWT non autorisés : {rejected or 'liste vide'}")
        return value

    @model_validator(mode="after")
    def _check_consistency(self) -> Self:
        if self.auth_mode == "api_key":
            if not self.api_keys:
                raise ValueError("IAM_API_KEYS est requis quand IAM_AUTH_MODE=api_key")
            for name, digest in self.api_keys.items():
                if not _SHA256_HEX.match(digest):
                    raise ValueError(
                        f"IAM_API_KEYS[{name!r}] doit être l'empreinte SHA-256 (64 caractères "
                        "hexadécimaux minuscules) de la clé, pas la clé elle-même"
                    )
        else:
            missing = [
                name
                for name in ("oidc_issuer", "oidc_audience", "oidc_jwks_url")
                if not getattr(self, name)
            ]
            if missing:
                raise ValueError(
                    "variables requises quand IAM_AUTH_MODE=oidc : "
                    + ", ".join(f"IAM_{name.upper()}" for name in missing)
                )
            if not self.oidc_jwks_url.lower().startswith("https://"):
                raise ValueError("IAM_OIDC_JWKS_URL doit être une URL https://")

        if self.directory_backend == "ldap":
            missing = [
                name
                for name in (
                    "ad_servers",
                    "ad_base_dn",
                    "ad_users_ou",
                    "ad_upn_suffix",
                    "ad_bind_user",
                    "ad_bind_password",
                )
                if not getattr(self, name)
            ]
            if missing:
                raise ValueError(
                    "variables requises quand IAM_DIRECTORY_BACKEND=ldap : "
                    + ", ".join(f"IAM_{name.upper()}" for name in missing)
                )
        elif not self.ad_upn_suffix:
            self.ad_upn_suffix = "demo.local"
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
