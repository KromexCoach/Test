import json

import pytest
from pydantic import ValidationError

from iam_ad.auth import hash_api_key
from iam_ad.config import Settings
from tests.conftest import make_settings

LDAP = {
    "directory_backend": "ldap",
    "ad_servers": "dc1.corp.exemple.be, dc2.corp.exemple.be",
    "ad_base_dn": "DC=corp,DC=exemple,DC=be",
    "ad_users_ou": "OU=Utilisateurs,DC=corp,DC=exemple,DC=be",
    "ad_upn_suffix": "exemple.be",
    "ad_bind_user": "svc-iam@corp.exemple.be",
    "ad_bind_password": "secret",
}


def test_ldap_backend_parses_server_list_and_hides_the_bind_password():
    settings = make_settings(**LDAP)
    assert settings.ad_servers == ["dc1.corp.exemple.be", "dc2.corp.exemple.be"]
    assert settings.ad_port == 636
    assert "secret" not in repr(settings)


def test_ldap_backend_requires_its_settings():
    with pytest.raises(ValidationError, match="IAM_AD_BIND_PASSWORD"):
        make_settings(**{**LDAP, "ad_bind_password": None})


def test_api_keys_must_be_hashes_not_plaintext():
    with pytest.raises(ValidationError, match="empreinte SHA-256"):
        make_settings(api_keys={"logiciel-rh": "ma-cle-en-clair"})
    with pytest.raises(ValidationError, match="IAM_API_KEYS"):
        make_settings(api_keys={})


def test_oidc_mode_requires_issuer_audience_and_https_jwks():
    with pytest.raises(ValidationError, match="IAM_OIDC_ISSUER"):
        Settings(_env_file=None, directory_backend="memory")
    with pytest.raises(ValidationError, match="https"):
        Settings(
            _env_file=None,
            directory_backend="memory",
            oidc_issuer="https://idp.exemple.be",
            oidc_audience="iam-ad",
            oidc_jwks_url="http://idp.exemple.be/jwks",
        )


@pytest.mark.parametrize("algorithms", ["HS256", "none", "RS256,HS512", ""])
def test_only_asymmetric_jwt_algorithms_are_accepted(algorithms):
    with pytest.raises(ValidationError, match="algorithmes"):
        make_settings(oidc_algorithms=algorithms)


def test_password_length_cannot_go_below_ten():
    with pytest.raises(ValidationError):
        make_settings(password_length=9)


def test_settings_are_read_from_environment(monkeypatch):
    monkeypatch.setenv("IAM_AUTH_MODE", "api_key")
    monkeypatch.setenv("IAM_API_KEYS", json.dumps({"logiciel-rh": hash_api_key("k")}))
    monkeypatch.setenv("IAM_DIRECTORY_BACKEND", "memory")
    monkeypatch.setenv("IAM_MAIL_ALLOWED_DOMAINS", "Exemple.be, @exemple.com")
    settings = Settings(_env_file=None)
    assert settings.mail_allowed_domains == ["exemple.be", "exemple.com"]
    assert settings.ad_upn_suffix == "demo.local"


def test_bind_password_can_come_from_a_secret_file(tmp_path):
    (tmp_path / "iam_ad_bind_password").write_text("secret-du-fichier\n")
    settings = Settings(
        _env_file=None,
        _secrets_dir=tmp_path,
        auth_mode="api_key",
        api_keys={"logiciel-rh": hash_api_key("k")},
        **{name: value for name, value in LDAP.items() if name != "ad_bind_password"},
    )
    assert settings.ad_bind_password.get_secret_value() == "secret-du-fichier"
