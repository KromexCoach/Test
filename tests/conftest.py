from __future__ import annotations

import pytest

from iam_ad.auth import hash_api_key
from iam_ad.config import Settings

API_KEY = "cle-de-test-uniquement"


def make_settings(**overrides) -> Settings:
    values = {
        "auth_mode": "api_key",
        "api_keys": {"logiciel-rh": hash_api_key(API_KEY)},
        "directory_backend": "memory",
        "ad_upn_suffix": "exemple.be",
    }
    values.update(overrides)
    return Settings(_env_file=None, **values)


@pytest.fixture
def settings() -> Settings:
    return make_settings()


@pytest.fixture(autouse=True)
def _isolated_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Aucune variable IAM_* de la machine ne doit influencer les tests."""
    import os

    for name in list(os.environ):
        if name.startswith("IAM_"):
            monkeypatch.delenv(name)
