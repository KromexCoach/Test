import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from iam_ad.auth import ApiKeyAuthenticator, AuthError, OidcAuthenticator, hash_api_key, new_api_key

ISSUER = "https://idp.exemple.be/realms/corp"
AUDIENCE = "iam-ad"
ROLE = "iam.users.create"


@pytest.fixture(scope="module")
def signing_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def authenticator(signing_key) -> OidcAuthenticator:
    return OidcAuthenticator(
        issuer=ISSUER,
        audience=AUDIENCE,
        required_role=ROLE,
        algorithms=["RS256"],
        signing_key_resolver=lambda token: signing_key.public_key(),
    )


def make_token(key, algorithm="RS256", **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "client-rh",
        "iat": now,
        "exp": now + 300,
        "roles": [ROLE],
    }
    claims.update(overrides)
    claims = {name: value for name, value in claims.items() if value is not None}
    return jwt.encode(claims, key, algorithm=algorithm)


def test_api_key_is_accepted_and_names_the_client():
    key, digest = new_api_key()
    principal = ApiKeyAuthenticator(
        {"autre": hash_api_key("x"), "logiciel-rh": digest}
    ).authenticate(key)
    assert (principal.subject, principal.method) == ("logiciel-rh", "api_key")
    assert len(key) >= 43  # 32 octets d'aléa


@pytest.mark.parametrize("token", ["", "mauvaise-cle", "x" * 5000])
def test_unknown_api_key_is_rejected(token):
    _, digest = new_api_key()
    with pytest.raises(AuthError) as error:
        ApiKeyAuthenticator({"logiciel-rh": digest}).authenticate(token)
    assert error.value.status_code == 401


def test_api_key_hash_itself_is_not_a_valid_key():
    _, digest = new_api_key()
    with pytest.raises(AuthError):
        ApiKeyAuthenticator({"logiciel-rh": digest}).authenticate(digest)


def test_valid_token_is_accepted(authenticator, signing_key):
    principal = authenticator.authenticate(
        make_token(signing_key, preferred_username="rh@exemple.be")
    )
    assert (principal.subject, principal.method) == ("rh@exemple.be", "oidc")


@pytest.mark.parametrize(
    "claims",
    [
        {"roles": None, "scp": f"autre {ROLE}"},
        {"roles": None, "scope": ROLE},
        {"roles": None, "realm_access": {"roles": [ROLE]}},
    ],
)
def test_role_is_read_from_common_claim_layouts(authenticator, signing_key, claims):
    assert authenticator.authenticate(make_token(signing_key, **claims)).subject == "client-rh"


@pytest.mark.parametrize(
    "claims",
    [{"roles": ["autre.role"]}, {"roles": None}, {"roles": None, "realm_access": "invalide"}],
)
def test_missing_role_is_forbidden(authenticator, signing_key, claims):
    with pytest.raises(AuthError) as error:
        authenticator.authenticate(make_token(signing_key, **claims))
    assert error.value.status_code == 403


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": int(time.time()) - 3600},
        {"iss": "https://faux-idp.exemple.be"},
        {"aud": "autre-api"},
        {"sub": None},
        {"exp": None},
    ],
)
def test_invalid_claims_are_rejected(authenticator, signing_key, claims):
    with pytest.raises(AuthError) as error:
        authenticator.authenticate(make_token(signing_key, **claims))
    assert error.value.status_code == 401


def test_token_signed_by_another_key_is_rejected(authenticator):
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(AuthError) as error:
        authenticator.authenticate(make_token(other_key))
    assert error.value.status_code == 401


def test_symmetric_and_unsigned_tokens_are_rejected(authenticator):
    with pytest.raises(AuthError):
        authenticator.authenticate(make_token("secret-partage-de-32-octets-minimum!", "HS256"))
    with pytest.raises(AuthError):
        authenticator.authenticate(make_token(None, "none"))
    with pytest.raises(AuthError):
        authenticator.authenticate("pas-un-jwt")


def test_unreachable_identity_provider_is_a_503(signing_key):
    from jwt.exceptions import PyJWKClientConnectionError

    def unreachable(token):
        raise PyJWKClientConnectionError("injoignable")

    authenticator = OidcAuthenticator(ISSUER, AUDIENCE, ROLE, ["RS256"], unreachable)
    with pytest.raises(AuthError) as error:
        authenticator.authenticate(make_token(signing_key))
    assert error.value.status_code == 503
