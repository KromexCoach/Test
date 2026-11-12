"""Connecteur LDAP testé contre l'annuaire simulé de ldap3 (schéma Active Directory)."""

import pytest
from ldap3 import MOCK_SYNC, OFFLINE_AD_2012_R2, Connection, Server
from ldap3.core.exceptions import (
    LDAPInsufficientAccessRightsResult,
    LDAPSocketOpenError,
    LDAPUnwillingToPerformResult,
)

from iam_ad.directory import (
    DirectoryRefusedError,
    DirectoryUnavailableError,
    EntryConflictError,
    NewUser,
)
from iam_ad.directory.ldap_ad import LdapDirectory
from tests.conftest import make_settings
from tests.test_config import LDAP

BASE_DN = LDAP["ad_base_dn"]
USERS_OU = LDAP["ad_users_ou"]
PASSWORD = "Ab3!efghJK"
# Le simulateur n'accepte qu'un DN comme identité de connexion.
BIND_DN = f"CN=svc-iam,OU=Services,{BASE_DN}"

MARIE = NewUser(
    login="mardup",
    upn="mardup@exemple.be",
    first_name="Marie",
    last_name="Dupont",
    display_name="Marie Dupont",
    mail="marie.dupont@exemple.be",
    matricule="M004217",
)


@pytest.fixture
def connection() -> Connection:
    server = Server("dc1.corp.exemple.be", get_info=OFFLINE_AD_2012_R2)
    connection = Connection(
        server,
        user=BIND_DN,
        password=LDAP["ad_bind_password"],
        client_strategy=MOCK_SYNC,
        raise_exceptions=True,
    )
    connection.strategy.add_entry(BIND_DN, {"userPassword": LDAP["ad_bind_password"]})
    connection.strategy.add_entry(USERS_OU, {"objectClass": ["top", "organizationalUnit"]})
    connection.bind()
    return connection


@pytest.fixture
def directory(connection) -> LdapDirectory:
    # La session ferme sa connexion ; le simulateur est rouvert à chaque session.
    def factory() -> Connection:
        if not connection.bound:
            connection.bind()
        return connection

    return LdapDirectory(make_settings(**LDAP), connection_factory=factory)


def read_entry(connection: Connection, dn: str) -> dict:
    if not connection.bound:
        connection.bind()
    connection.search(dn, "(objectClass=*)", search_scope="BASE", attributes=["*"])
    return connection.response[0]["raw_attributes"]


def test_creates_enabled_account_with_expected_attributes(directory, connection):
    with directory.session() as session:
        dn = session.create_user(MARIE, PASSWORD)

    assert dn == f"CN=Marie Dupont,{USERS_OU}"
    entry = read_entry(connection, dn)
    assert entry["sAMAccountName"] == [b"mardup"]
    assert entry["userPrincipalName"] == [b"mardup@exemple.be"]
    assert entry["givenName"] == [b"Marie"]
    assert entry["sn"] == [b"Dupont"]
    assert entry["displayName"] == [b"Marie Dupont"]
    assert entry["mail"] == [b"marie.dupont@exemple.be"]
    assert entry["employeeID"] == [b"M004217"]
    assert {b"user", b"person"} <= set(entry["objectClass"])
    # Compte normal et activé (512), mot de passe à changer à la première connexion.
    assert entry["userAccountControl"] == [b"512"]
    assert entry["pwdLastSet"] == [b"0"]
    # Format imposé par AD : mot de passe entre guillemets, encodé en UTF-16LE.
    assert entry["unicodePwd"] == [f'"{PASSWORD}"'.encode("utf-16-le")]


def test_uniqueness_lookups(directory):
    with directory.session() as session:
        session.create_user(MARIE, PASSWORD)
        assert session.is_taken("login", "MARDUP")
        assert session.is_taken("upn", "mardup@exemple.be")
        assert session.is_taken("mail", "marie.dupont@exemple.be")
        assert session.is_taken("matricule", "M004217")
        assert not session.is_taken("login", "mardup2")
        assert not session.is_taken("mail", "autre@exemple.be")
        assert not session.is_taken("matricule", "M000001")


def test_mail_held_as_secondary_address_is_taken(directory, connection):
    connection.strategy.add_entry(
        f"CN=Boîte partagée,{USERS_OU}",
        {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "sAMAccountName": "boite",
            "proxyAddresses": ["smtp:alias@exemple.be"],
        },
    )
    with directory.session() as session:
        assert session.is_taken("mail", "alias@exemple.be")


def test_filter_metacharacters_are_escaped(directory):
    with directory.session() as session:
        session.create_user(MARIE, PASSWORD)
        assert not session.is_taken("login", "*")
        assert not session.is_taken("matricule", "*)(sAMAccountName=mardup")
        assert not session.is_taken("mail", "x)(|(mail=*")


def test_same_display_name_gets_a_distinct_common_name(directory):
    homonym = NewUser(
        login="mardup2",
        upn="mardup2@exemple.be",
        first_name="Marie",
        last_name="Dupont",
        display_name="Marie Dupont",
        mail="marie.dupont2@exemple.be",
        matricule="M2",
    )
    with directory.session() as session:
        session.create_user(MARIE, PASSWORD)
        assert session.create_user(homonym, PASSWORD) == f"CN=Marie Dupont (mardup2),{USERS_OU}"


def test_special_characters_in_names_are_escaped_in_the_dn(directory, connection):
    user = NewUser(
        login="anndho",
        upn="anndho@exemple.be",
        first_name="Anne",
        last_name="D'Hondt, Jr.",
        display_name="Anne D'Hondt, Jr.",
        mail="anne.dhondt@exemple.be",
        matricule="M3",
    )
    with directory.session() as session:
        dn = session.create_user(user, PASSWORD)
    assert dn == f"CN=Anne D'Hondt\\, Jr.,{USERS_OU}"
    assert read_entry(connection, dn)["sn"] == [b"D'Hondt, Jr."]


def test_existing_object_is_reported_as_conflict(directory, connection, monkeypatch):
    with directory.session() as session:
        session.create_user(MARIE, PASSWORD)
        # Le contrôle préalable est neutralisé pour simuler une création concurrente.
        monkeypatch.setattr(session, "_exists", lambda *args, **kwargs: False)
        with pytest.raises(EntryConflictError):
            session.create_user(MARIE, PASSWORD)


@pytest.mark.parametrize(
    ("failing_step", "error"),
    [
        ("password", LDAPUnwillingToPerformResult),  # politique de mot de passe du domaine
        ("enable", LDAPInsufficientAccessRightsResult),
    ],
)
def test_partial_account_is_rolled_back(directory, connection, monkeypatch, failing_step, error):
    original_modify = connection.modify

    def modify(dn, changes, *args, **kwargs):
        step = "password" if "unicodePwd" in changes else "enable"
        if step == failing_step:
            raise error()
        return original_modify(dn, changes, *args, **kwargs)

    monkeypatch.setattr(connection, "modify", modify)
    with directory.session() as session:
        with pytest.raises(DirectoryRefusedError):
            session.create_user(MARIE, PASSWORD)
        assert not session.is_taken("login", "mardup")


def test_unreachable_directory_is_reported_as_unavailable():
    def factory():
        raise LDAPSocketOpenError("connexion refusée")

    directory = LdapDirectory(make_settings(**LDAP), connection_factory=factory)
    with pytest.raises(DirectoryUnavailableError):
        directory.check()


def test_session_closes_the_connection(directory, connection):
    with directory.session():
        assert connection.bound
    assert not connection.bound


def test_real_connections_are_ldaps_with_certificate_validation(monkeypatch):
    import ssl

    captured = {}

    def fake_connection(target, **kwargs):
        captured.update(kwargs, target=target)
        raise LDAPSocketOpenError("pas de réseau pendant les tests")

    monkeypatch.setattr("iam_ad.directory.ldap_ad.Connection", fake_connection)
    with pytest.raises(DirectoryUnavailableError):
        LdapDirectory(make_settings(**LDAP)).check()

    servers = captured["target"].servers
    assert [server.host for server in servers] == LDAP["ad_servers"].replace(" ", "").split(",")
    for server in servers:
        assert server.ssl is True
        assert server.port == 636
        assert server.tls.validate == ssl.CERT_REQUIRED
    assert captured["auto_referrals"] is False
    assert captured["raise_exceptions"] is True
