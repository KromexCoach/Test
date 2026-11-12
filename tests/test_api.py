import json
import logging

import pytest
from fastapi.testclient import TestClient

from iam_ad.api import create_app
from iam_ad.directory import DirectoryRefusedError, DirectoryUnavailableError
from iam_ad.directory.memory import MemoryDirectory
from tests.conftest import API_KEY, make_settings

AUTH = {"Authorization": f"Bearer {API_KEY}"}
MARIE = {
    "nom": "Dupont",
    "prenom": "Marie",
    "mail": "marie.dupont@exemple.be",
    "matricule": "M004217",
}


@pytest.fixture
def directory() -> MemoryDirectory:
    return MemoryDirectory()


@pytest.fixture
def client(directory, settings) -> TestClient:
    return TestClient(create_app(settings=settings, directory=directory))


@pytest.fixture
def audit_records():
    records: list[dict] = []

    class Collector(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(json.loads(record.getMessage()))

    handler = Collector()
    logger = logging.getLogger("iam_ad.audit")
    logger.addHandler(handler)
    yield records
    logger.removeHandler(handler)


def test_create_user(client, directory):
    response = client.post("/api/v1/users", json=MARIE, headers=AUTH)

    assert response.status_code == 201
    body = response.json()
    password = body.pop("mot_de_passe_temporaire")
    assert len(password) == 10
    assert body == {
        "login": "mardup",
        "upn": "mardup@exemple.be",
        "dn": "CN=Marie Dupont,OU=Utilisateurs,DC=demo,DC=local",
        "nom": "Dupont",
        "prenom": "Marie",
        "nom_affiche": "Marie Dupont",
        "mail": "marie.dupont@exemple.be",
        "matricule": "M004217",
        "changement_mot_de_passe_requis": True,
    }
    assert response.headers["cache-control"] == "no-store"
    assert len(directory.users) == 1


def test_names_are_trimmed_and_whitespace_collapsed(client):
    payload = {**MARIE, "prenom": "  Jean   Pierre ", "nom": " de  la Tour "}
    body = client.post("/api/v1/users", json=payload, headers=AUTH).json()
    assert body["nom_affiche"] == "Jean Pierre de la Tour"
    assert body["login"] == "jeadel"


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer mauvaise-cle"}, {"Authorization": f"Basic {API_KEY}"}],
)
def test_authentication_is_required(client, directory, headers):
    response = client.post("/api/v1/users", json=MARIE, headers=headers)
    assert response.status_code == 401
    assert response.json()["code"] == "non_authentifie"
    assert response.headers["www-authenticate"] == "Bearer"
    assert directory.users == {}


def test_authentication_is_checked_before_the_payload(client):
    response = client.post("/api/v1/users", json={"n'importe": "quoi"})
    assert response.status_code == 401


@pytest.mark.parametrize(
    "change",
    [
        {"nom": ""},
        {"nom": "Dupont<script>"},
        {"prenom": "Marie\u0000"},
        {"prenom": "x" * 65},
        {"prenom": "-Marie"},
        {"mail": "pas-une-adresse"},
        {"matricule": "x" * 17},
        {"matricule": ""},
        {"login": "admin"},  # champ inconnu : le login n'est pas choisi par l'appelant
        {"nom": None},
    ],
)
def test_invalid_payload_is_rejected(client, directory, change):
    response = client.post("/api/v1/users", json={**MARIE, **change}, headers=AUTH)
    assert response.status_code == 422
    body = response.json()
    assert body["code"] == "donnees_invalides"
    assert [error["champ"] for error in body["erreurs"]] == list(change)
    assert directory.users == {}


def test_validation_errors_do_not_echo_the_input(client):
    response = client.post("/api/v1/users", json={**MARIE, "nom": "valeur<envoyée>"}, headers=AUTH)
    assert response.json()["erreurs"] == [
        {
            "champ": "nom",
            "message": "ne doit contenir que des lettres, espaces, tirets et apostrophes",
        }
    ]
    assert "valeur<envoyée>" not in response.text
    assert client.post("/api/v1/users", content="{", headers=AUTH).status_code == 422


def test_duplicate_matricule_returns_409(client):
    assert client.post("/api/v1/users", json=MARIE, headers=AUTH).status_code == 201
    response = client.post(
        "/api/v1/users", json={**MARIE, "mail": "autre@exemple.be"}, headers=AUTH
    )
    assert response.status_code == 409
    assert response.json() == {
        "code": "matricule_deja_utilise",
        "detail": "Un compte existe déjà avec ce matricule.",
    }


def test_business_rule_violation_returns_422_with_code(client):
    response = client.post("/api/v1/users", json={**MARIE, "matricule": "a b"}, headers=AUTH)
    assert response.status_code == 422
    assert response.json()["code"] == "matricule_invalide"


@pytest.mark.parametrize(
    ("error", "status", "code"),
    [
        (DirectoryUnavailableError("LDAPSocketOpenError"), 503, "annuaire_indisponible"),
        (DirectoryRefusedError("LDAPInsufficientAccessRightsResult"), 502, "operation_refusee"),
    ],
)
def test_directory_failures_do_not_leak_details(settings, error, status, code):
    class FailingDirectory(MemoryDirectory):
        def create_user(self, user, password):
            raise error

    client = TestClient(create_app(settings=settings, directory=FailingDirectory()))
    response = client.post("/api/v1/users", json=MARIE, headers=AUTH)
    assert response.status_code == status
    assert response.json()["code"] == code
    assert "LDAP" not in response.text


def test_audit_trail_records_actor_and_never_the_password(client, audit_records):
    password = client.post("/api/v1/users", json=MARIE, headers=AUTH).json()[
        "mot_de_passe_temporaire"
    ]
    client.post("/api/v1/users", json=MARIE, headers=AUTH)
    client.post("/api/v1/users", json=MARIE, headers={"Authorization": "Bearer mauvaise-cle"})

    created, conflict, denied = audit_records
    assert created["event"] == "user.create"
    assert created["outcome"] == "succès"
    assert created["actor"] == "logiciel-rh"
    assert created["login"] == "mardup"
    assert created["matricule"] == "M004217"
    assert created["request_id"]
    assert (conflict["outcome"], conflict["reason"]) == ("refusé", "matricule_deja_utilise")
    assert (denied["event"], denied["outcome"]) == ("auth", "refusé")
    dump = json.dumps(audit_records)
    assert password not in dump
    assert API_KEY not in dump
    assert "mauvaise-cle" not in dump


def test_security_headers(client):
    for path in ("/", "/healthz", "/api/v1/users"):
        headers = client.get(path).headers
        assert "default-src 'none'" in headers["content-security-policy"]
        assert "frame-ancestors 'none'" in headers["content-security-policy"]
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["strict-transport-security"].startswith("max-age=")
        assert headers["x-request-id"]


def test_ui_and_health_endpoints(client):
    assert "Nouveau compte utilisateur" in client.get("/").text
    assert client.get("/app.js").status_code == 200
    assert client.get("/healthz").json() == {"status": "ok", "annuaire": "memory"}
    assert client.get("/readyz").status_code == 200


def test_readiness_reflects_directory_state(settings):
    class DownDirectory(MemoryDirectory):
        def check(self):
            raise DirectoryUnavailableError("injoignable")

    client = TestClient(create_app(settings=settings, directory=DownDirectory()))
    assert client.get("/readyz").status_code == 503


def test_interactive_docs_are_opt_in_and_openapi_contract_is_always_served(directory):
    default = TestClient(create_app(settings=make_settings(), directory=directory))
    enabled = TestClient(create_app(settings=make_settings(enable_docs=True), directory=directory))

    assert default.get("/docs").status_code == 404
    assert enabled.get("/docs").status_code == 200
    assert "cdn.jsdelivr.net" in enabled.get("/docs").headers["content-security-policy"]

    contract = default.get("/openapi.json").json()
    assert "/api/v1/users" in contract["paths"]
    assert contract["paths"]["/api/v1/users"]["post"]["security"] == [{"HTTPBearer": []}]
