"""Application FastAPI : routes, authentification, en-têtes de sécurité."""

import logging
import time
import uuid
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles

from iam_ad import __version__
from iam_ad.audit import audit, configure_logging
from iam_ad.auth import Authenticator, AuthError, Principal, build_authenticator
from iam_ad.config import Settings, get_settings
from iam_ad.directory import (
    Directory,
    DirectoryError,
    DirectoryRefusedError,
    DirectoryUnavailableError,
)
from iam_ad.models import ErrorResponse, UserCreateRequest, UserCreateResponse
from iam_ad.service import InvalidRequestError, ProvisioningError, UserProvisioner

logger = logging.getLogger(__name__)

_STATIC_DIR = Path(__file__).parent / "static"
_READINESS_CACHE_SECONDS = 15

_CSP_APP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
    "img-src 'self' data:; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
# La page de documentation interactive (Swagger UI) charge ses ressources depuis un CDN.
_CSP_DOCS = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data: https://fastapi.tiangolo.com; frame-ancestors 'none'"
)


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.code = code
        self.detail = detail


def build_directory(settings: Settings) -> Directory:
    if settings.directory_backend == "memory":
        from iam_ad.directory.memory import MemoryDirectory

        logger.warning(
            "IAM_DIRECTORY_BACKEND=memory : annuaire de démonstration, AUCUN compte n'est créé "
            "dans Active Directory"
        )
        return MemoryDirectory()
    from iam_ad.directory.ldap_ad import LdapDirectory

    return LdapDirectory(settings)


def create_app(
    settings: Settings | None = None,
    directory: Directory | None = None,
    authenticator: Authenticator | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging()
    directory = directory or build_directory(settings)
    authenticator = authenticator or build_authenticator(settings)
    provisioner = UserProvisioner(directory, settings)

    app = FastAPI(
        title="IAM – création de comptes Active Directory",
        version=__version__,
        description=(
            "Crée les comptes utilisateurs dans Active Directory à partir du nom, du prénom, "
            "de l'adresse mail et du matricule. Le login et le mot de passe initial sont générés."
        ),
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
    )
    bearer = HTTPBearer(
        auto_error=False,
        description="Jeton d'accès OIDC ou clé d'API, selon IAM_AUTH_MODE.",
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        request.state.request_id = uuid.uuid4().hex
        response: Response = await call_next(request)
        is_docs = request.url.path.startswith("/docs")
        response.headers["Content-Security-Policy"] = _CSP_DOCS if is_docs else _CSP_APP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    @app.exception_handler(ApiError)
    async def api_error_handler(request: Request, error: ApiError) -> JSONResponse:
        headers = {"WWW-Authenticate": "Bearer"} if error.status_code == 401 else None
        return JSONResponse(
            {"code": error.code, "detail": error.detail},
            status_code=error.status_code,
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(
        request: Request, error: RequestValidationError
    ) -> JSONResponse:
        # Même forme que les autres erreurs, sans renvoyer les valeurs reçues.
        errors = [
            {
                "champ": ".".join(str(part) for part in item["loc"] if part != "body") or "corps",
                "message": item["msg"].removeprefix("Value error, "),
            }
            for item in error.errors()
        ]
        return JSONResponse(
            {
                "code": "donnees_invalides",
                "detail": "Les données envoyées sont invalides.",
                "erreurs": errors,
            },
            status_code=422,
        )

    def require_principal(
        request: Request,
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Principal:
        client = request.client.host if request.client else None
        request_id = request.state.request_id
        if credentials is None:
            audit("auth", "refusé", reason="jeton absent", client=client, request_id=request_id)
            raise ApiError(401, "non_authentifie", "Authentification requise.")
        try:
            return authenticator.authenticate(credentials.credentials)
        except AuthError as error:
            audit("auth", "refusé", reason=error.message, client=client, request_id=request_id)
            code = {401: "non_authentifie", 403: "acces_refuse"}.get(
                error.status_code, "authentification_indisponible"
            )
            raise ApiError(error.status_code, code, error.message) from error

    @app.post(
        "/api/v1/users",
        status_code=201,
        response_model=UserCreateResponse,
        summary="Créer un compte utilisateur",
        responses={
            401: {"model": ErrorResponse, "description": "Authentification absente ou invalide"},
            403: {"model": ErrorResponse, "description": "Rôle insuffisant"},
            409: {"model": ErrorResponse, "description": "Matricule, mail ou login déjà utilisé"},
            422: {"model": ErrorResponse, "description": "Données invalides"},
            502: {"model": ErrorResponse, "description": "Opération refusée par l'annuaire"},
            503: {"model": ErrorResponse, "description": "Annuaire injoignable"},
        },
    )
    def create_user(
        payload: UserCreateRequest,
        request: Request,
        principal: Annotated[Principal, Depends(require_principal)],
    ) -> UserCreateResponse:
        context = {
            "actor": principal.subject,
            "auth_method": principal.method,
            "matricule": payload.matricule,
            "request_id": request.state.request_id,
        }
        try:
            user = provisioner.create_user(
                first_name=payload.prenom,
                last_name=payload.nom,
                mail=str(payload.mail),
                matricule=payload.matricule,
            )
        except ProvisioningError as error:
            audit("user.create", "refusé", reason=error.code, **context)
            status = 422 if isinstance(error, InvalidRequestError) else 409
            raise ApiError(status, error.code, error.message) from error
        except DirectoryUnavailableError as error:
            audit("user.create", "échec", reason="annuaire_indisponible", **context)
            raise ApiError(
                503, "annuaire_indisponible", "L'annuaire est momentanément injoignable."
            ) from error
        except DirectoryRefusedError as error:
            audit("user.create", "échec", reason="operation_refusee", **context)
            raise ApiError(
                502,
                "operation_refusee",
                "L'annuaire a refusé l'opération (droits du compte de service ou politique "
                "de mot de passe). Aucun compte n'a été créé.",
            ) from error
        except DirectoryError as error:
            audit("user.create", "échec", reason="erreur_annuaire", **context)
            raise ApiError(
                502, "erreur_annuaire", "Erreur de l'annuaire. Aucun compte n'a été créé."
            ) from error

        audit("user.create", "succès", login=user.login, dn=user.dn, **context)
        return UserCreateResponse(
            login=user.login,
            upn=user.upn,
            dn=user.dn,
            nom=user.last_name,
            prenom=user.first_name,
            nom_affiche=user.display_name,
            mail=user.mail,
            matricule=user.matricule,
            mot_de_passe_temporaire=user.temporary_password,
        )

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict[str, str]:
        return {"status": "ok", "annuaire": settings.directory_backend}

    readiness: dict[str, float | bool] = {"checked_at": 0.0, "ready": False}

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        # Résultat mis en cache : la sonde ne doit pas permettre de solliciter l'annuaire en boucle.
        now = time.monotonic()
        if now - readiness["checked_at"] > _READINESS_CACHE_SECONDS or not readiness["checked_at"]:
            try:
                directory.check()
                readiness["ready"] = True
            except DirectoryError:
                readiness["ready"] = False
            readiness["checked_at"] = now
        if readiness["ready"]:
            return JSONResponse({"status": "ok"})
        return JSONResponse({"status": "annuaire_indisponible"}, status_code=503)

    app.mount("/", StaticFiles(directory=_STATIC_DIR, html=True), name="ui")
    return app
