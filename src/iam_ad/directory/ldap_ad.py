"""Connecteur Active Directory via LDAPS.

Le mot de passe (`unicodePwd`) ne peut être écrit que sur un canal chiffré : la connexion
est donc toujours LDAPS (TLS, certificat du contrôleur de domaine vérifié), jamais LDAP simple.
"""

from __future__ import annotations

import logging
import ssl
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from ldap3 import (
    FIRST,
    LEVEL,
    MODIFY_REPLACE,
    NONE,
    SIMPLE,
    SUBTREE,
    Connection,
    Server,
    ServerPool,
    Tls,
)
from ldap3.core.exceptions import (
    LDAPBindError,
    LDAPCertificateError,
    LDAPCommunicationError,
    LDAPConstraintViolationResult,
    LDAPEntryAlreadyExistsResult,
    LDAPException,
    LDAPInsufficientAccessRightsResult,
    LDAPInvalidCredentialsResult,
    LDAPResponseTimeoutError,
    LDAPServerPoolError,
    LDAPServerPoolExhaustedError,
    LDAPUnwillingToPerformResult,
)
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import escape_rdn

from iam_ad.config import Settings
from iam_ad.directory import (
    DirectoryError,
    DirectoryRefusedError,
    DirectoryUnavailableError,
    EntryConflictError,
    NewUser,
    UniqueField,
)

logger = logging.getLogger(__name__)

# userAccountControl
_NORMAL_ACCOUNT = 0x0200
_ACCOUNT_DISABLE = 0x0002

_USER_OBJECT_CLASSES = ["top", "person", "organizationalPerson", "user"]

_UNAVAILABLE = (
    LDAPBindError,
    LDAPInvalidCredentialsResult,
    LDAPCertificateError,
    LDAPCommunicationError,
    LDAPResponseTimeoutError,
    LDAPServerPoolError,
    LDAPServerPoolExhaustedError,
    ssl.SSLError,
    OSError,
)
_REFUSED = (
    LDAPInsufficientAccessRightsResult,
    LDAPConstraintViolationResult,
    LDAPUnwillingToPerformResult,
)


def _translate(error: Exception) -> DirectoryError:
    """Convertit une erreur ldap3 en erreur métier, sans propager le détail au client."""
    kind = type(error).__name__
    if isinstance(error, LDAPEntryAlreadyExistsResult):
        return EntryConflictError(kind)
    if isinstance(error, _REFUSED):
        return DirectoryRefusedError(kind)
    if isinstance(error, _UNAVAILABLE):
        return DirectoryUnavailableError(kind)
    return DirectoryError(kind)


class LdapSession:
    def __init__(self, connection: Connection, settings: Settings) -> None:
        self._connection = connection
        self._base_dn = settings.ad_base_dn
        self._users_ou = settings.ad_users_ou

    def _exists(self, search_base: str, search_filter: str, scope: str = SUBTREE) -> bool:
        self._connection.search(
            search_base, search_filter, search_scope=scope, attributes=["sAMAccountName"]
        )
        # Les renvois vers d'autres partitions (searchResRef) ne sont pas des objets trouvés.
        return any(item.get("type") == "searchResEntry" for item in self._connection.response)

    def is_taken(self, field: UniqueField, value: str) -> bool:
        escaped = escape_filter_chars(value)
        filters: dict[UniqueField, str] = {
            # sAMAccountName est unique pour tout le domaine, tous types d'objets confondus.
            "login": f"(sAMAccountName={escaped})",
            "upn": f"(userPrincipalName={escaped})",
            "mail": f"(|(mail={escaped})(proxyAddresses=smtp:{escaped}))",
            "matricule": f"(employeeID={escaped})",
        }
        try:
            return self._exists(self._base_dn, filters[field])
        except (LDAPException, OSError) as error:
            logger.error("recherche %s en échec : %r", field, error)
            raise _translate(error) from error

    def create_user(self, user: NewUser, password: str) -> str:
        connection = self._connection
        try:
            common_name = user.display_name
            if self._exists(self._users_ou, f"(cn={escape_filter_chars(common_name)})", LEVEL):
                common_name = f"{user.display_name} ({user.login})"
            dn = f"CN={escape_rdn(common_name)},{self._users_ou}"

            # 1. Création du compte désactivé : il n'est jamais utilisable sans mot de passe.
            connection.add(
                dn,
                _USER_OBJECT_CLASSES,
                {
                    "cn": common_name,
                    "givenName": user.first_name,
                    "sn": user.last_name,
                    "displayName": user.display_name,
                    "sAMAccountName": user.login,
                    "userPrincipalName": user.upn,
                    "mail": user.mail,
                    "employeeID": user.matricule,
                    "userAccountControl": _NORMAL_ACCOUNT | _ACCOUNT_DISABLE,
                },
            )
        except (LDAPException, OSError) as error:
            logger.error("création du compte %s en échec : %r", user.login, error)
            raise _translate(error) from error

        try:
            # 2. Mot de passe initial (soumis à la politique de mots de passe du domaine).
            connection.extend.microsoft.modify_password(dn, password)
            # 3. Activation, avec changement de mot de passe imposé à la première connexion.
            connection.modify(
                dn,
                {
                    "userAccountControl": [(MODIFY_REPLACE, [_NORMAL_ACCOUNT])],
                    "pwdLastSet": [(MODIFY_REPLACE, [0])],
                },
            )
        except (LDAPException, OSError) as error:
            logger.error("finalisation du compte %s en échec : %r", user.login, error)
            self._rollback(dn)
            raise _translate(error) from error
        return dn

    def _rollback(self, dn: str) -> None:
        try:
            self._connection.delete(dn)
        except (LDAPException, OSError) as error:
            logger.critical(
                "ANNULATION IMPOSSIBLE : le compte désactivé %s doit être supprimé à la main (%r)",
                dn,
                error,
            )


class LdapDirectory:
    def __init__(
        self, settings: Settings, connection_factory: Callable[[], Connection] | None = None
    ) -> None:
        self._settings = settings
        self._connection_factory = connection_factory or self._connect

    def _connect(self) -> Connection:
        settings = self._settings
        # Contexte TLS par défaut de Python : TLS >= 1.2 et chaîne de certificats vérifiée.
        # ldap3 vérifie en plus que le certificat correspond au nom du serveur.
        tls = Tls(
            validate=ssl.CERT_REQUIRED,
            ca_certs_file=str(settings.ad_ca_cert_file) if settings.ad_ca_cert_file else None,
        )
        servers = [
            Server(
                host,
                port=settings.ad_port,
                use_ssl=True,
                tls=tls,
                get_info=NONE,
                connect_timeout=settings.ad_timeout_seconds,
            )
            for host in settings.ad_servers
        ]
        target = servers[0] if len(servers) == 1 else ServerPool(servers, FIRST, active=1)
        return Connection(
            target,
            user=settings.ad_bind_user,
            password=settings.ad_bind_password.get_secret_value(),
            authentication=SIMPLE,
            auto_bind=True,
            auto_referrals=False,
            raise_exceptions=True,
            receive_timeout=settings.ad_timeout_seconds,
        )

    @contextmanager
    def session(self) -> Iterator[LdapSession]:
        try:
            connection = self._connection_factory()
        except (LDAPException, OSError) as error:
            logger.error("connexion à l'annuaire en échec : %r", error)
            raise _translate(error) from error
        try:
            yield LdapSession(connection, self._settings)
        finally:
            try:
                connection.unbind()
            except (LDAPException, OSError):
                logger.debug("fermeture de la connexion LDAP en échec", exc_info=True)

    def check(self) -> None:
        with self.session():
            pass
