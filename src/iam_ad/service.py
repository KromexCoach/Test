"""Création d'un compte utilisateur : règles métier, indépendantes de HTTP et de LDAP."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from iam_ad.config import Settings
from iam_ad.directory import Directory, EntryConflictError, NewUser
from iam_ad.login import LoginError, build_login, login_candidates
from iam_ad.password import forbidden_fragments, generate_password


class ProvisioningError(Exception):
    """Demande refusée pour une raison que l'appelant peut corriger."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class InvalidRequestError(ProvisioningError):
    pass


class UserConflictError(ProvisioningError):
    pass


@dataclass(frozen=True, slots=True)
class CreatedUser:
    login: str
    upn: str
    dn: str
    first_name: str
    last_name: str
    display_name: str
    mail: str
    matricule: str
    # repr=False : le mot de passe n'apparaît jamais dans une trace ou un journal.
    temporary_password: str = field(repr=False)


class UserProvisioner:
    def __init__(self, directory: Directory, settings: Settings) -> None:
        self._directory = directory
        self._settings = settings
        self._matricule_pattern = re.compile(settings.matricule_pattern)

    def create_user(
        self, first_name: str, last_name: str, mail: str, matricule: str
    ) -> CreatedUser:
        settings = self._settings
        mail = mail.strip().lower()
        matricule = matricule.strip()

        if not self._matricule_pattern.fullmatch(matricule):
            raise InvalidRequestError("matricule_invalide", "Le format du matricule est invalide.")
        domain = mail.rpartition("@")[2]
        if settings.mail_allowed_domains and domain not in settings.mail_allowed_domains:
            raise InvalidRequestError(
                "domaine_mail_refuse", f"Le domaine de messagerie « {domain} » n'est pas autorisé."
            )
        try:
            base_login = build_login(
                first_name,
                last_name,
                settings.login_first_name_letters,
                settings.login_last_name_letters,
            )
        except LoginError as error:
            raise InvalidRequestError(
                "login_non_derivable", str(error).capitalize() + "."
            ) from error

        with self._directory.session() as session:
            if session.is_taken("matricule", matricule):
                raise UserConflictError(
                    "matricule_deja_utilise", "Un compte existe déjà avec ce matricule."
                )
            if session.is_taken("mail", mail):
                raise UserConflictError(
                    "mail_deja_utilise", "Un compte existe déjà avec cette adresse mail."
                )

            for login in login_candidates(base_login):
                upn = f"{login}@{settings.ad_upn_suffix}"
                if not session.is_taken("login", login) and not session.is_taken("upn", upn):
                    break
            else:
                raise UserConflictError(
                    "login_indisponible", f"Aucun login disponible à partir de « {base_login} »."
                )

            user = NewUser(
                login=login,
                upn=upn,
                first_name=first_name,
                last_name=last_name,
                display_name=f"{first_name} {last_name}",
                mail=mail,
                matricule=matricule,
            )
            password = generate_password(
                settings.password_length, forbidden_fragments(login, first_name, last_name)
            )
            try:
                dn = session.create_user(user, password)
            except EntryConflictError as error:
                # Deux demandes simultanées pour le même login : l'annuaire a tranché.
                raise UserConflictError(
                    "creation_concurrente",
                    "Un compte identique vient d'être créé. Relancez la demande.",
                ) from error

        return CreatedUser(
            login=user.login,
            upn=user.upn,
            dn=dn,
            first_name=user.first_name,
            last_name=user.last_name,
            display_name=user.display_name,
            mail=user.mail,
            matricule=user.matricule,
            temporary_password=password,
        )
