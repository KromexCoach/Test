"""Contrat entre le service de création de comptes et l'annuaire."""

from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Literal, Protocol

UniqueField = Literal["login", "upn", "mail", "matricule"]


@dataclass(frozen=True, slots=True)
class NewUser:
    login: str
    upn: str
    first_name: str
    last_name: str
    display_name: str
    mail: str
    matricule: str


class DirectoryError(Exception):
    """Erreur inattendue renvoyée par l'annuaire."""


class DirectoryUnavailableError(DirectoryError):
    """Annuaire injoignable, certificat refusé ou compte de service rejeté."""


class EntryConflictError(DirectoryError):
    """L'annuaire a refusé la création : un objet identique existe déjà."""


class DirectoryRefusedError(DirectoryError):
    """L'annuaire a refusé l'opération (droits insuffisants, politique de mot de passe…)."""


class DirectorySession(Protocol):
    def is_taken(self, field: UniqueField, value: str) -> bool:
        """Indique si la valeur est déjà portée par un objet de l'annuaire."""

    def create_user(self, user: NewUser, password: str) -> str:
        """Crée le compte activé, mot de passe à changer à la première connexion.

        Retourne le DN de l'objet créé. Ne laisse aucun compte partiel en cas d'échec.
        """


class Directory(Protocol):
    def session(self) -> AbstractContextManager[DirectorySession]:
        """Ouvre une session authentifiée sur l'annuaire."""

    def check(self) -> None:
        """Vérifie que l'annuaire est joignable ; lève `DirectoryError` sinon."""
