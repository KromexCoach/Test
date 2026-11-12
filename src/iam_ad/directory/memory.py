"""Annuaire en mémoire, pour la démonstration et les tests. Rien n'est persisté."""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from iam_ad.directory import EntryConflictError, NewUser, UniqueField

_FIELD_TO_ATTRIBUTE: dict[UniqueField, str] = {
    "login": "login",
    "upn": "upn",
    "mail": "mail",
    "matricule": "matricule",
}


class MemoryDirectory:
    def __init__(self, users_ou: str = "OU=Utilisateurs,DC=demo,DC=local") -> None:
        self._users_ou = users_ou
        self._users: dict[str, NewUser] = {}
        self._lock = threading.Lock()

    @property
    def users(self) -> dict[str, NewUser]:
        """Comptes créés, indexés par DN."""
        return dict(self._users)

    @contextmanager
    def session(self) -> Iterator[MemoryDirectory]:
        yield self

    def check(self) -> None:
        return None

    def is_taken(self, field: UniqueField, value: str) -> bool:
        attribute = _FIELD_TO_ATTRIBUTE[field]
        wanted = value.casefold()
        with self._lock:
            return any(
                getattr(user, attribute).casefold() == wanted for user in self._users.values()
            )

    def create_user(self, user: NewUser, password: str) -> str:
        del password  # volontairement ni conservé ni journalisé
        with self._lock:
            if any(
                existing.login.casefold() == user.login.casefold()
                for existing in self._users.values()
            ):
                raise EntryConflictError(user.login)
            dn = f"CN={user.display_name},{self._users_ou}"
            if dn.casefold() in (existing.casefold() for existing in self._users):
                dn = f"CN={user.display_name} ({user.login}),{self._users_ou}"
            self._users[dn] = user
            return dn
