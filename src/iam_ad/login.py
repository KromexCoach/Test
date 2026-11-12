"""Génération du login : premières lettres du prénom + premières lettres du nom."""

from __future__ import annotations

import unicodedata
from collections.abc import Iterator

# Limite historique de sAMAccountName pour un compte utilisateur.
SAM_ACCOUNT_NAME_MAX = 20
_MAX_SUFFIX = 99

# Lettres que la décomposition Unicode ne ramène pas à une lettre ASCII.
_TRANSLITERATION = str.maketrans(
    {"æ": "ae", "œ": "oe", "ø": "o", "đ": "d", "ð": "d", "þ": "th", "ł": "l", "ı": "i"}
)


class LoginError(ValueError):
    """Le login ne peut pas être dérivé des nom et prénom fournis."""


def ascii_letters(text: str) -> str:
    """Réduit un texte à ses lettres a-z : « Éloïse » -> « eloise », « D'Hondt » -> « dhondt »."""
    text = text.casefold().translate(_TRANSLITERATION)
    decomposed = unicodedata.normalize("NFKD", text)
    return "".join(char for char in decomposed if "a" <= char <= "z")


def build_login(
    first_name: str, last_name: str, first_letters: int = 3, last_letters: int = 3
) -> str:
    """« Marie », « Dupont » -> « mardup ».

    Un nom plus court que le nombre de lettres demandé est pris en entier (« Li » -> « li »).
    """
    first = ascii_letters(first_name)[:first_letters]
    last = ascii_letters(last_name)[:last_letters]
    if not first or not last:
        raise LoginError(
            "impossible de dériver un login : le prénom et le nom doivent contenir "
            "au moins une lettre latine"
        )
    return first + last


def login_candidates(base: str) -> Iterator[str]:
    """Le login de base, puis ses variantes numérotées en cas d'homonymie : mardup, mardup2…"""
    yield base[:SAM_ACCOUNT_NAME_MAX]
    for index in range(2, _MAX_SUFFIX + 1):
        suffix = str(index)
        yield base[: SAM_ACCOUNT_NAME_MAX - len(suffix)] + suffix
