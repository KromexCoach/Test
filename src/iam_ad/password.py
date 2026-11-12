"""Génération du mot de passe initial.

- tirage par le générateur cryptographique du système (`secrets`), jamais `random` ;
- au moins une majuscule, une minuscule, un chiffre et un symbole (complexité AD) ;
- aucun fragment du login ou du nom de la personne (règle de complexité AD) ;
- pas de caractères ambigus à la lecture (O/0, I/l/1) : le mot de passe est transmis une fois
  à l'utilisateur, qui doit le changer à sa première ouverture de session.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Iterable

from iam_ad.login import ascii_letters

UPPERCASE = "ABCDEFGHJKLMNPQRSTUVWXYZ"
LOWERCASE = "abcdefghijkmnopqrstuvwxyz"
DIGITS = "23456789"
SYMBOLS = "!#$%*+-=?@_"
_CLASSES = (UPPERCASE, LOWERCASE, DIGITS, SYMBOLS)
_ALPHABET = "".join(_CLASSES)

MIN_LENGTH = 10
_MIN_FORBIDDEN_FRAGMENT = 3
_MAX_ATTEMPTS = 1000
_TOKEN_SEPARATORS = re.compile(r"[\s,.\-_#'’]+")

_rng = secrets.SystemRandom()


def forbidden_fragments(*values: str) -> set[str]:
    """Fragments (>= 3 caractères) que le mot de passe ne doit pas contenir."""
    fragments: set[str] = set()
    for value in values:
        for token in _TOKEN_SEPARATORS.split(value):
            for candidate in (token.casefold(), ascii_letters(token)):
                if len(candidate) >= _MIN_FORBIDDEN_FRAGMENT:
                    fragments.add(candidate)
    return fragments


def is_compliant(password: str, forbidden: Iterable[str] = ()) -> bool:
    if len(password) < MIN_LENGTH:
        return False
    if any(char not in _ALPHABET for char in password):
        return False
    if not all(any(char in group for char in password) for group in _CLASSES):
        return False
    if any(a == b == c for a, b, c in zip(password, password[1:], password[2:], strict=False)):
        return False
    folded = password.casefold()
    return not any(fragment in folded for fragment in forbidden)


def generate_password(length: int = MIN_LENGTH, forbidden: Iterable[str] = ()) -> str:
    if length < MIN_LENGTH:
        raise ValueError(f"la longueur minimale est de {MIN_LENGTH} caractères")
    forbidden = set(forbidden)
    for _ in range(_MAX_ATTEMPTS):
        chars = [secrets.choice(group) for group in _CLASSES]
        chars += [secrets.choice(_ALPHABET) for _ in range(length - len(chars))]
        _rng.shuffle(chars)
        password = "".join(chars)
        if is_compliant(password, forbidden):
            return password
    raise RuntimeError("impossible de générer un mot de passe conforme")  # pragma: no cover
