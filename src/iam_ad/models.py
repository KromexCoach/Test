"""Schémas JSON de l'API."""

from __future__ import annotations

import unicodedata
from typing import Annotated

from pydantic import AfterValidator, BaseModel, ConfigDict, EmailStr, Field

_NAME_MAX_LENGTH = 64
_NAME_PUNCTUATION = " -'’."


def _clean_name(value: str) -> str:
    value = unicodedata.normalize("NFC", " ".join(value.split()))
    if not value:
        raise ValueError("ne doit pas être vide")
    if len(value) > _NAME_MAX_LENGTH:
        raise ValueError(f"ne doit pas dépasser {_NAME_MAX_LENGTH} caractères")
    if not all(char.isalpha() or char in _NAME_PUNCTUATION for char in value):
        raise ValueError("ne doit contenir que des lettres, espaces, tirets et apostrophes")
    if not value[0].isalpha():
        raise ValueError("doit commencer par une lettre")
    return value


PersonName = Annotated[str, Field(max_length=256), AfterValidator(_clean_name)]


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        json_schema_extra={
            "example": {
                "nom": "Dupont",
                "prenom": "Marie",
                "mail": "marie.dupont@exemple.be",
                "matricule": "M004217",
            }
        },
    )

    nom: PersonName = Field(description="Nom de famille")
    prenom: PersonName = Field(description="Prénom")
    mail: EmailStr = Field(description="Adresse de messagerie")
    matricule: str = Field(min_length=1, max_length=16, description="Numéro de matricule")


class UserCreateResponse(BaseModel):
    login: str = Field(description="Identifiant de connexion (sAMAccountName)")
    upn: str = Field(description="Nom principal d'utilisateur (userPrincipalName)")
    dn: str = Field(description="Nom distinctif de l'objet créé dans l'annuaire")
    nom: str
    prenom: str
    nom_affiche: str
    mail: str
    matricule: str
    mot_de_passe_temporaire: str = Field(
        description="Mot de passe initial. Communiqué une seule fois, ni conservé ni journalisé."
    )
    changement_mot_de_passe_requis: bool = True


class FieldError(BaseModel):
    champ: str
    message: str


class ErrorResponse(BaseModel):
    code: str = Field(description="Code stable, exploitable par les applications clientes")
    detail: str = Field(description="Message lisible, en français")
    erreurs: list[FieldError] | None = Field(
        default=None, description="Détail par champ, pour le code « donnees_invalides »"
    )
