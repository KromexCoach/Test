from contextlib import contextmanager

import pytest

from iam_ad.directory import EntryConflictError
from iam_ad.directory.memory import MemoryDirectory
from iam_ad.password import is_compliant
from iam_ad.service import InvalidRequestError, UserConflictError, UserProvisioner
from tests.conftest import make_settings


@pytest.fixture
def directory() -> MemoryDirectory:
    return MemoryDirectory()


@pytest.fixture
def provisioner(directory, settings) -> UserProvisioner:
    return UserProvisioner(directory, settings)


def test_creates_user_with_derived_login_and_compliant_password(provisioner, directory):
    user = provisioner.create_user("Marie", "Dupont", "Marie.Dupont@Exemple.be", "M004217")

    assert user.login == "mardup"
    assert user.upn == "mardup@exemple.be"
    assert user.display_name == "Marie Dupont"
    assert user.mail == "marie.dupont@exemple.be"
    assert user.matricule == "M004217"
    assert len(user.temporary_password) == 10
    assert is_compliant(user.temporary_password, {"mardup", "marie", "dupont"})
    assert directory.users[user.dn].login == "mardup"


def test_password_is_absent_from_repr(provisioner):
    user = provisioner.create_user("Marie", "Dupont", "marie.dupont@exemple.be", "M1")
    assert user.temporary_password not in repr(user)


def test_homonyms_get_a_numbered_login_and_a_distinct_dn(provisioner):
    first = provisioner.create_user("Marie", "Dupont", "marie.dupont@exemple.be", "M1")
    second = provisioner.create_user("Marie", "Dupont", "marie.dupont2@exemple.be", "M2")
    third = provisioner.create_user("Marc", "Dupuis", "marc.dupuis@exemple.be", "M3")

    assert [first.login, second.login, third.login] == ["mardup", "mardup2", "mardup3"]
    assert second.upn == "mardup2@exemple.be"
    assert len({first.dn, second.dn, third.dn}) == 3


def test_duplicate_matricule_is_rejected(provisioner, directory):
    provisioner.create_user("Marie", "Dupont", "marie.dupont@exemple.be", "M1")
    with pytest.raises(UserConflictError) as error:
        provisioner.create_user("Paul", "Martin", "paul.martin@exemple.be", "m1")
    assert error.value.code == "matricule_deja_utilise"
    assert len(directory.users) == 1


def test_duplicate_mail_is_rejected(provisioner):
    provisioner.create_user("Marie", "Dupont", "marie.dupont@exemple.be", "M1")
    with pytest.raises(UserConflictError) as error:
        provisioner.create_user("Paul", "Martin", "MARIE.DUPONT@exemple.be", "M2")
    assert error.value.code == "mail_deja_utilise"


@pytest.mark.parametrize("matricule", ["", "avec espace", "trop-long-0123456789", "é123", "-12"])
def test_invalid_matricule_is_rejected(provisioner, matricule):
    with pytest.raises(InvalidRequestError) as error:
        provisioner.create_user("Marie", "Dupont", "marie.dupont@exemple.be", matricule)
    assert error.value.code == "matricule_invalide"


def test_mail_domain_allowlist(directory):
    provisioner = UserProvisioner(directory, make_settings(mail_allowed_domains="exemple.be"))
    provisioner.create_user("Marie", "Dupont", "marie.dupont@EXEMPLE.be", "M1")
    with pytest.raises(InvalidRequestError) as error:
        provisioner.create_user("Paul", "Martin", "paul.martin@ailleurs.com", "M2")
    assert error.value.code == "domaine_mail_refuse"


def test_name_without_latin_letters_is_rejected(provisioner):
    with pytest.raises(InvalidRequestError) as error:
        provisioner.create_user("李", "王", "li.wang@exemple.be", "M1")
    assert error.value.code == "login_non_derivable"


def test_configured_password_length_is_applied(directory):
    provisioner = UserProvisioner(directory, make_settings(password_length=14))
    user = provisioner.create_user("Marie", "Dupont", "marie.dupont@exemple.be", "M1")
    assert len(user.temporary_password) == 14


def test_concurrent_creation_is_reported_as_conflict(settings):
    class RacingDirectory(MemoryDirectory):
        @contextmanager
        def session(self):
            yield self

        def create_user(self, user, password):
            raise EntryConflictError(user.login)

    with pytest.raises(UserConflictError) as error:
        UserProvisioner(RacingDirectory(), settings).create_user(
            "Marie", "Dupont", "marie.dupont@exemple.be", "M1"
        )
    assert error.value.code == "creation_concurrente"
