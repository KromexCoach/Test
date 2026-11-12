import pytest

from iam_ad.login import LoginError, ascii_letters, build_login, login_candidates


@pytest.mark.parametrize(
    ("first_name", "last_name", "expected"),
    [
        ("Marie", "Dupont", "mardup"),
        ("Éloïse", "Lefèvre", "elolef"),
        ("Jean-Pierre", "D'Hondt", "jeadho"),
        ("Jan", "Van Damme", "janvan"),
        ("Li", "Wu", "liwu"),
        ("Søren", "Œuvrard", "soroeu"),
        ("  ANNE  ", "de la Tour", "anndel"),
        ("Zoë", "Ñandú", "zoenan"),
    ],
)
def test_build_login(first_name, last_name, expected):
    assert build_login(first_name, last_name) == expected


def test_build_login_respects_configured_lengths():
    assert build_login("Marie", "Dupont", first_letters=1, last_letters=5) == "mdupon"


@pytest.mark.parametrize(
    ("first_name", "last_name"), [("李", "Dupont"), ("Marie", "---"), ("", "")]
)
def test_build_login_rejects_names_without_latin_letters(first_name, last_name):
    with pytest.raises(LoginError):
        build_login(first_name, last_name)


def test_ascii_letters_keeps_only_a_to_z():
    assert ascii_letters("Straße 12, Ætna!") == "strasseaetna"


def test_login_candidates_number_homonyms_within_sam_limit():
    candidates = list(login_candidates("mardup"))
    assert candidates[:3] == ["mardup", "mardup2", "mardup3"]
    assert candidates[-1] == "mardup99"
    long_candidates = list(login_candidates("a" * 20))
    assert all(len(candidate) <= 20 for candidate in long_candidates)
    assert len(set(long_candidates)) == len(long_candidates)
