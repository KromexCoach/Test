import pytest

from iam_ad import password as pw
from iam_ad.password import forbidden_fragments, generate_password, is_compliant


def test_generated_passwords_are_ten_characters_with_all_classes():
    for _ in range(500):
        password = generate_password()
        assert len(password) == 10
        assert any(char in pw.UPPERCASE for char in password)
        assert any(char in pw.LOWERCASE for char in password)
        assert any(char in pw.DIGITS for char in password)
        assert any(char in pw.SYMBOLS for char in password)
        assert not set(password) & set("O0Il1")


def test_generated_passwords_are_unique():
    assert len({generate_password() for _ in range(1000)}) == 1000


def test_generation_uses_the_system_csprng():
    import secrets

    assert isinstance(pw._rng, secrets.SystemRandom)


def test_length_is_configurable_but_never_below_ten():
    assert len(generate_password(16)) == 16
    with pytest.raises(ValueError):
        generate_password(9)


def test_forbidden_fragments_cover_login_and_name_tokens():
    fragments = forbidden_fragments("mardup", "Marie-Hélène", "D'Hondt")
    assert {"mardup", "marie", "hélène", "helene", "hondt"} <= fragments
    assert "d" not in fragments  # trop court pour être significatif


@pytest.mark.parametrize(
    ("password", "forbidden", "expected"),
    [
        ("Ab3!efghJK", (), True),
        ("Ab3!efghJ", (), False),  # 9 caractères
        ("ab3!efghjk", (), False),  # pas de majuscule
        ("AB3!EFGHJK", (), False),  # pas de minuscule
        ("Abc!efghJK", (), False),  # pas de chiffre
        ("Ab3defghJK", (), False),  # pas de symbole
        ("Ab3!eeehJK", (), False),  # trois caractères identiques à la suite
        ("Ab3!MaRiEx", ("marie",), False),  # contient le prénom
        ("Ab3!efgh K", (), False),  # caractère hors alphabet
    ],
)
def test_is_compliant(password, forbidden, expected):
    assert is_compliant(password, forbidden) is expected


def test_generated_password_never_contains_forbidden_fragment(monkeypatch):
    # Un alphabet minuscule réduit rend la collision fréquente : le tirage doit recommencer.
    monkeypatch.setattr(pw, "LOWERCASE", "ab")
    monkeypatch.setattr(pw, "_CLASSES", (pw.UPPERCASE, "ab", pw.DIGITS, pw.SYMBOLS))
    for _ in range(300):
        assert "ab" not in generate_password(forbidden={"ab"}).casefold()
