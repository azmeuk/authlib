import pytest

from authlib.common.urls import is_valid_url


@pytest.mark.parametrize(
    "url",
    [
        "https://provider.test/cb",
        "https://provider.test:8443/cb",
        "http://provider.test/cb",
        "http://localhost:8080/cb",
        "https://provider.test/cb?next=user@provider.test",
        "https://provider.test/cb#fragment",
    ],
)
def test_valid_url(url):
    assert is_valid_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "",
        "provider.test/cb",
        "https://",
        "/cb",
        "urn:ietf:wg:oauth:2.0:oob",
    ],
)
def test_invalid_url(url):
    assert is_valid_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "https://user:pass@provider.test/cb",
        "https://user@provider.test/cb",
        "https://@provider.test/cb",
        "https://provider.test@attacker.test/cb",
        "http://localhost:80@attacker.test/cb",
    ],
)
def test_userinfo_is_rejected(url):
    assert is_valid_url(url) is False


@pytest.mark.parametrize(
    "url",
    [
        "http://[::1]:80@attacker.test/cb",
        "http://[not-an-ip]/cb",
    ],
)
def test_unparsable_authority(url):
    """urlparse() raises ValueError on these, it must not propagate."""
    assert is_valid_url(url) is False


def test_fragments_not_allowed():
    assert is_valid_url("https://provider.test/cb", fragments_allowed=False) is True
    assert (
        is_valid_url("https://provider.test/cb#fragment", fragments_allowed=False)
        is False
    )
