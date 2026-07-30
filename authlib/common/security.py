import ipaddress
import os
import random
import string
from urllib.parse import urlsplit

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits


def generate_token(length=30, chars=UNICODE_ASCII_CHARACTER_SET):
    rand = random.SystemRandom()
    return "".join(rand.choice(chars) for _ in range(length))


def is_secure_transport(uri):
    """Check if the uri is over ssl."""
    if os.getenv("AUTHLIB_INSECURE_TRANSPORT"):
        return True

    try:
        parts = urlsplit(uri)
    except ValueError:
        return False

    if not parts.hostname:
        return False

    if parts.scheme == "https":
        return True

    if parts.scheme != "http":
        return False

    # rfc8252 §7.3: native apps may use http for loopback redirection URIs.
    if parts.hostname == "localhost":
        return True

    try:
        return ipaddress.ip_address(parts.hostname).is_loopback
    except ValueError:
        return False
