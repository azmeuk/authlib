"""Support for OAuth 2.0 Protected Resource Metadata .well-known url"""

from authlib.common.urls import urlparse


def get_well_known_url(
    resource_identifier, external=False, suffix="oauth-protected-resource"
):
    """Get well-known URI from a resource identifier via :rfc:`9728#section-3.1`."""
    parsed = urlparse.urlparse(resource_identifier)
    path = parsed.path
    if path and path != "/":
        url_path = f"/.well-known/{suffix}{path}"
    else:
        url_path = f"/.well-known/{suffix}"
    if not external:
        return url_path
    return parsed.scheme + "://" + parsed.netloc + url_path
