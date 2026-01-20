"""Tests for RP-Initiated Logout endpoint."""

import pytest
from joserfc import jwt
from joserfc.jwk import KeySet

from authlib.oauth2.rfc6749.errors import OAuth2Error
from authlib.oidc.rpinitiated import EndSessionEndpoint
from authlib.oidc.rpinitiated import EndSessionRequest
from tests.util import read_file_path

from .models import Client
from .models import db


def create_id_token(claims):
    """Create a signed ID token for testing."""
    header = {"alg": "RS256"}
    jwks = read_file_path("jwks_private.json")
    key = KeySet.import_key_set(jwks)
    return jwt.encode(header, claims, key)


class MyEndSessionEndpoint(EndSessionEndpoint):
    """Test endpoint implementation."""

    def get_server_jwks(self):
        return read_file_path("jwks_public.json")

    def get_client_by_id(self, client_id):
        return db.session.query(Client).filter_by(client_id=client_id).first()

    def is_post_logout_redirect_uri_legitimate(
        self, request, post_logout_redirect_uri, client, logout_hint
    ):
        # Allow redirect without id_token_hint for testing
        return True

    def end_session(self, end_session_request):
        pass


@pytest.fixture
def endpoint_server(server, app):
    """Server with EndSessionEndpoint registered."""
    endpoint = MyEndSessionEndpoint()
    server.register_endpoint(endpoint)

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        # Non-interactive mode: validate and respond in one step
        return server.create_endpoint_response("end_session") or "Logged out"

    @app.route("/logout_interactive", methods=["GET", "POST"])
    def logout_interactive():
        # Interactive mode: validate, check confirmation, then respond
        from flask import request

        try:
            req = server.validate_endpoint_request("end_session")
        except OAuth2Error as error:
            return server.handle_error_response(None, error)

        if req.needs_confirmation and request.method == "GET":
            return "Confirm logout", 200

        return server.create_endpoint_response("end_session", req) or "Logged out"

    return server


@pytest.fixture
def client_model(user, db):
    """Create a test client."""
    client = Client(
        user_id=user.id,
        client_id="client-id",
        client_secret="client-secret",
    )
    client.set_client_metadata(
        {
            "redirect_uris": ["https://client.test/callback"],
            "post_logout_redirect_uris": [
                "https://client.test/logout",
                "https://client.test/logged-out",
            ],
        }
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


@pytest.fixture
def valid_id_token():
    """Create a valid ID token."""
    return create_id_token(
        {
            "iss": "https://provider.test",
            "sub": "user-1",
            "aud": "client-id",
            "exp": 9999999999,
            "iat": 1000000000,
        }
    )


# --- EndSessionRequest tests ---


class TestEndSessionRequest:
    def test_needs_confirmation_without_id_token(self):
        """needs_confirmation is True when id_token_claims is None."""
        req = EndSessionRequest(request=None, client=None, id_token_claims=None)
        assert req.needs_confirmation is True

    def test_needs_confirmation_with_id_token(self):
        """needs_confirmation is False when id_token_claims is present."""
        req = EndSessionRequest(
            request=None, client=None, id_token_claims={"sub": "user-1"}
        )
        assert req.needs_confirmation is False


# --- Non-interactive mode tests ---


class TestNonInteractiveMode:
    def test_logout_with_valid_id_token(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """Logout with valid id_token_hint succeeds."""
        rv = test_client.get(f"/logout?id_token_hint={valid_id_token}")

        assert rv.status_code == 200
        assert rv.data == b"Logged out"

    def test_logout_with_redirect_uri(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """Logout with valid redirect URI redirects."""
        rv = test_client.get(
            f"/logout?id_token_hint={valid_id_token}"
            "&post_logout_redirect_uri=https://client.test/logout"
        )

        assert rv.status_code == 302
        assert rv.headers["Location"] == "https://client.test/logout"

    def test_logout_with_redirect_uri_and_state(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """State parameter is appended to redirect URI."""
        rv = test_client.get(
            f"/logout?id_token_hint={valid_id_token}"
            "&post_logout_redirect_uri=https://client.test/logout"
            "&state=xyz123"
        )

        assert rv.status_code == 302
        assert rv.headers["Location"] == "https://client.test/logout?state=xyz123"

    def test_logout_without_id_token(self, test_client, endpoint_server, client_model):
        """Logout without id_token_hint succeeds in non-interactive mode."""
        rv = test_client.get("/logout")

        assert rv.status_code == 200
        assert rv.data == b"Logged out"

    def test_invalid_redirect_uri_ignored(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """Unregistered redirect URI results in no redirect."""
        rv = test_client.get(
            f"/logout?id_token_hint={valid_id_token}"
            "&post_logout_redirect_uri=https://attacker.test/logout"
        )

        assert rv.status_code == 200
        assert rv.data == b"Logged out"

    def test_post_with_form_data(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """POST with form-encoded data works."""
        rv = test_client.post(
            "/logout",
            data={
                "id_token_hint": valid_id_token,
                "post_logout_redirect_uri": "https://client.test/logout",
                "state": "abc",
            },
        )

        assert rv.status_code == 302
        assert rv.headers["Location"] == "https://client.test/logout?state=abc"


# --- Interactive mode tests ---


class TestInteractiveMode:
    def test_confirmation_shown_without_id_token(
        self, test_client, endpoint_server, client_model
    ):
        """Without id_token_hint, confirmation page is shown on GET."""
        rv = test_client.get("/logout_interactive")

        assert rv.status_code == 200
        assert rv.data == b"Confirm logout"

    def test_confirmation_bypassed_with_id_token(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """With valid id_token_hint, no confirmation needed."""
        rv = test_client.get(f"/logout_interactive?id_token_hint={valid_id_token}")

        assert rv.status_code == 200
        assert rv.data == b"Logged out"

    def test_post_executes_logout(self, test_client, endpoint_server, client_model):
        """POST request executes logout even without id_token_hint."""
        rv = test_client.post("/logout_interactive")

        assert rv.status_code == 200
        assert rv.data == b"Logged out"

    def test_redirect_preserved_after_confirmation(
        self, test_client, endpoint_server, client_model
    ):
        """Redirect URI is used after POST confirmation."""
        rv = test_client.post(
            "/logout_interactive",
            data={
                "client_id": "client-id",
                "post_logout_redirect_uri": "https://client.test/logout",
            },
        )

        assert rv.status_code == 302
        assert rv.headers["Location"] == "https://client.test/logout"


# --- Validation tests ---


class TestValidation:
    def test_client_id_mismatch_error(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """client_id not matching aud claim returns error."""
        rv = test_client.get(
            f"/logout?id_token_hint={valid_id_token}&client_id=other-client"
        )

        assert rv.status_code == 400
        assert rv.json["error"] == "invalid_request"
        assert "'client_id' does not match 'aud' claim" in rv.json["error_description"]

    def test_invalid_jwt_error(self, test_client, endpoint_server, client_model):
        """Invalid JWT returns error."""
        rv = test_client.get("/logout?id_token_hint=invalid.jwt.token")

        assert rv.status_code == 400
        assert rv.json["error"] == "invalid_request"

    def test_client_id_matches_aud_list(
        self, test_client, endpoint_server, client_model
    ):
        """client_id matches when aud is a list containing it."""
        id_token = create_id_token(
            {
                "iss": "https://provider.test",
                "sub": "user-1",
                "aud": ["client-id", "other-client"],
                "exp": 9999999999,
                "iat": 1000000000,
            }
        )
        rv = test_client.get(f"/logout?id_token_hint={id_token}&client_id=client-id")

        assert rv.status_code == 200

    def test_client_id_not_in_aud_list_error(
        self, test_client, endpoint_server, client_model
    ):
        """client_id not in aud list returns error."""
        id_token = create_id_token(
            {
                "iss": "https://provider.test",
                "sub": "user-1",
                "aud": ["other-client-1", "other-client-2"],
                "exp": 9999999999,
                "iat": 1000000000,
            }
        )
        rv = test_client.get(f"/logout?id_token_hint={id_token}&client_id=client-id")

        assert rv.status_code == 400
        assert rv.json["error"] == "invalid_request"


# --- Token expiration tests ---


class TestTokenExpiration:
    def test_expired_id_token_accepted(
        self, test_client, endpoint_server, client_model
    ):
        """Expired ID tokens are accepted per the specification."""
        expired_token = create_id_token(
            {
                "iss": "https://provider.test",
                "sub": "user-1",
                "aud": "client-id",
                "exp": 1,  # Expired in 1970
                "iat": 0,
            }
        )
        rv = test_client.get(f"/logout?id_token_hint={expired_token}")

        assert rv.status_code == 200
        assert rv.data == b"Logged out"

    def test_token_with_future_nbf_rejected(
        self, test_client, endpoint_server, client_model
    ):
        """Token with nbf in the future is rejected."""
        token = create_id_token(
            {
                "iss": "https://provider.test",
                "sub": "user-1",
                "aud": "client-id",
                "exp": 9999999999,
                "iat": 0,
                "nbf": 9999999999,  # Not valid until far future
            }
        )
        rv = test_client.get(f"/logout?id_token_hint={token}")

        assert rv.status_code == 400
        assert rv.json["error"] == "invalid_request"


# --- Client resolution tests ---


class TestClientResolution:
    def test_client_resolved_from_single_aud(
        self, test_client, endpoint_server, client_model, valid_id_token
    ):
        """Client is resolved from single aud claim."""
        rv = test_client.get(
            f"/logout?id_token_hint={valid_id_token}"
            "&post_logout_redirect_uri=https://client.test/logout"
        )

        assert rv.status_code == 302
        assert rv.headers["Location"] == "https://client.test/logout"

    def test_client_not_resolved_from_aud_list(
        self, test_client, endpoint_server, client_model
    ):
        """Client is not resolved from aud list (ambiguous)."""
        id_token = create_id_token(
            {
                "iss": "https://provider.test",
                "sub": "user-1",
                "aud": ["client-id", "other-client"],
                "exp": 9999999999,
                "iat": 1000000000,
            }
        )
        # Without client_id, client resolution fails, so redirect_uri is not used
        rv = test_client.get(
            f"/logout?id_token_hint={id_token}"
            "&post_logout_redirect_uri=https://client.test/logout"
        )

        assert rv.status_code == 200
        assert rv.data == b"Logged out"  # No redirect

    def test_client_resolved_with_explicit_client_id(
        self, test_client, endpoint_server, client_model
    ):
        """Client is resolved when client_id is provided explicitly."""
        id_token = create_id_token(
            {
                "iss": "https://provider.test",
                "sub": "user-1",
                "aud": ["client-id", "other-client"],
                "exp": 9999999999,
                "iat": 1000000000,
            }
        )
        rv = test_client.get(
            f"/logout?id_token_hint={id_token}"
            "&client_id=client-id"
            "&post_logout_redirect_uri=https://client.test/logout"
        )

        assert rv.status_code == 302
        assert rv.headers["Location"] == "https://client.test/logout"

    def test_redirect_requires_client(self, test_client, endpoint_server, client_model):
        """Redirect URI without resolvable client is ignored."""
        rv = test_client.get(
            "/logout?post_logout_redirect_uri=https://client.test/logout"
        )

        assert rv.status_code == 200
        assert rv.data == b"Logged out"  # No redirect
