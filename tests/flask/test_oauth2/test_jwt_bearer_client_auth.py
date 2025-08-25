import pytest
from flask import json

from authlib.oauth2.rfc6749.grants import ClientCredentialsGrant
from authlib.oauth2.rfc7523 import JWTBearerClientAssertion
from authlib.oauth2.rfc7523 import client_secret_jwt_sign
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from tests.util import read_file_path

from .models import Client
from .models import User
from .oauth2_server import create_authorization_server


@pytest.fixture(autouse=True)
def server(app):
    class JWTClientCredentialsGrant(ClientCredentialsGrant):
        TOKEN_ENDPOINT_AUTH_METHODS = [
            JWTBearerClientAssertion.CLIENT_AUTH_METHOD,
        ]

    server = create_authorization_server(app)
    server.register_grant(JWTClientCredentialsGrant)
    return server


@pytest.fixture(autouse=True)
def user(db):
    user = User(username="foo")
    db.session.add(user)
    db.session.commit()
    yield user
    db.session.delete(user)


@pytest.fixture(autouse=True)
def client(db, user):
    client = Client(
        user_id=user.id,
        client_id="credential-client",
        client_secret="credential-secret",
    )
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["http://localhost/authorized"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": JWTBearerClientAssertion.CLIENT_AUTH_METHOD,
        }
    )
    db.session.add(client)
    db.session.commit()
    yield client
    db.session.delete(client)


def register_jwt_client_auth(server, validate_jti=True):
    class JWTClientAuth(JWTBearerClientAssertion):
        def validate_jti(self, claims, jti):
            return True

        def resolve_client_public_key(self, client, headers):
            if headers["alg"] == "RS256":
                return read_file_path("jwk_public.json")
            return client.client_secret

    server.register_client_auth_method(
        JWTClientAuth.CLIENT_AUTH_METHOD,
        JWTClientAuth("https://localhost/oauth/token", validate_jti),
    )


def test_invalid_client(test_client, server):
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_invalid_jwt(test_client, server):
    register_jwt_client_auth(server)

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="invalid-secret",
                client_id="credential-client",
                token_endpoint="https://localhost/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_not_found_client(test_client, server):
    register_jwt_client_auth(server)

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="credential-secret",
                client_id="invalid-client",
                token_endpoint="https://localhost/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_not_supported_auth_method(test_client, server, client, db):
    register_jwt_client_auth(server)
    client.set_client_metadata(
        {
            "scope": "profile",
            "redirect_uris": ["http://localhost/authorized"],
            "grant_types": ["client_credentials"],
            "token_endpoint_auth_method": "invalid",
        }
    )
    db.session.add(client)
    db.session.commit()
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="credential-secret",
                client_id="credential-client",
                token_endpoint="https://localhost/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert resp["error"] == "invalid_client"


def test_client_secret_jwt(test_client, server):
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="credential-secret",
                client_id="credential-client",
                token_endpoint="https://localhost/oauth/token",
                claims={"jti": "nonce"},
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_private_key_jwt(test_client, server):
    register_jwt_client_auth(server)
    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": private_key_jwt_sign(
                private_key=read_file_path("jwk_private.json"),
                client_id="credential-client",
                token_endpoint="https://localhost/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp


def test_not_validate_jti(test_client, server):
    register_jwt_client_auth(server, validate_jti=False)

    rv = test_client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_assertion_type": JWTBearerClientAssertion.CLIENT_ASSERTION_TYPE,
            "client_assertion": client_secret_jwt_sign(
                client_secret="credential-secret",
                client_id="credential-client",
                token_endpoint="https://localhost/oauth/token",
            ),
        },
    )
    resp = json.loads(rv.data)
    assert "access_token" in resp
