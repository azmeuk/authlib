import os

import pytest
from flask import Flask


@pytest.fixture(autouse=True)
def env():
    os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"
    yield
    del os.environ["AUTHLIB_INSECURE_TRANSPORT"]


@pytest.fixture
def app():
    app = Flask(__name__)
    app.debug = True
    app.testing = True
    app.secret_key = "testing"
    app.config.update(
        {
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
            "SQLALCHEMY_DATABASE_URI": "sqlite://",
            "OAUTH2_ERROR_URIS": [("invalid_client", "https://a.b/e#invalid_client")],
        }
    )
    with app.app_context():
        yield app


@pytest.fixture
def db(app):
    from .models import db

    db.init_app(app)
    db.create_all()
    yield db
    db.drop_all()


@pytest.fixture
def test_client(app):
    return app.test_client()
