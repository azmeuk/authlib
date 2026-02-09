"""authlib.oidc.core.grants.code.
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implementation of Authentication using the Authorization Code Flow
per `Section 3.1`_.

.. _`Section 3.1`: https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
"""

import logging
import time
import warnings

from joserfc import jwt

from authlib._joserfc_helpers import import_any_key
from authlib.oauth2.rfc6749 import OAuth2Request

from ..models import AuthorizationCodeMixin
from .util import create_half_hash
from .util import is_openid_scope
from .util import validate_nonce
from .util import validate_request_prompt

log = logging.getLogger(__name__)


class OpenIDToken:
    DEFAULT_EXPIRES_IN = 3600

    def resolve_client_private_key(self, client):
        """Resolve the client private key for encoding ``id_token`` Developers
        MUST implement this method in subclass, e.g.::

            import json
            from joserfc.jwk import KeySet


            def resolve_client_private_key(self, client):
                with open(jwks_file_path) as f:
                    data = json.load(f)
                return KeySet.import_key_set(data)
        """
        config = self._compatible_resolve_jwt_config(None, client)
        return config["key"]

    def get_client_algorithm(self, client):
        """Return the algorithm for encoding ``id_token``. By default, it will
        use ``client.id_token_signed_response_alg``, if not defined, ``RS256``
        will be used. But you can override this method to customize the returned
        algorithm.
        """
        # Per OpenID Connect Registration 1.0 Section 2:
        # Use client's id_token_signed_response_alg if specified
        config = self._compatible_resolve_jwt_config(None, client)
        alg = config.get("alg")
        if alg:
            return alg

        if hasattr(client, "id_token_signed_response_alg"):
            return client.id_token_signed_response_alg or "RS256"
        return "RS256"

    def get_client_claims(self, client):
        """Return the default client claims for encoding the ``id_token``. Developers
        MUST implement this method in subclass, e.g.::

            def get_client_claims(self, client):
                return {
                    "iss": "your-service-url",
                    "aud": [client.get_client_id()],
                }
        """
        config = self._compatible_resolve_jwt_config(None, client)
        claims = {k: config[k] for k in config if k not in ["key", "alg"]}
        if "exp" in config:
            now = int(time.time())
            claims["exp"] = now + config["exp"]
        return claims

    def get_authorization_code_claims(self, authorization_code: AuthorizationCodeMixin):
        claims = {
            "nonce": authorization_code.get_nonce(),
            "auth_time": authorization_code.get_auth_time(),
        }

        if acr := authorization_code.get_acr():
            claims["acr"] = acr

        if amr := authorization_code.get_amr():
            claims["amr"] = amr
        return claims

    def get_encode_header(self, client):
        config = self._compatible_resolve_jwt_config(None, client)
        kid = config.get("kid")
        header = {"alg": self.get_client_algorithm(client)}
        if kid:
            header["kid"] = kid
        return header

    def generate_user_info(self, user, scope):
        """Provide user information for the given scope. Developers
        MUST implement this method in subclass, e.g.::

            from authlib.oidc.core import UserInfo


            def generate_user_info(self, user, scope):
                user_info = UserInfo(sub=user.id, name=user.name)
                if "email" in scope:
                    user_info["email"] = user.email
                return user_info

        :param user: user instance
        :param scope: scope of the token
        :return: ``authlib.oidc.core.UserInfo`` instance
        """
        raise NotImplementedError()

    def _compatible_resolve_jwt_config(self, grant, client):
        if not hasattr(self, "get_jwt_config"):
            return {}

        warnings.warn(
            "get_jwt_config(self, grant) is deprecated and will be removed in version 1.8. "
            "Use resolve_client_private_key, get_client_claims, get_client_algorithm instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        try:
            config = self.get_jwt_config(grant, client)
        except TypeError:
            config = self.get_jwt_config(grant)
        return config

    def encode_id_token(self, token, request: OAuth2Request):
        alg = self.get_client_algorithm(request.client)
        header = self.get_encode_header(request.client)

        now = int(time.time())

        claims = self.get_client_claims(request.client)
        claims.setdefault("iat", now)
        claims.setdefault("exp", now + self.DEFAULT_EXPIRES_IN)
        claims.setdefault("auth_time", now)

        # compatible code
        if "aud" not in claims and hasattr(self, "get_audiences"):
            warnings.warn(
                "get_audiences(self, request) is deprecated and will be removed in version 1.8. "
                "You can set the ``aud`` value in get_client_claims instead.",
                DeprecationWarning,
                stacklevel=2,
            )
            claims["aud"] = self.get_audiences(request)

        claims.setdefault("aud", [request.client.get_client_id()])
        if request.authorization_code:
            claims.update(
                self.get_authorization_code_claims(request.authorization_code)
            )

        access_token = token.get("access_token")
        if access_token:
            at_hash = create_half_hash(access_token, alg)
            if at_hash is not None:
                claims["at_hash"] = at_hash.decode("utf-8")

        user_info = self.generate_user_info(request.user, token["scope"])
        claims.update(user_info)

        if alg == "none":
            private_key = None
        else:
            key = self.resolve_client_private_key(request.client)
            private_key = import_any_key(key)

        return jwt.encode(header, claims, private_key, [alg])

    def process_token(self, grant, response):
        _, token, _ = response
        scope = token.get("scope")
        if not scope or not is_openid_scope(scope):
            # standard authorization code flow
            return token

        request: OAuth2Request = grant.request
        id_token = self.encode_id_token(token, request)
        token["id_token"] = id_token
        return token

    def __call__(self, grant):
        grant.register_hook("after_create_token_response", self.process_token)


class OpenIDCode(OpenIDToken):
    """An extension from OpenID Connect for "grant_type=code" request. Developers
    MUST implement the missing methods::

        class MyOpenIDCode(OpenIDCode):
            def get_jwt_config(self, grant):
                return {...}

            def exists_nonce(self, nonce, request):
                return check_if_nonce_in_cache(request.payload.client_id, nonce)

            def generate_user_info(self, user, scope):
                return {...}

    The register this extension with AuthorizationCodeGrant::

        authorization_server.register_grant(
            AuthorizationCodeGrant, extensions=[MyOpenIDCode()]
        )
    """

    def __init__(self, require_nonce=False):
        self.require_nonce = require_nonce

    def exists_nonce(self, nonce, request):
        """Check if the given nonce is existing in your database. Developers
        MUST implement this method in subclass, e.g.::

            def exists_nonce(self, nonce, request):
                exists = AuthorizationCode.query.filter_by(
                    client_id=request.payload.client_id, nonce=nonce
                ).first()
                return bool(exists)

        :param nonce: A string of "nonce" parameter in request
        :param request: OAuth2Request instance
        :return: Boolean
        """
        raise NotImplementedError()

    def validate_openid_authorization_request(self, grant, redirect_uri):
        validate_nonce(grant.request, self.exists_nonce, self.require_nonce)

    def __call__(self, grant):
        grant.register_hook("after_create_token_response", self.process_token)
        if is_openid_scope(grant.request.payload.scope):
            grant.register_hook(
                "after_validate_authorization_request_payload",
                self.validate_openid_authorization_request,
            )
            grant.register_hook(
                "after_validate_consent_request", validate_request_prompt
            )
