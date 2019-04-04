import json
import logging
from typing import Dict, Optional

import jwt
from django.contrib.sites.models import Site
from django.urls import reverse
from django.utils.functional import cached_property
from jwt.algorithms import RSAAlgorithm
from requests_oauthlib import OAuth2Session
from mypy_extensions import TypedDict

from .utils import get_scheme

logger = logging.getLogger("django")

MicrosoftTokensResponse = TypedDict("MicrosoftTokensResponse", {
    "token_type": str,
    "scope": str,
    "expires_in": int,
    "ext_expires_in": int,
    "access_token": str,
    "refresh_token": str,
    "id_token": str
})

class MicrosoftClient(OAuth2Session):
    """
    Simple Microsoft OAuth2 Client to authenticate them

    Extended from Requests-OAuthlib's OAuth2Session class which
        does most of the heavy lifting

    https://requests-oauthlib.readthedocs.io/en/latest/

    Microsoft OAuth documentation can be found at
    https://developer.microsoft.com/en-us/graph/docs/get-started/rest
    """
    _config_url = "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"  # noqa
    config = None

    # required OAuth scopes (does not include offline_access)
    SCOPE_MICROSOFT = ["openid", "email", "profile"]

    def __init__(self, state=None, request=None, *args, **kwargs):
        from .conf import config

        self.config = config

        extra_scopes = self.config.MICROSOFT_AUTH_EXTRA_SCOPES

        try:
            current_site = Site.objects.get_current(request)
        except Site.DoesNotExist:
            current_site = Site.objects.first()

        domain = current_site.domain
        path = reverse("microsoft_auth:auth-callback")
        scope = " ".join(self.SCOPE_MICROSOFT)
        scope = "{} {}".format(scope, extra_scopes).strip()  # adds offline_access scope
        scheme = get_scheme(request, self.config)

        super().__init__(
            self.config.MICROSOFT_AUTH_CLIENT_ID,
            scope=scope,
            state=state,
            redirect_uri="{0}://{1}{2}".format(scheme, domain, path),
            *args,
            **kwargs
        )

    @cached_property
    def openid_config(self):
        """
        Property which holds Azure's OpenID server metadata received by the
        OpenID Connect Discovery mechanism.
        """
        config_url = self._config_url.format(
            tenant=self.config.MICROSOFT_AUTH_TENANT_ID
        )
        response = self.get(config_url)

        if response.ok:
            return response.json()

        return None

    @cached_property
    def jwks(self):
        response = self.get(self.openid_config["jwks_uri"])

        if response.ok:
            return response.json()["keys"]
        return []

    def get_token_claims(self, token_type: str) -> Optional[Dict]:
        """
        Validates and gets all claims of a given token type.

        :param token_type: string of token type: "access_token", "id_token" or "refresh_token".
        :return Dict with all the tokem clains or None.
        """
        if self.token is None:
            return None

        token = self.token[token_type].encode("utf8")
        kid = jwt.get_unverified_header(token)["kid"]

        for key in self.jwks:
            if kid == key["kid"]:
                jwk = key
                break

        if jwk is None:
            logger.warning("could not find public key for id_token")
            return None

        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))

        try:
            claims = jwt.decode(
                token,
                public_key,
                algoithm="RS256",
                audience=self.config.MICROSOFT_AUTH_CLIENT_ID,
            )
        except jwt.PyJWTError as e:
            logger.warning("could verify token signature: {}".format(e))
            return None

        return claims

    def authorization_url(self) -> str:
        """ Generates Microsoft Authorization URL """
        auth_url = self.openid_config["authorization_endpoint"]

        return super().authorization_url(auth_url, response_mode="form_post")

    def fetch_tokens(self, **kwargs) -> MicrosoftTokensResponse:
        """ Fetchs OAuth2 Tokens from Microsoft with given kwargs and assign to token property. """
        ms_tokens_response = super().fetch_token(  # pragma: no cover
            self.openid_config["token_endpoint"],  # from login.microsoft link, gets oauth token_endpoint
            client_secret=self.config.MICROSOFT_AUTH_CLIENT_SECRET,  # application secret to get tokens from
            **kwargs
        )

        return ms_tokens_response

    def has_fetched_tokens_the_appropriate_scopes(self, scopes) -> bool:
        """
        Validates Microsoft's OAuth2 server token response scopes based on MICROSOFT_AUTH_LOGIN_TYPE.
        """
        scopes = set(scopes)
        required_scopes = set(self.SCOPE_MICROSOFT)

        return required_scopes <= scopes
