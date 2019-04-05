import json
import logging
from typing import Any, Dict, Optional

import jwt
from django.contrib.sites.models import Site
from django.urls import reverse
from django.utils.functional import cached_property
from jwt.algorithms import RSAAlgorithm
from mypy_extensions import TypedDict
from requests_oauthlib import OAuth2Session

from .utils import get_scheme

logger = logging.getLogger("django")

MicrosoftTokensResponse = TypedDict(
    "MicrosoftTokensResponse",
    {
        "token_type": str,
        "scope": str,
        "expires_in": int,
        "ext_expires_in": int,
        "access_token": str,
        "refresh_token": str,
        "id_token": str,
    },
)


class AzureOAuth2Session(OAuth2Session):
    """
    Azure OAuth2 Client to authenticate and get OAuth2 tokens on the user behalf by using the authorization grant flow.
    """

    _openid_discovery_url = "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"  # noqa

    SCOPE_MICROSOFT = ["openid", "email", "profile"]
    SCOPE_MICROSOFT_EXTRA = [
        "offline_access"
    ]  # does not come from microsoft token

    def __init__(self, state=None, request=None, *args, **kwargs):
        # variables for OAuth2 authorization URI
        redirect_uri = self._build_redirect_uri(request)
        scope = " ".join(self.SCOPE_MICROSOFT + self.SCOPE_MICROSOFT_EXTRA)

        # OAuth2Session class initialization
        super().__init__(
            client_id=self.config.MICROSOFT_AUTH_CLIENT_ID,
            scope=scope,
            state=state,
            redirect_uri=redirect_uri,
            *args,
            **kwargs,
        )

    def _build_redirect_uri(self, request) -> str:
        """
        Builds an authorization redirect uri for the OAuth2 authorization code flow.
        """
        current_site = Site.objects.get_current(request)
        domain = current_site.domain
        path = reverse("microsoft_auth:auth-callback")
        scheme = get_scheme(request, self.config)

        # final uri
        redirect_uri = f"{scheme}://{domain}{path}"

        return redirect_uri

    @cached_property
    def config(self):
        """
        Loads Django config.
        """
        from .conf import config

        return config

    @cached_property
    def openid_config(self):
        """
        Property which holds Azure's OpenID server metadata received by the
        OpenID Connect Discovery mechanism.
        """
        config_url = self._openid_discovery_url.format(
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
        Validates and gets all claims of a given token type which can be "access_token", "id_token" or "refresh_token".
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
            logger.warning(
                "Could not find public key id for reading JWT token"
            )
            raise RuntimeError(
                "Could not find public key id for reading JWT token"
            )

        public_key = RSAAlgorithm.from_jwk(json.dumps(jwk))

        try:
            claims = jwt.decode(
                token,
                public_key,
                algoithm="RS256",
                audience=self.config.MICROSOFT_AUTH_CLIENT_ID,
            )
        except jwt.PyJWTError as exception:
            logger.warning(
                "could verify token signature: {}".format(exception)
            )

            raise exception

        return claims

    def authorization_url(self) -> str:
        """ Generates Microsoft Authorization URL """
        authorization_url = super().authorization_url(
            self.openid_config["authorization_endpoint"],
            response_mode="form_post",
        )

        return authorization_url

    def fetch_tokens(self, **kwargs) -> MicrosoftTokensResponse:
        """
        Fetchs OAuth2 Tokens from Microsoft with given kwargs and assign to token property
        after the user has given consent and clicked the authorization url.
        """
        ms_tokens_response = super().fetch_token(  # pragma: no cover
            self.openid_config["token_endpoint"],
            client_secret=self.config.MICROSOFT_AUTH_CLIENT_SECRET,  # application secret to get tokens from
            **kwargs,  # authorization code is given as a keyword arg
        )

        return ms_tokens_response

    def refresh_token(self, refresh_token, **kwargs):
        """
        Refreshes OAuth2 Tokens from Microsoft with given kwargs and assign to token property
        after the user has given consent and clicked the authorization url.
        """
        extra_params = {"client_id": self.client_id}

        try:
            refreshed_ms_tokens = super().refresh_token(
                self.openid_config["token_endpoint"],
                refresh_token=refresh_token,
                client_secret=self.config.MICROSOFT_AUTH_CLIENT_SECRET,  # application secret to get tokens from
                **extra_params,  # authorization code is given as a keyword arg
            )

            raise RuntimeError("hu")
        except BaseException as exception:
            # an exception occured when refreshing... log the user again!
            print(exception)
            return None

        return refreshed_ms_tokens

    def has_fetched_tokens_the_appropriate_scopes(self, scopes) -> bool:
        """
        Validates Microsoft's OAuth2 server token response scopes based on MICROSOFT_AUTH_LOGIN_TYPE.
        """
        scopes = set(scopes)
        required_scopes = set(self.SCOPE_MICROSOFT)

        return required_scopes <= scopes
