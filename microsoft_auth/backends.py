import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .client import AzureOAuth2Session
from .models import MicrosoftAccount
from .utils import get_hook, update_user_ad_roles

logger = logging.getLogger("django")
User = get_user_model()


class AzureAuthenticationBackend(ModelBackend):
    """ .
    Authentication backend to authenticate a user against their Microsoft
    Uses Microsoft's Graph OAuth and XBL servers to authentiate
    """

    microsoft = None

    def __init__(self):
        self._azure_client = None

    @property
    def config(self):
        from .conf import config

        return config

    @property
    def azure_client(self):
        return self._azure_client

    @azure_client.setter
    def azure_client(self, request):
        self._azure_client = AzureOAuth2Session(request=request)

    def authenticate(self, request, code):
        """
        Authenticates the user against the Django backend
        using Azure's OAuth2 Authorization flow by using the
        authorization code which contains the user acceptance.
        """
        self._azure_client = AzureOAuth2Session(request=request)
        user = None

        # fetch OAuth2 access, refresh and id_token
        # muast store on a session object!
        ms_tokens_response = self._azure_client.fetch_tokens(code=code)

        # store session data for checking for expiration
        request.session["ms_tokens_response"] = ms_tokens_response

        # validate permission scopes
        if self._azure_client.has_fetched_tokens_the_appropriate_scopes(
            ms_tokens_response["scope"]
        ):
            user = self._get_user_from_microsoft()
            id_token_claims = self._azure_client.get_token_claims("id_token")
            update_user_ad_roles(user, id_token_claims)

        return user

    def _get_user_from_microsoft(self):
        """
        Retrieves existing Django user or creates a new one.
        """
        id_token_claims = self._azure_client.get_token_claims("id_token")
        microsoft_user = self._get_or_create_microsoft_user(id_token_claims)
        user = self._verify_microsoft_user(microsoft_user, id_token_claims)

        return user

    def _get_or_create_microsoft_user(self, id_token_claims):
        """
        Returns a microsoft user instance or creates a new one from the MicrosoftUser model.
        """
        microsoft_user = None

        try:
            microsoft_user = MicrosoftAccount.objects.get(
                microsoft_id=id_token_claims["oid"]
            )
        except MicrosoftAccount.DoesNotExist:
            if self.config.MICROSOFT_AUTH_AUTO_CREATE:
                # create new Microsoft Account
                microsoft_user = MicrosoftAccount(
                    microsoft_id=id_token_claims["oid"]
                )
                microsoft_user.save()

        return microsoft_user

    def _verify_microsoft_user(self, microsoft_user, id_token_claims):
        """
        Verifies if the microsoft user already has an associated Django User. If not, it creates
        a new relationship.
        """
        user = microsoft_user.user

        if user is None:
            fullname = id_token_claims.get("name")
            first_name, last_name = "", ""

            if fullname is not None:
                first_name, last_name = id_token_claims["name"].split(" ", 1)

            # creates new Django user from provided data
            try:
                user = User.objects.get(email=id_token_claims["email"])

                if user.first_name == "" and user.last_name == "":
                    user.first_name = first_name
                    user.last_name = last_name
                    user.save()

            except User.DoesNotExist:
                user = User(
                    username=id_token_claims["preferred_username"][:150],
                    first_name=first_name,
                    last_name=last_name,
                    email=id_token_claims["email"],
                )
                user.save()

            microsoft_user.user = user
            microsoft_user.save()

        return user
