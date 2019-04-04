import logging

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend

from .client import MicrosoftClient
from .models import MicrosoftAccount
from .utils import get_hook

logger = logging.getLogger("django")
User = get_user_model()


class MicrosoftAuthenticationBackend(ModelBackend):
    """ .
    Authentication backend to authenticate a user against their Microsoft
    Uses Microsoft's Graph OAuth and XBL servers to authentiate
    """
    config = None
    microsoft = None

    def __init__(self, user=None):
        from .conf import config

        self.config = config

    def authenticate(self, request, code=None):
        """
        Authenticates the user against the Django backend
        using a Microsoft auth code from
        https://login.microsoftonline.com/common/oauth2/v2.0/authorize or
        https://login.live.com/oauth20_authorize.srf

        For more details:
        https://developer.microsoft.com/en-us/graph/docs/get-started/rest
        """
        self.microsoft = MicrosoftClient(request=request)
        user = None
        if code is not None:
            # fetch OAuth2 access, refresh and id_token
            ms_tokens_response = self.microsoft.fetch_tokens(code=code)

            # validate permission scopes
            if self.microsoft.has_fetched_tokens_the_appropriate_scopes(
                ms_tokens_response["scope"]
            ):
                user = self._authenticate_microsoft_user()

        return user

    def _authenticate_microsoft_user(self):
        id_token_claims = self.microsoft.get_token_claims("id_token")

        if id_token_claims is not None:
            return self._get_user_from_microsoft(id_token_claims)

        return None

    def _get_user_from_microsoft(self, id_token_claims):
        """
        Retrieves existing Django user or creates a new one.
        """
        user = None
        microsoft_user = self._get_or_create_microsoft_user(id_token_claims)

        if microsoft_user is not None:
            user = self._verify_microsoft_user(microsoft_user, id_token_claims)

        return user

    def _get_or_create_microsoft_user(self, id_token_claims):
        """
        Returns a microsoft user instance or creates a new one from the MicrosoftUser model.
        """
        microsoft_user = None

        try:
            microsoft_user = MicrosoftAccount.objects.get(
                microsoft_id=id_token_claims["sub"]
            )
        except MicrosoftAccount.DoesNotExist:
            if self.config.MICROSOFT_AUTH_AUTO_CREATE:
                # create new Microsoft Account
                microsoft_user = MicrosoftAccount(microsoft_id=id_token_claims["sub"])
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

        self._add_user_staff_permissions(user, id_token_claims)

        return user

    def _add_user_staff_permissions(self, user, id_tokens_claims):
        STAFF_REQUIRED_PERMISSIONS = ("Writer", )
        ad_roles = id_tokens_claims.get("roles")

        for role in ad_roles:
            if role in STAFF_REQUIRED_PERMISSIONS:
                user.is_staff = True
                user.save()

    #
    # def _get_existing_microsoft_account(self, user):
    #     try:
    #         return MicrosoftAccount.objects.get(user=user)
    #     except MicrosoftAccount.DoesNotExist:
    #         return None
    #
    # def _call_hook(self, user):
    #     function = get_hook("MICROSOFT_AUTH_AUTHENTICATE_HOOK")
    #     if function is not None:
    #         if self.config.MICROSOFT_AUTH_LOGIN_TYPE == LOGIN_TYPE_XBL:
    #             function(user, self.microsoft.xbox_token)
    #         else:
    #             function(user, self.microsoft.token)
