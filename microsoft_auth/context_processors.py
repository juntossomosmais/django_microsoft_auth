import logging
from datetime import datetime
from typing import Dict

import requests
from django.contrib.sites.models import Site
from django.core.signing import TimestampSigner
from django.http.request import HttpRequest
from django.middleware.csrf import get_token
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _

from .client import AzureOAuth2Session
from .conf import config
from .utils import get_scheme

logger = logging.getLogger("django")


def microsoft(request: HttpRequest) -> Dict:
    """ Adds global template variables for microsoft_auth """
    login_type = _("Microsoft")

    if config.DEBUG:  # pragma: no branch
        try:
            current_domain = Site.objects.get_current(request).domain
        except Site.DoesNotExist:
            logger.warning(
                "\nWARNING:\nThe domain configured for the sites framework "
                "does not match the domain you are accessing Django with. "
                "Microsoft authentication may not work.\n"
            )
        else:
            do_warning = get_scheme(
                request
            ) == "http" and not current_domain.startswith("localhost")
            if do_warning:  # pragma: no branch
                logger.warning(
                    "\nWARNING:\nYou are not using HTTPS. Microsoft "
                    "authentication only works over HTTPS unless the hostname "
                    "for your `redirect_uri` is `localhost`\n"
                )

    # initialize Microsoft client using CSRF token as state variable
    signer = TimestampSigner()
    state = signer.sign(get_token(request))

    # Creates OAuth2Session based on the request to the admin page
    microsoft = AzureOAuth2Session(state=state, request=request)
    authorizarion_url = microsoft.authorization_url()[0]

    return {
        "microsoft_login_enabled": config.MICROSOFT_AUTH_LOGIN_ENABLED,
        "microsoft_authorization_url": mark_safe(authorizarion_url),
        "microsoft_login_type_text": login_type,
    }


def has_access_token_expired(ms_tokens_response: Dict):
    access_token_expires_at = datetime.fromtimestamp(
        ms_tokens_response.get("expires_at")
    )
    now = datetime.now()

    print("Token expires at: %s" % (access_token_expires_at))
    print("Now: %s" % now)

    return now < access_token_expires_at


def check_access_token_expired(request: HttpRequest):
    ms_tokens_response = request.session.get("ms_tokens_response")

    print("Verifying ms_tokens_response is available in the session...")

    if ms_tokens_response:
        print("Found microsoft tokens cookie from session...")

        if has_access_token_expired(ms_tokens_response):
            print("Token has expired... trying to refresh...")

            azure_client = AzureOAuth2Session(request=request)
            refreshed_ms_tokens_response = azure_client.refresh_token(
                ms_tokens_response["refresh_token"]
            )

            # refresh was successful
            if refreshed_ms_tokens_response:
                request.session[
                    "ms_tokens_response"
                ] = refreshed_ms_tokens_response

                print(refreshed_ms_tokens_response)

            # no successful refresh, log the user again!
            else:
                print(
                    "Refreshing the access token was not successful, removing from session..."
                )
                # del request.session["ms_tokens_response"]
                for sesskey in request.session.keys():
                    del request.session[sesskey]

    return {}
