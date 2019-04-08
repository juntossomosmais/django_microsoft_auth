import importlib
import os
from typing import Dict

from django.contrib.auth.models import Permission, User

from .conf import HOOK_SETTINGS
from .conf import config as global_config

AD_SUPER_USER_ROLE = os.getenv("MICROSOFT_AUTH_SUPERUSER_ROLE", "dunno")
AD_IS_STAFF_ROLE = os.getenv("MICROSOFT_AUTH_IS_STAFF_ROLE", "Writer")


def get_scheme(request, config=None):
    if config is None:
        config = global_config

    scheme = "https"
    if config.DEBUG and request is not None:
        if "HTTP_X_FORWARDED_PROTO" in request.META:
            scheme = request.META["HTTP_X_FORWARDED_PROTO"]
        else:
            scheme = request.scheme
    return scheme


def get_hook(name):
    if name in HOOK_SETTINGS:
        hook_setting = getattr(global_config, name)
        if hook_setting != "":
            module_path, function_name = hook_setting.rsplit(".", 1)
            module = importlib.import_module(module_path)
            function = getattr(module, function_name)

            return function
    return None


def _add_missing_ad_role(user_obj: User, permission_codename):
    if permission_codename == AD_SUPER_USER_ROLE:
        print("Adding superuser role...")
        user_obj.is_superuser = True

    elif permission_codename == AD_IS_STAFF_ROLE:
        print("Adding is_staff role...")
        user_obj.is_staff = True

    else:

        try:

            print("Adding permission... %s" % permission_codename)
            permission = Permission.objects.get(codename=permission_codename)
            user_obj.user_permissions.add(permission)

        except Permission.DoesNotExist as exception:
            print(
                "Permission does not exist... ignoring addition... %s"
                % permission_codename
            )


def _exclude_missing_ad_role(user_obj: User, permission_codename):
    if permission_codename == AD_SUPER_USER_ROLE:
        print("Excluding superuser role...")
        user_obj.is_superuser = False

    elif permission_codename == AD_IS_STAFF_ROLE:
        print("Excluding is_staff role...")
        user_obj.is_staff = False

    else:

        try:

            print("Excluding permission... %s" % permission_codename)
            permission = Permission.objects.get(codename=permission_codename)
            user_obj.user_permissions.remove(permission)

        except Permission.DoesNotExist as exception:
            print(
                "Permission does not exist... ignoring exclude... %s"
                % permission_codename
            )


def update_user_ad_roles(user_obj: User, id_token_claims: Dict):
    """
    Adds permissions to the user model based on what is registered in the roles section
    on Azure AD.
    """
    # must clear previous roles
    user_ad_permissions = id_token_claims["roles"]
    previous_permissions = [
        x.codename for x in Permission.objects.filter(user=user_obj)
    ]

    # django.contrib.auth.models.Permission.DoesNotExist:
    # adds roles that were found on AD but not locally for the user
    for missing_ad_role in set(user_ad_permissions) - set(
        previous_permissions
    ):
        _add_missing_ad_role(user_obj, missing_ad_role)

    # removes roles that are local but not anymore on ad
    for excluded_ad_role in set(previous_permissions) - set(
        user_ad_permissions
    ):
        _exclude_missing_ad_role(user_obj, excluded_ad_role)

    # saves alterations
    print("Saving model alterations...")
    user_obj.save()
