from django.apps import apps
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .conf import LOGIN_TYPE_MA, config
from .models import MicrosoftAccount

__all__ = [
    "MicrosoftAccountAdmin",
    "MicrosoftAccountInlineAdmin",
    "UserAdmin",
]

User = get_user_model()

# override admin site template
admin.site.login_template = "microsoft/admin_login.html"

# djangoql support
extra_base = []
if apps.is_installed("djangoql"):  # pragma: no branch
    from djangoql.admin import DjangoQLSearchMixin

    extra_base = [DjangoQLSearchMixin]

base_admin = extra_base + [admin.ModelAdmin]
base_user_admin = extra_base + [BaseUserAdmin]

# unregister User mode if it is already registered
if admin.site.is_registered(User):  # pragma: no branch
    admin.site.unregister(User)


class MicrosoftAccountAdmin(*base_admin):
    readonly_fields = ("microsoft_id",)


class MicrosoftAccountInlineAdmin(admin.StackedInline):
    model = MicrosoftAccount
    readonly_fields = ("microsoft_id",)

def _register_admins():
    _do_both = config.MICROSOFT_AUTH_REGISTER_INACTIVE_ADMIN
    _login_type = config.MICROSOFT_AUTH_LOGIN_TYPE

    if admin.site.is_registered(MicrosoftAccount):
        admin.site.unregister(MicrosoftAccount)

    if _do_both or _login_type == LOGIN_TYPE_MA:
        admin.site.register(MicrosoftAccount, MicrosoftAccountAdmin)


def _get_inlines():
    _do_both = config.MICROSOFT_AUTH_REGISTER_INACTIVE_ADMIN
    _login_type = config.MICROSOFT_AUTH_LOGIN_TYPE
    inlines = []

    if _do_both or _login_type == LOGIN_TYPE_MA:
        inlines.append(MicrosoftAccountInlineAdmin)

    return inlines


@admin.register(User)
class UserAdmin(*base_user_admin):
    @property
    def inlines(self):
        """ Adds MicrosoftAccount foreign keys to
        User model """

        return _get_inlines()


_register_admins()
