import requests

from allauth.socialaccount import app_settings
from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.providers.base import ProviderAccount
from allauth.socialaccount.providers.oauth2.client import OAuth2Error
from allauth.socialaccount.providers.oauth2.provider import OAuth2Provider
from allauth.socialaccount.providers.vk import flows
from allauth.socialaccount.providers.vk.views import VKOAuth2Adapter


class VKAccount(ProviderAccount):
    def get_profile_url(self):
        return f"https://vk.ru/id{self.account.extra_data.get('id')}"

    def get_avatar_url(self):
        return self.account.extra_data.get("avatar")


class VKProvider(OAuth2Provider):
    id = "vk"
    name = "VK"
    account_class = VKAccount
    oauth2_adapter_class = VKOAuth2Adapter
    pkce_enabled_default = True
    supports_token_authentication = True

    def get_default_scope(self):
        scope = []
        if app_settings.QUERY_EMAIL:
            scope.append("email")
        return scope

    def extract_uid(self, data):
        return str(data["user_id"])

    def extract_common_fields(self, data):
        return dict(
            email=data.get("email"),
            last_name=data.get("last_name"),
            username=data.get("screen_name"),
            first_name=data.get("first_name"),
            phone=data.get("phone"),
        )

    def verify_token(self, request, token):
        """
        Exchanges authorization code for VK ID.

        Treats `access_token` as an authorization code and exchanges it
        using PKCE code_verifier. `state` must be present.
        """

        access_token = token.get("access_token")
        state_id = token.get("state")

        if not access_token:
            raise get_adapter().validation_error("invalid_token")
        if not state_id:
            raise get_adapter().validation_error("invalid_state")

        try:
            return flows.exchange_code(
                request,
                self,
                code=access_token,
                state_id=state_id,
                device_id=token.get("device_id"),
            )
        except (OAuth2Error, requests.RequestException) as e:
            raise get_adapter().validation_error("invalid_token") from e


provider_classes = [VKProvider]
