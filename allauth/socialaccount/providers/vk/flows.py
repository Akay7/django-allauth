import logging

from django.core.exceptions import PermissionDenied

from allauth.socialaccount.adapter import get_adapter
from allauth.socialaccount.models import SocialLogin


logger = logging.getLogger(__name__)


def exchange_code(
    request, provider, code: str, state_id: str, device_id: str = None
) -> SocialLogin:
    """
    Exchanges authorization code for access token using PKCE code_verifier.
    """
    # Retrieve state with pkce_code_verifier
    try:
        state = provider.unstash_redirect_state(request, state_id)
    except PermissionDenied as e:
        raise get_adapter().validation_error("invalid_state") from e

    if not state or not state.get("pkce_code_verifier"):
        raise get_adapter().validation_error("invalid_state")

    pkce_code_verifier = state.get("pkce_code_verifier")

    # Get adapter and client
    adapter = provider.get_oauth2_adapter(request)
    client = adapter.get_client(request, provider.app)

    # Exchange code for access token
    extra_data = {
        "state": state_id,
        "device_id": device_id,
    }
    access_token_data = client.get_access_token(
        code, pkce_code_verifier=pkce_code_verifier, extra_data=extra_data
    )

    # Parse token and complete login
    token = adapter.parse_token(access_token_data)
    if provider.app.pk:
        token.app = provider.app

    login = adapter.complete_login(
        request, provider.app, token, response=access_token_data
    )
    login.token = token
    login.state = state
    return login
