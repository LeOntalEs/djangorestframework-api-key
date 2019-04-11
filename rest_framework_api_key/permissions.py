"""API key permissions."""

from rest_framework import permissions

from .models import APIKey
from .settings import TOKEN_HEADER, SECRET_KEY_HEADER
from .crypto import hash_token
from .utilities import get_api_key, get_token_from_request


class APIKeyBasePermission(permissions.BasePermission):
    """
    Base permission class for API key permission
    """

    def get_api_key_from_request(self, request):
        """ Retrive an API Key form request """
        # Extract token and secret_key from request
        token, secret_key = get_token_from_request(request)

        # Token and secret key must have been given
        if not token or not secret_key:
            return None

        # Retrieve not revoked key and verified APIKey with given token and secret key.
        api_key = get_api_key(token, secret_key)

        return api_key


class HasAPIKey(APIKeyBasePermission):
    """Authorize if a valid API token and secret key are provided.

    The request is not authorized if:
    - The token or the secret key headers are missing
    - There is no API key for the given token
    - The token hased by the given secret key does not match the hash stored
    in database.

    In all other cases, the request is authorized.
    """

    def has_permission(self, request, view):
        """Check whether the API key grants access to a view."""
        api_key = self.get_api_key_from_request(request)
        return not api_key is None


class HasAPIKeyOrIsAuthenticated(APIKeyBasePermission):
    """Authorize if a valid API key is provided or request is authenticated."""

    def has_permission(self, request, view):
        perms = [HasAPIKey(), permissions.IsAuthenticated()]
        return any(perm.has_permission(request, view) for perm in perms)


class HasSomeScopeInAPIKey(APIKeyBasePermission):
    message = 'Api key is not exist or not enough permission.'

    def has_permission(self, request, view):
        """ Check API key has scope to access view. """
        view_scopes = getattr(view, 'scopes', None)
        if not view_scopes:
            raise Exception(
                'HasSomeScopeInAPIKey permission need `.scopes` attribute in view.'
            )

        api_key = self.get_api_key_from_request(request)
        if not api_key:
            return False

        key_scopes = api_key.scopes.all()
        return any(key_scopes.filter(name=name) for name in view_scopes)
