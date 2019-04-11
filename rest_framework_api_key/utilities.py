""" Utilities function."""
from .models import APIKey
from .crypto import hash_token
from .settings import TOKEN_HEADER, SECRET_KEY_HEADER


def get_token_from_request(request):
    """Extract Token and Secret from django request object."""
    token = request.META.get(TOKEN_HEADER, "")
    secret_key = request.META.get(SECRET_KEY_HEADER, "")
    return token, secret_key


def get_api_key(token, secret_key):
    """Retrieve an API Key from given token and secret.

    This method will return None if one of following reason:
    - The token or the secret key are missing
    - There is no API key for the given token
    - The token hased by the given secret key does not match the hash stored
    in database.

    In all other cases, return APIKey instance.
    """
    # Token and secret key must have been given
    if not token or not secret_key:
        return None

    # An unrevoked API key for this token must exist
    api_key = APIKey.objects.filter(token=token, revoked=False).first()
    if api_key is None:
        return None

    # Compare the hash of the given token by the given secret_key
    # to the hash stored no the api_key.
    hashed_token = hash_token(token, secret_key)
    granted = hashed_token == api_key.hashed_token
    return api_key if granted else None
