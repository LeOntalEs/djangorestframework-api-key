"""Example views."""

from rest_framework import viewsets, views, response, mixins, exceptions

from .models import Animal
from .serializers import AnimalSerializer
from rest_framework_api_key.utilities import get_token_from_request, get_api_key
from rest_framework_api_key.permissions import HasAPIKey, HasSomeScopeInAPIKey


class AnimalViewSet(viewsets.ReadOnlyModelViewSet):
    """Endpoints for listing and retrieving animals."""

    queryset = Animal.objects.all()
    serializer_class = AnimalSerializer
    permission_classes = (HasAPIKey,)


class AnimalCreateViewSet(mixins.CreateModelMixin, viewsets.GenericViewSet):
    """ Endpoints for create animals with verify api key scope."""

    queryset = Animal.objects.all()
    serializer_class = AnimalSerializer
    permission_classes = (HasSomeScopeInAPIKey, )
    scopes = ('add-animal',)  # needed scope for access this view

    def permission_denied(self, request, message="Permission denied"):
        """ override for PermissionDenied message """
        raise exceptions.PermissionDenied(detail=message)
