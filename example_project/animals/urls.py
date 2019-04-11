"""Example URL configuration."""

from rest_framework.routers import DefaultRouter
from django.urls import path
from .views import AnimalViewSet, AnimalCreateViewSet

router = DefaultRouter()
router.register("animals", AnimalViewSet)
router.register("animal-create", AnimalCreateViewSet)

urlpatterns = router.urls
