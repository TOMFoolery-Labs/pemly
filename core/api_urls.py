"""
API URL routing for certificate management.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .api_views import (
    CertificateViewSet,
    CertificateAuthorityViewSet,
    PendingCertificateRequestViewSet,
    APIKeyViewSet
)

app_name = 'api'

# Create router and register viewsets
router = DefaultRouter()
router.register(r'certificates', CertificateViewSet, basename='certificate')
router.register(r'cas', CertificateAuthorityViewSet, basename='ca')
router.register(r'requests', PendingCertificateRequestViewSet, basename='request')
router.register(r'api-keys', APIKeyViewSet, basename='apikey')

# URL patterns
urlpatterns = [
    path('', include(router.urls)),
]
