"""
Shared pytest fixtures for PEMLY tests.

Provides fixtures for:
- Users with various roles
- Certificate Authorities
- Certificates
- API clients
"""

import pytest
from django.contrib.auth.models import User
from rest_framework.test import APIClient

from accounts.models import UserProfile
from tests.factories import (
    UserFactory,
    CertificateAuthorityFactory,
    CertificateFactory,
    PendingCertificateRequestFactory,
)


# ============================================================================
# User Fixtures
# ============================================================================

@pytest.fixture
def super_admin_user(db):
    """Create a Super Admin user."""
    user = UserFactory(username='super_admin')
    user.profile.role = UserProfile.Role.SUPER_ADMIN
    user.profile.save()
    return user


@pytest.fixture
def admin_user(db):
    """Create an Administrator user."""
    user = UserFactory(username='admin')
    user.profile.role = UserProfile.Role.ADMINISTRATOR
    user.profile.save()
    return user


@pytest.fixture
def manager_user(db):
    """Create a Certificate Manager user."""
    user = UserFactory(username='manager')
    user.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
    user.profile.save()
    return user


@pytest.fixture
def requester_user(db):
    """Create a Certificate Requester user."""
    user = UserFactory(username='requester')
    user.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
    user.profile.save()
    return user


@pytest.fixture
def auditor_user(db):
    """Create an Auditor user."""
    user = UserFactory(username='auditor')
    user.profile.role = UserProfile.Role.AUDITOR
    user.profile.save()
    return user


@pytest.fixture
def all_role_users(super_admin_user, admin_user, manager_user, requester_user, auditor_user):
    """Return a dict of all role users for parametrized tests."""
    return {
        'super_admin': super_admin_user,
        'administrator': admin_user,
        'certificate_manager': manager_user,
        'certificate_requester': requester_user,
        'auditor': auditor_user,
    }


# ============================================================================
# API Client Fixtures
# ============================================================================

@pytest.fixture
def api_client():
    """Return an unauthenticated API client."""
    return APIClient()


@pytest.fixture
def super_admin_client(api_client, super_admin_user):
    """Return an API client authenticated as Super Admin."""
    api_client.force_authenticate(user=super_admin_user)
    return api_client


@pytest.fixture
def admin_client(api_client, admin_user):
    """Return an API client authenticated as Administrator."""
    api_client.force_authenticate(user=admin_user)
    return api_client


@pytest.fixture
def manager_client(api_client, manager_user):
    """Return an API client authenticated as Certificate Manager."""
    api_client.force_authenticate(user=manager_user)
    return api_client


@pytest.fixture
def requester_client(api_client, requester_user):
    """Return an API client authenticated as Certificate Requester."""
    api_client.force_authenticate(user=requester_user)
    return api_client


@pytest.fixture
def auditor_client(api_client, auditor_user):
    """Return an API client authenticated as Auditor."""
    api_client.force_authenticate(user=auditor_user)
    return api_client


# ============================================================================
# Certificate Authority Fixtures
# ============================================================================

@pytest.fixture
def root_ca(db, super_admin_user):
    """Create a root CA with mock certificate data."""
    return CertificateAuthorityFactory(
        name='Test Root CA',
        common_name='Test Root CA',
        ca_type='root',
        created_by=super_admin_user,
    )


@pytest.fixture
def intermediate_ca(db, root_ca, super_admin_user):
    """Create an intermediate CA under the root CA."""
    return CertificateAuthorityFactory(
        name='Test Intermediate CA',
        common_name='Test Intermediate CA',
        ca_type='intermediate',
        parent=root_ca,
        created_by=super_admin_user,
    )


@pytest.fixture
def air_gapped_ca(db, super_admin_user):
    """Create an air-gapped CA (no private key)."""
    ca = CertificateAuthorityFactory(
        name='Air-Gapped CA',
        common_name='Air-Gapped CA',
        ca_type='root',
        status='air_gapped',
        created_by=super_admin_user,
    )
    ca.private_key_pem_encrypted = ''
    ca.save()
    return ca


# ============================================================================
# Certificate Fixtures
# ============================================================================

@pytest.fixture
def server_certificate(db, root_ca, manager_user):
    """Create a server TLS certificate."""
    return CertificateFactory(
        ca=root_ca,
        common_name='test.example.com',
        type='server_tls',
        created_by=manager_user,
    )


@pytest.fixture
def client_certificate(db, root_ca, manager_user):
    """Create a client authentication certificate."""
    return CertificateFactory(
        ca=root_ca,
        common_name='client@example.com',
        type='client_auth',
        created_by=manager_user,
    )


@pytest.fixture
def revoked_certificate(db, root_ca, manager_user):
    """Create a revoked certificate."""
    cert = CertificateFactory(
        ca=root_ca,
        common_name='revoked.example.com',
        type='server_tls',
        status='revoked',
        created_by=manager_user,
    )
    return cert


# ============================================================================
# Pending Request Fixtures
# ============================================================================

@pytest.fixture
def pending_request(db, root_ca, requester_user):
    """Create a pending certificate request."""
    return PendingCertificateRequestFactory(
        ca=root_ca,
        requested_by=requester_user,
        common_name='pending.example.com',
    )


@pytest.fixture
def approved_request(db, root_ca, requester_user, manager_user, server_certificate):
    """Create an approved certificate request with issued certificate."""
    request = PendingCertificateRequestFactory(
        ca=root_ca,
        requested_by=requester_user,
        common_name='approved.example.com',
        status='issued',
        reviewed_by=manager_user,
        issued_certificate=server_certificate,
    )
    return request
