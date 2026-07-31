"""
Regression tests for view-level authorization.

These lock in the access-control fixes for previously under-protected views:
- Application settings / CFSSL control (Admin+ only)
- Backup & restore (Super Admin only)
- Intermediate-CA CSR/import and OCSP config (Admin+ only)
- Certificate detail/download object scoping and private-key gating
- REST API certificate listing role scoping
"""

import pytest
from django.urls import reverse

from tests.factories import (
    AdministratorUserFactory,
    AuditorUserFactory,
    CertificateManagerUserFactory,
    CertificateRequesterUserFactory,
    CertificateFactory,
    PendingCAFactory,
    RootCAFactory,
    SuperAdminUserFactory,
)


# ---------------------------------------------------------------------------
# Application settings & CFSSL control: Administrators and Super Admins only
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestSettingsAuthorization:
    @pytest.mark.parametrize('factory,allowed', [
        (SuperAdminUserFactory, True),
        (AdministratorUserFactory, True),
        (CertificateManagerUserFactory, False),
        (CertificateRequesterUserFactory, False),
        (AuditorUserFactory, False),
    ])
    def test_settings_page_access(self, client, factory, allowed):
        client.force_login(factory())
        response = client.get(reverse('core:settings'))
        if allowed:
            assert response.status_code == 200
        else:
            assert response.status_code == 403

    @pytest.mark.parametrize('factory,allowed', [
        (AdministratorUserFactory, True),
        (CertificateRequesterUserFactory, False),
        (AuditorUserFactory, False),
    ])
    def test_cfssl_action_access(self, client, factory, allowed):
        client.force_login(factory())
        response = client.post(reverse('core:cfssl_action'), {'action': 'status'})
        # Allowed users get a redirect back to settings; others are forbidden.
        assert (response.status_code == 403) == (not allowed)

    def test_requester_cannot_write_cfssl_binary_path(self, client):
        """A non-admin must not be able to change the CFSSL binary path (RCE vector)."""
        from core.models import AppSettings

        client.force_login(CertificateRequesterUserFactory())
        response = client.post(reverse('core:settings'), {
            'cfssl_binary_path': '/tmp/evil',
            'cfssl_host': '0.0.0.0',
            'cfssl_port': '8888',
            'email_backend': 'smtp',
            'smtp_port': '587',
        })
        assert response.status_code == 403
        assert AppSettings.get().cfssl_binary_path == ''


# ---------------------------------------------------------------------------
# Backup & restore: Super Admin only
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestBackupAuthorization:
    @pytest.mark.parametrize('factory,allowed', [
        (SuperAdminUserFactory, True),
        (AdministratorUserFactory, False),
        (CertificateManagerUserFactory, False),
        (CertificateRequesterUserFactory, False),
        (AuditorUserFactory, False),
    ])
    def test_backup_page_access(self, client, factory, allowed):
        client.force_login(factory())
        response = client.get(reverse('core:backup'))
        assert (response.status_code == 200) == allowed
        if not allowed:
            assert response.status_code == 403

    @pytest.mark.parametrize('factory', [
        AdministratorUserFactory,
        CertificateRequesterUserFactory,
        AuditorUserFactory,
    ])
    def test_restore_confirm_denied_for_non_super_admin(self, client, factory):
        """Restore (which can wipe all data in replace mode) must be Super Admin only."""
        client.force_login(factory())
        response = client.post(reverse('core:restore_confirm'), {'mode': 'replace'})
        assert response.status_code == 403


# ---------------------------------------------------------------------------
# Intermediate CA CSR/import and OCSP config: Administrators and Super Admins
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCAOperationAuthorization:
    @pytest.mark.parametrize('factory,allowed', [
        (AdministratorUserFactory, True),
        (CertificateManagerUserFactory, False),
        (CertificateRequesterUserFactory, False),
        (AuditorUserFactory, False),
    ])
    def test_intermediate_csr_access(self, client, factory, allowed):
        ca = RootCAFactory()
        client.force_login(factory())
        response = client.get(reverse('core:intermediate_create_csr', args=[ca.pk]))
        if allowed:
            assert response.status_code == 200
        else:
            assert response.status_code == 403

    @pytest.mark.parametrize('factory,allowed', [
        (AdministratorUserFactory, True),
        (CertificateManagerUserFactory, False),
        (CertificateRequesterUserFactory, False),
    ])
    def test_intermediate_import_access(self, client, factory, allowed):
        pending = PendingCAFactory()
        client.force_login(factory())
        response = client.get(reverse('core:intermediate_import_cert', args=[pending.pk]))
        if allowed:
            assert response.status_code == 200
        else:
            assert response.status_code == 403

    @pytest.mark.parametrize('factory,allowed', [
        (AdministratorUserFactory, True),
        (CertificateManagerUserFactory, False),
        (AuditorUserFactory, False),
    ])
    def test_ocsp_config_access(self, client, factory, allowed):
        ca = RootCAFactory()
        client.force_login(factory())
        response = client.get(reverse('core:ca_ocsp_config', args=[ca.pk]))
        if allowed:
            assert response.status_code == 200
        else:
            assert response.status_code == 403


# ---------------------------------------------------------------------------
# Certificate detail/download scoping and private-key gating
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestCertificateAccessScoping:
    def _cert_with_key(self, **kwargs):
        cert = CertificateFactory(**kwargs)
        cert.set_private_key('-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----')
        cert.save()
        return cert

    def test_requester_cannot_view_other_users_certificate(self, client):
        other_cert = CertificateFactory()
        client.force_login(CertificateRequesterUserFactory())
        response = client.get(reverse('core:certificate_detail', args=[other_cert.pk]))
        assert response.status_code == 404

    def test_requester_can_view_own_certificate(self, client):
        requester = CertificateRequesterUserFactory()
        own_cert = CertificateFactory(created_by=requester)
        client.force_login(requester)
        response = client.get(reverse('core:certificate_detail', args=[own_cert.pk]))
        assert response.status_code == 200

    def test_requester_cannot_download_other_users_private_key(self, client):
        victim_cert = self._cert_with_key()
        client.force_login(CertificateRequesterUserFactory())
        response = client.get(
            reverse('core:certificate_download', args=[victim_cert.pk, 'key'])
        )
        # Scoped out entirely -> 404, key is never disclosed.
        assert response.status_code == 404

    def test_requester_can_download_own_private_key(self, client):
        requester = CertificateRequesterUserFactory()
        own_cert = self._cert_with_key(created_by=requester)
        client.force_login(requester)
        response = client.get(
            reverse('core:certificate_download', args=[own_cert.pk, 'key'])
        )
        assert response.status_code == 200

    def test_auditor_cannot_download_any_private_key(self, client):
        cert = self._cert_with_key()
        client.force_login(AuditorUserFactory())
        response = client.get(
            reverse('core:certificate_download', args=[cert.pk, 'key'])
        )
        # Read-only users are redirected away from private-key material.
        assert response.status_code == 302

    def test_auditor_can_download_public_certificate(self, client):
        cert = CertificateFactory()
        client.force_login(AuditorUserFactory())
        response = client.get(
            reverse('core:certificate_download', args=[cert.pk, 'cert'])
        )
        assert response.status_code == 200

    def test_manager_can_download_any_private_key(self, client):
        cert = self._cert_with_key()
        client.force_login(CertificateManagerUserFactory())
        response = client.get(
            reverse('core:certificate_download', args=[cert.pk, 'key'])
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# REST API certificate listing role scoping
# ---------------------------------------------------------------------------

@pytest.mark.django_db
class TestAPICertificateScoping:
    def test_requester_api_list_only_returns_own_certificates(self, client):
        requester = CertificateRequesterUserFactory()
        own_cert = CertificateFactory(created_by=requester)
        CertificateFactory()  # someone else's certificate

        client.force_login(requester)
        response = client.get('/api/v1/certificates/')
        assert response.status_code == 200

        returned_ids = {item['id'] for item in response.json()['results']}
        assert returned_ids == {str(own_cert.id)}

    def test_manager_api_list_returns_all_certificates(self, client):
        CertificateFactory()
        CertificateFactory()

        client.force_login(CertificateManagerUserFactory())
        response = client.get('/api/v1/certificates/')
        assert response.status_code == 200
        assert response.json()['count'] == 2
