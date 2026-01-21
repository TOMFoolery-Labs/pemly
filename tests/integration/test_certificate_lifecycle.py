"""
Integration tests for certificate lifecycle.

Tests the full certificate lifecycle including:
- Certificate creation
- Status transitions
- Revocation
- Archive/unarchive
- Renewal tracking
"""

import pytest
from datetime import timedelta

from django.utils import timezone
from freezegun import freeze_time

from core.models import CertificateStatus, RevocationReason
from tests.factories import (
    UserFactory,
    CertificateFactory,
    CertificateAuthorityFactory,
)


@pytest.mark.django_db
@pytest.mark.integration
class TestCertificateLifecycle:
    """Integration tests for certificate lifecycle management."""

    def test_certificate_creation_and_active_status(self):
        """Test that newly created certificates are active."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        cert = CertificateFactory(
            ca=ca,
            common_name='new.example.com',
            status=CertificateStatus.ACTIVE,
            created_by=user,
        )

        assert cert.status == CertificateStatus.ACTIVE
        assert cert.is_expired is False
        assert cert.revoked_at is None

    def test_certificate_revocation_flow(self):
        """Test certificate revocation workflow."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        cert = CertificateFactory(
            ca=ca,
            status=CertificateStatus.ACTIVE,
            created_by=user,
        )

        # Revoke the certificate
        cert.revoke(reason=RevocationReason.KEY_COMPROMISE)

        assert cert.status == CertificateStatus.REVOKED
        assert cert.revoked_at is not None
        assert cert.revocation_reason == RevocationReason.KEY_COMPROMISE

    @pytest.mark.parametrize('reason', [
        RevocationReason.UNSPECIFIED,
        RevocationReason.KEY_COMPROMISE,
        RevocationReason.CA_COMPROMISE,
        RevocationReason.AFFILIATION_CHANGED,
        RevocationReason.SUPERSEDED,
        RevocationReason.CESSATION_OF_OPERATION,
        RevocationReason.CERTIFICATE_HOLD,
        RevocationReason.PRIVILEGE_WITHDRAWN,
    ])
    def test_all_revocation_reasons(self, reason):
        """Test all RFC 5280 revocation reasons can be applied."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)
        cert = CertificateFactory(
            ca=ca,
            status=CertificateStatus.ACTIVE,
            created_by=user,
        )

        cert.revoke(reason=reason)

        assert cert.status == CertificateStatus.REVOKED
        assert cert.revocation_reason == reason

    def test_archive_workflow(self):
        """Test certificate archiving workflow."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        # Create and revoke certificate
        cert = CertificateFactory(
            ca=ca,
            status=CertificateStatus.ACTIVE,
            created_by=user,
        )
        cert.revoke(reason=RevocationReason.SUPERSEDED)

        # Archive the revoked certificate
        archiver = UserFactory()
        cert.archive(archiver)

        assert cert.is_archived is True
        assert cert.archived_at is not None
        assert cert.archived_by == archiver

    def test_unarchive_workflow(self):
        """Test certificate unarchiving workflow."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        # Create, revoke, and archive certificate
        cert = CertificateFactory(
            ca=ca,
            status=CertificateStatus.ACTIVE,
            created_by=user,
        )
        cert.revoke()
        cert.archive(user)

        # Unarchive
        cert.unarchive()

        assert cert.is_archived is False
        assert cert.archived_at is None
        assert cert.archived_by is None
        # Still revoked after unarchive
        assert cert.status == CertificateStatus.REVOKED

    def test_cannot_archive_active_certificate(self):
        """Test that active certificates cannot be archived."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        cert = CertificateFactory(
            ca=ca,
            status=CertificateStatus.ACTIVE,
            created_by=user,
        )

        with pytest.raises(ValueError, match='Only revoked certificates'):
            cert.archive(user)


@pytest.mark.django_db
@pytest.mark.integration
class TestCertificateExpiration:
    """Integration tests for certificate expiration handling."""

    def test_certificate_expiration_detection(self):
        """Test expired certificate detection."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        # Create expired certificate
        cert = CertificateFactory(
            ca=ca,
            not_after=timezone.now() - timedelta(days=1),
            created_by=user,
        )

        assert cert.is_expired is True
        assert cert.days_until_expiry == 0

    @freeze_time('2025-01-15')
    def test_expiring_soon_detection(self):
        """Test certificate expiring soon detection."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        # Certificate expiring in 15 days (within 30 day threshold)
        cert = CertificateFactory(
            ca=ca,
            not_after=timezone.now() + timedelta(days=15),
            created_by=user,
        )

        assert cert.is_expiring_soon is True
        assert cert.days_until_expiry == 15

    @freeze_time('2025-01-15')
    def test_not_expiring_soon(self):
        """Test certificate not expiring soon."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        # Certificate expiring in 60 days (beyond 30 day threshold)
        cert = CertificateFactory(
            ca=ca,
            not_after=timezone.now() + timedelta(days=60),
            created_by=user,
        )

        assert cert.is_expiring_soon is False
        assert cert.days_until_expiry == 60


@pytest.mark.django_db
@pytest.mark.integration
class TestCertificateRenewal:
    """Integration tests for certificate renewal tracking."""

    def test_renewal_chain_tracking(self):
        """Test renewal chain is properly tracked."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)

        # Create original certificate
        original = CertificateFactory(
            ca=ca,
            common_name='renewed.example.com',
            created_by=user,
        )

        # Create first renewal
        renewal1 = CertificateFactory(
            ca=ca,
            common_name='renewed.example.com',
            renewed_from=original,
            created_by=user,
        )

        # Create second renewal
        renewal2 = CertificateFactory(
            ca=ca,
            common_name='renewed.example.com',
            renewed_from=renewal1,
            created_by=user,
        )

        # Verify chain
        assert original.is_renewal is False
        assert original.has_been_renewed is True

        assert renewal1.is_renewal is True
        assert renewal1.renewed_from == original
        assert renewal1.has_been_renewed is True

        assert renewal2.is_renewal is True
        assert renewal2.renewed_from == renewal1
        assert renewal2.has_been_renewed is False


@pytest.mark.django_db
@pytest.mark.integration
class TestCertificateChainBuilding:
    """Integration tests for certificate chain building."""

    def test_certificate_chain_with_intermediate(self):
        """Test certificate chain includes intermediate CA."""
        user = UserFactory()

        # Create CA hierarchy
        root_ca = CertificateAuthorityFactory(
            name='Root CA',
            ca_type='root',
            certificate_pem='-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----',
            created_by=user,
        )
        intermediate_ca = CertificateAuthorityFactory(
            name='Intermediate CA',
            ca_type='intermediate',
            parent=root_ca,
            certificate_pem='-----BEGIN CERTIFICATE-----\nINTERMEDIATE\n-----END CERTIFICATE-----',
            created_by=user,
        )

        # Create end-entity certificate
        cert = CertificateFactory(
            ca=intermediate_ca,
            certificate_pem='-----BEGIN CERTIFICATE-----\nEND ENTITY\n-----END CERTIFICATE-----',
            created_by=user,
        )

        chain = cert.get_chain_pem()

        # Chain should include all three certificates
        assert 'END ENTITY' in chain
        assert 'INTERMEDIATE' in chain
        assert 'ROOT' in chain

    def test_certificate_chain_order(self):
        """Test certificate chain is in correct order (leaf -> root)."""
        user = UserFactory()

        root_ca = CertificateAuthorityFactory(
            ca_type='root',
            certificate_pem='ROOT_CERT',
            created_by=user,
        )
        intermediate_ca = CertificateAuthorityFactory(
            ca_type='intermediate',
            parent=root_ca,
            certificate_pem='INTERMEDIATE_CERT',
            created_by=user,
        )
        cert = CertificateFactory(
            ca=intermediate_ca,
            certificate_pem='LEAF_CERT',
            created_by=user,
        )

        chain = cert.get_chain_pem()

        # Verify order: leaf first, then intermediate, then root
        leaf_pos = chain.index('LEAF_CERT')
        intermediate_pos = chain.index('INTERMEDIATE_CERT')
        root_pos = chain.index('ROOT_CERT')

        assert leaf_pos < intermediate_pos < root_pos


@pytest.mark.django_db
@pytest.mark.integration
class TestCASigningCapability:
    """Integration tests for CA signing capability."""

    def test_active_ca_can_sign(self):
        """Test active CA with private key can sign."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(
            status='active',
            not_after=timezone.now() + timedelta(days=365),
            created_by=user,
        )
        ca.set_private_key('-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----')
        ca.save()

        assert ca.can_sign is True

    def test_air_gapped_ca_cannot_sign(self):
        """Test air-gapped CA cannot sign."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(
            status='air_gapped',
            created_by=user,
        )

        assert ca.can_sign is False

    def test_expired_ca_cannot_sign(self):
        """Test expired CA cannot sign."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(
            status='active',
            not_after=timezone.now() - timedelta(days=1),
            created_by=user,
        )
        ca.set_private_key('-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----')
        ca.save()

        assert ca.can_sign is False

    def test_ca_without_private_key_cannot_sign(self):
        """Test CA without private key cannot sign."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(
            status='active',
            not_after=timezone.now() + timedelta(days=365),
            created_by=user,
        )
        ca.private_key_pem_encrypted = ''
        ca.save()

        assert ca.can_sign is False
