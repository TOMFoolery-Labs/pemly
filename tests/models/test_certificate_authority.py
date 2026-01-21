"""
Tests for CertificateAuthority model.
"""

import pytest
from datetime import timedelta
from unittest.mock import patch

from django.conf import settings
from django.utils import timezone

from core.models import CAType, CAStatus
from tests.factories import CertificateAuthorityFactory, UserFactory


@pytest.mark.django_db
class TestCertificateAuthorityModel:
    """Tests for CertificateAuthority model basic functionality."""

    def test_create_root_ca(self):
        """Test creating a root CA."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(
            name='Test Root CA',
            ca_type=CAType.ROOT,
            created_by=user,
        )
        assert ca.name == 'Test Root CA'
        assert ca.ca_type == CAType.ROOT
        assert ca.parent is None
        assert ca.is_root is True
        assert ca.is_intermediate is False

    def test_create_intermediate_ca(self):
        """Test creating an intermediate CA with a parent."""
        user = UserFactory()
        root_ca = CertificateAuthorityFactory(
            name='Root CA',
            ca_type=CAType.ROOT,
            created_by=user,
        )
        intermediate_ca = CertificateAuthorityFactory(
            name='Intermediate CA',
            ca_type=CAType.INTERMEDIATE,
            parent=root_ca,
            created_by=user,
        )
        assert intermediate_ca.ca_type == CAType.INTERMEDIATE
        assert intermediate_ca.parent == root_ca
        assert intermediate_ca.is_root is False
        assert intermediate_ca.is_intermediate is True

    def test_ca_str_representation(self):
        """Test string representation of CA."""
        ca = CertificateAuthorityFactory(name='My Test CA')
        assert str(ca) == 'My Test CA'

    def test_ca_depth_root(self):
        """Test depth property for root CA."""
        ca = CertificateAuthorityFactory(ca_type=CAType.ROOT)
        assert ca.depth == 0

    def test_ca_depth_intermediate(self):
        """Test depth property for intermediate CA."""
        user = UserFactory()
        root = CertificateAuthorityFactory(ca_type=CAType.ROOT, created_by=user)
        intermediate = CertificateAuthorityFactory(
            ca_type=CAType.INTERMEDIATE,
            parent=root,
            created_by=user,
        )
        assert intermediate.depth == 1

    def test_ca_get_chain_root(self):
        """Test get_chain for root CA returns only itself."""
        ca = CertificateAuthorityFactory(ca_type=CAType.ROOT)
        chain = ca.get_chain()
        assert len(chain) == 1
        assert chain[0] == ca

    def test_ca_get_chain_intermediate(self):
        """Test get_chain for intermediate CA includes parent."""
        user = UserFactory()
        root = CertificateAuthorityFactory(ca_type=CAType.ROOT, created_by=user)
        intermediate = CertificateAuthorityFactory(
            ca_type=CAType.INTERMEDIATE,
            parent=root,
            created_by=user,
        )
        chain = intermediate.get_chain()
        assert len(chain) == 2
        assert chain[0] == intermediate
        assert chain[1] == root


@pytest.mark.django_db
class TestCertificateAuthorityEncryption:
    """Tests for CA private key encryption."""

    def test_set_and_get_private_key(self):
        """Test encrypting and decrypting private key."""
        ca = CertificateAuthorityFactory()
        test_key = '-----BEGIN RSA PRIVATE KEY-----\nTEST KEY CONTENT\n-----END RSA PRIVATE KEY-----'

        ca.set_private_key(test_key)
        assert ca.private_key_pem_encrypted != ''
        assert ca.private_key_pem_encrypted != test_key  # Should be encrypted

        decrypted = ca.get_private_key()
        assert decrypted == test_key

    def test_get_empty_private_key(self):
        """Test getting private key when none is set."""
        ca = CertificateAuthorityFactory()
        ca.private_key_pem_encrypted = ''
        assert ca.get_private_key() == ''

    def test_set_private_key_without_encryption_key(self):
        """Test that setting private key fails without ENCRYPTION_KEY."""
        ca = CertificateAuthorityFactory()
        test_key = '-----BEGIN RSA PRIVATE KEY-----\nTEST\n-----END RSA PRIVATE KEY-----'

        with patch.object(settings, 'ENCRYPTION_KEY', None):
            with pytest.raises(ValueError, match="ENCRYPTION_KEY not configured"):
                ca.set_private_key(test_key)

    def test_get_private_key_without_encryption_key(self):
        """Test that getting private key fails without ENCRYPTION_KEY."""
        ca = CertificateAuthorityFactory()
        ca.private_key_pem_encrypted = 'encrypted_data'

        with patch.object(settings, 'ENCRYPTION_KEY', None):
            with pytest.raises(ValueError, match="ENCRYPTION_KEY not configured"):
                ca.get_private_key()


@pytest.mark.django_db
class TestCertificateAuthorityStatus:
    """Tests for CA status and operational properties."""

    def test_can_sign_active_with_key(self):
        """Test can_sign returns True for active CA with private key."""
        ca = CertificateAuthorityFactory(status=CAStatus.ACTIVE)
        ca.set_private_key('-----BEGIN RSA PRIVATE KEY-----\nTEST\n-----END RSA PRIVATE KEY-----')
        ca.not_after = timezone.now() + timedelta(days=365)
        ca.save()

        assert ca.can_sign is True

    def test_can_sign_air_gapped(self):
        """Test can_sign returns False for air-gapped CA."""
        ca = CertificateAuthorityFactory(status=CAStatus.AIR_GAPPED)
        assert ca.can_sign is False

    def test_can_sign_no_private_key(self):
        """Test can_sign returns False when no private key."""
        ca = CertificateAuthorityFactory(status=CAStatus.ACTIVE)
        ca.private_key_pem_encrypted = ''
        ca.save()

        assert ca.can_sign is False

    def test_can_sign_expired(self):
        """Test can_sign returns False for expired CA."""
        ca = CertificateAuthorityFactory(status=CAStatus.ACTIVE)
        ca.set_private_key('-----BEGIN RSA PRIVATE KEY-----\nTEST\n-----END RSA PRIVATE KEY-----')
        ca.not_after = timezone.now() - timedelta(days=1)
        ca.save()

        assert ca.can_sign is False

    def test_is_expired_property(self):
        """Test is_expired property."""
        ca = CertificateAuthorityFactory()
        ca.not_after = timezone.now() - timedelta(days=1)
        assert ca.is_expired is True

        ca.not_after = timezone.now() + timedelta(days=1)
        assert ca.is_expired is False

    def test_is_expired_no_date(self):
        """Test is_expired returns False when no expiry date."""
        ca = CertificateAuthorityFactory()
        ca.not_after = None
        assert ca.is_expired is False

    def test_days_until_expiry(self):
        """Test days_until_expiry calculation."""
        from freezegun import freeze_time
        with freeze_time('2025-01-15 12:00:00'):
            ca = CertificateAuthorityFactory()
            ca.not_after = timezone.now() + timedelta(days=30)
            assert ca.days_until_expiry == 30

    def test_days_until_expiry_expired(self):
        """Test days_until_expiry returns 0 for expired CA."""
        ca = CertificateAuthorityFactory()
        ca.not_after = timezone.now() - timedelta(days=10)
        assert ca.days_until_expiry == 0

    def test_is_air_gapped_property(self):
        """Test is_air_gapped property."""
        ca = CertificateAuthorityFactory(status=CAStatus.AIR_GAPPED)
        assert ca.is_air_gapped is True

        ca.status = CAStatus.ACTIVE
        assert ca.is_air_gapped is False

    def test_has_private_key_property(self):
        """Test has_private_key property."""
        ca = CertificateAuthorityFactory()
        ca.private_key_pem_encrypted = ''
        assert ca.has_private_key is False

        ca.private_key_pem_encrypted = 'encrypted_data'
        assert ca.has_private_key is True


@pytest.mark.django_db
class TestCertificateAuthorityAirGap:
    """Tests for CA air-gap operations."""

    def test_remove_private_key(self):
        """Test removing private key for air-gapping."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(status=CAStatus.ACTIVE, created_by=user)
        original_key = '-----BEGIN RSA PRIVATE KEY-----\nORIGINAL\n-----END RSA PRIVATE KEY-----'
        ca.set_private_key(original_key)
        ca.save()

        returned_key = ca.remove_private_key(user)

        assert returned_key == original_key
        assert ca.private_key_pem_encrypted == ''
        assert ca.status == CAStatus.AIR_GAPPED
        assert ca.key_removed_at is not None
        assert ca.key_removed_by == user

    def test_remove_private_key_no_key(self):
        """Test removing private key when none exists raises error."""
        user = UserFactory()
        ca = CertificateAuthorityFactory(created_by=user)
        ca.private_key_pem_encrypted = ''
        ca.save()

        with pytest.raises(ValueError, match="No private key to remove"):
            ca.remove_private_key(user)


@pytest.mark.django_db
class TestCertificateAuthorityOCSP:
    """Tests for CA OCSP responder functionality."""

    def test_set_and_get_ocsp_private_key(self):
        """Test encrypting and decrypting OCSP private key."""
        ca = CertificateAuthorityFactory()
        test_key = '-----BEGIN RSA PRIVATE KEY-----\nOCSP KEY\n-----END RSA PRIVATE KEY-----'

        ca.set_ocsp_private_key(test_key)
        assert ca.ocsp_private_key_pem_encrypted != ''

        decrypted = ca.get_ocsp_private_key()
        assert decrypted == test_key

    def test_has_ocsp_responder_true(self):
        """Test has_ocsp_responder when both cert and key are present."""
        ca = CertificateAuthorityFactory()
        ca.ocsp_certificate_pem = '-----BEGIN CERTIFICATE-----\nOCSP CERT\n-----END CERTIFICATE-----'
        ca.set_ocsp_private_key('-----BEGIN RSA PRIVATE KEY-----\nOCSP KEY\n-----END RSA PRIVATE KEY-----')

        assert ca.has_ocsp_responder is True

    def test_has_ocsp_responder_false_no_cert(self):
        """Test has_ocsp_responder when certificate is missing."""
        ca = CertificateAuthorityFactory()
        ca.ocsp_certificate_pem = ''
        ca.set_ocsp_private_key('-----BEGIN RSA PRIVATE KEY-----\nOCSP KEY\n-----END RSA PRIVATE KEY-----')

        assert ca.has_ocsp_responder is False

    def test_has_ocsp_responder_false_no_key(self):
        """Test has_ocsp_responder when key is missing."""
        ca = CertificateAuthorityFactory()
        ca.ocsp_certificate_pem = '-----BEGIN CERTIFICATE-----\nOCSP CERT\n-----END CERTIFICATE-----'
        ca.ocsp_private_key_pem_encrypted = ''

        assert ca.has_ocsp_responder is False

    def test_ocsp_is_expired(self):
        """Test ocsp_is_expired property."""
        ca = CertificateAuthorityFactory()
        ca.ocsp_not_after = timezone.now() - timedelta(days=1)
        assert ca.ocsp_is_expired is True

        ca.ocsp_not_after = timezone.now() + timedelta(days=1)
        assert ca.ocsp_is_expired is False

        ca.ocsp_not_after = None
        assert ca.ocsp_is_expired is False
