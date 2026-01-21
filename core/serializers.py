"""
REST API serializers for certificate management.
"""

from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    Certificate, CertificateAuthority, PendingCertificateRequest,
    APIKey, CertificateType, KeyAlgorithm
)
from .authentication import generate_api_key


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model."""

    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'last_name']
        read_only_fields = ['id']


class CertificateAuthoritySerializer(serializers.ModelSerializer):
    """Serializer for Certificate Authority model."""

    class Meta:
        model = CertificateAuthority
        fields = [
            'id', 'name', 'common_name', 'organization', 'organizational_unit',
            'country', 'state', 'locality', 'key_algorithm', 'key_size',
            'validity_years', 'is_active', 'certificate_pem', 'serial_number',
            'not_before', 'not_after', 'created_at', 'ca_type', 'parent'
        ]
        read_only_fields = [
            'id', 'certificate_pem', 'serial_number', 'not_before',
            'not_after', 'created_at'
        ]


class CertificateListSerializer(serializers.ModelSerializer):
    """Serializer for listing certificates (without private keys)."""

    ca_name = serializers.CharField(source='ca.name', read_only=True)
    type_display = serializers.CharField(source='get_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = Certificate
        fields = [
            'id', 'common_name', 'organization', 'type', 'type_display',
            'status', 'status_display', 'ca', 'ca_name', 'serial_number',
            'not_before', 'not_after', 'created_at', 'san_dns_names',
            'san_ip_addresses', 'san_email_addresses'
        ]
        read_only_fields = [
            'id', 'serial_number', 'not_before', 'not_after', 'created_at',
            'ca_name', 'type_display', 'status_display'
        ]


class CertificateDetailSerializer(serializers.ModelSerializer):
    """Serializer for certificate details including PEM data."""

    ca_name = serializers.CharField(source='ca.name', read_only=True)
    type_display = serializers.CharField(source='get_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    created_by_username = serializers.CharField(source='created_by.username', read_only=True)

    class Meta:
        model = Certificate
        fields = [
            'id', 'common_name', 'organization', 'type', 'type_display',
            'status', 'status_display', 'ca', 'ca_name', 'serial_number',
            'not_before', 'not_after', 'created_at', 'created_by_username',
            'san_dns_names', 'san_ip_addresses', 'san_email_addresses',
            'certificate_pem', 'public_key_pem', 'key_algorithm', 'key_size',
            'validity_days', 'revoked_at', 'revocation_reason'
        ]
        read_only_fields = [
            'id', 'serial_number', 'not_before', 'not_after', 'created_at',
            'ca_name', 'type_display', 'status_display', 'created_by_username',
            'certificate_pem', 'public_key_pem', 'revoked_at'
        ]


class CertificateCreateSerializer(serializers.Serializer):
    """Serializer for creating new certificates."""

    ca = serializers.UUIDField(help_text="Certificate Authority ID")
    common_name = serializers.CharField(max_length=255)
    organization = serializers.CharField(max_length=255, required=False, allow_blank=True)
    type = serializers.ChoiceField(choices=CertificateType.choices)
    key_algorithm = serializers.ChoiceField(choices=KeyAlgorithm.choices, default='rsa')
    key_size = serializers.IntegerField(default=2048)
    validity_days = serializers.IntegerField(default=365)
    san_dns_names = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
        help_text="Subject Alternative Names - DNS entries"
    )
    san_ip_addresses = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
        help_text="Subject Alternative Names - IP addresses"
    )
    san_email_addresses = serializers.ListField(
        child=serializers.CharField(),
        required=False,
        allow_empty=True,
        help_text="Subject Alternative Names - Email addresses"
    )

    def validate_ca(self, value):
        """Validate that the CA exists and is active."""
        try:
            ca = CertificateAuthority.objects.get(id=value)
            if not ca.is_active:
                raise serializers.ValidationError("Certificate Authority is not active")
            return ca
        except CertificateAuthority.DoesNotExist:
            raise serializers.ValidationError("Certificate Authority not found")

    def validate_key_size(self, value):
        """Validate key size based on algorithm."""
        if value not in [2048, 3072, 4096, 256, 384, 521]:
            raise serializers.ValidationError(
                "Invalid key size. RSA: 2048, 3072, 4096. ECDSA: 256, 384, 521"
            )
        return value


class CertificateRevokeSerializer(serializers.Serializer):
    """Serializer for revoking certificates."""

    reason = serializers.ChoiceField(
        choices=[
            'unspecified', 'key_compromise', 'ca_compromise',
            'affiliation_changed', 'superseded', 'cessation_of_operation',
            'privilege_withdrawn'
        ],
        default='unspecified'
    )


class PendingCertificateRequestSerializer(serializers.ModelSerializer):
    """Serializer for pending certificate requests."""

    ca_name = serializers.CharField(source='ca.name', read_only=True)
    requested_by_username = serializers.CharField(source='requested_by.username', read_only=True)
    reviewed_by_username = serializers.CharField(source='reviewed_by.username', read_only=True, allow_null=True)
    type_display = serializers.CharField(source='get_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)

    class Meta:
        model = PendingCertificateRequest
        fields = [
            'id', 'common_name', 'organization', 'type', 'type_display',
            'status', 'status_display', 'ca', 'ca_name', 'key_algorithm',
            'key_size', 'validity_days', 'san_dns_names', 'san_ip_addresses',
            'san_email_addresses', 'requested_by', 'requested_by_username',
            'requested_at', 'reviewed_by', 'reviewed_by_username', 'reviewed_at',
            'rejection_reason', 'issued_certificate'
        ]
        read_only_fields = [
            'id', 'requested_by', 'requested_by_username', 'requested_at',
            'reviewed_by', 'reviewed_by_username', 'reviewed_at',
            'status', 'status_display', 'ca_name', 'type_display',
            'issued_certificate'
        ]


class RequestApproveSerializer(serializers.Serializer):
    """Serializer for approving certificate requests."""
    pass  # No additional fields needed


class RequestRejectSerializer(serializers.Serializer):
    """Serializer for rejecting certificate requests."""

    reason = serializers.CharField(
        required=True,
        help_text="Reason for rejecting the certificate request"
    )


class APIKeySerializer(serializers.ModelSerializer):
    """Serializer for API keys (read-only for listing)."""

    user_username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model = APIKey
        fields = [
            'id', 'name', 'prefix', 'user', 'user_username',
            'is_active', 'created_at', 'last_used_at', 'expires_at'
        ]
        read_only_fields = [
            'id', 'prefix', 'created_at', 'last_used_at', 'user_username'
        ]


class APIKeyCreateSerializer(serializers.Serializer):
    """Serializer for creating new API keys."""

    name = serializers.CharField(
        max_length=255,
        help_text="Descriptive name for this API key"
    )
    expires_at = serializers.DateTimeField(
        required=False,
        allow_null=True,
        help_text="Optional expiration date for this key"
    )

    def create(self, validated_data):
        """Create a new API key."""
        user = self.context['request'].user
        name = validated_data['name']
        expires_at = validated_data.get('expires_at')

        # Generate API key
        full_key, prefix, hashed_key = generate_api_key()

        # Create API key object
        api_key = APIKey.objects.create(
            name=name,
            prefix=prefix,
            hashed_key=hashed_key,
            user=user,
            expires_at=expires_at
        )

        # Attach the full key to the instance for one-time display
        api_key.full_key = full_key

        return api_key
