import uuid

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone


class KeyAlgorithm(models.TextChoices):
    """Supported key algorithms."""
    RSA = 'rsa', 'RSA'
    ECDSA = 'ecdsa', 'ECDSA'


class CertificateType(models.TextChoices):
    """Types of certificates that can be issued."""
    SERVER_TLS = 'server_tls', 'Server TLS'
    CLIENT_AUTH = 'client_auth', 'Client Authentication'


class CertificateStatus(models.TextChoices):
    """Certificate lifecycle status."""
    ACTIVE = 'active', 'Active'
    REVOKED = 'revoked', 'Revoked'
    EXPIRED = 'expired', 'Expired'


class RevocationReason(models.TextChoices):
    """Standard certificate revocation reasons (RFC 5280)."""
    UNSPECIFIED = 'unspecified', 'Unspecified'
    KEY_COMPROMISE = 'key_compromise', 'Key Compromise'
    CA_COMPROMISE = 'ca_compromise', 'CA Compromise'
    AFFILIATION_CHANGED = 'affiliation_changed', 'Affiliation Changed'
    SUPERSEDED = 'superseded', 'Superseded'
    CESSATION_OF_OPERATION = 'cessation_of_operation', 'Cessation of Operation'
    CERTIFICATE_HOLD = 'certificate_hold', 'Certificate Hold'
    PRIVILEGE_WITHDRAWN = 'privilege_withdrawn', 'Privilege Withdrawn'


class CertificateAuthority(models.Model):
    """
    Root Certificate Authority for signing certificates.

    Only one CA should be active per deployment (enforced by application logic).
    Private key is encrypted at rest using Fernet.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=255, help_text="Friendly name for this CA")
    common_name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255)
    organizational_unit = models.CharField(max_length=255, blank=True)
    country = models.CharField(max_length=2, help_text="Two-letter country code")
    state = models.CharField(max_length=255)
    locality = models.CharField(max_length=255)

    # Key configuration
    key_algorithm = models.CharField(
        max_length=10,
        choices=KeyAlgorithm.choices,
        default=KeyAlgorithm.RSA
    )
    key_size = models.IntegerField(
        default=4096,
        help_text="Key size in bits (RSA: 2048, 4096; ECDSA: 256, 384)"
    )
    validity_years = models.IntegerField(default=10)

    # Certificate data
    certificate_pem = models.TextField(blank=True)
    private_key_pem_encrypted = models.TextField(blank=True)
    public_key_pem = models.TextField(blank=True)
    serial_number = models.CharField(max_length=255, blank=True)

    # Validity dates
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)

    # Status
    is_active = models.BooleanField(default=True)

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='created_cas'
    )

    class Meta:
        verbose_name = "Certificate Authority"
        verbose_name_plural = "Certificate Authorities"
        ordering = ['-created_at']

    def __str__(self):
        return self.name

    def set_private_key(self, plaintext_key: str) -> None:
        """Encrypt and store the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        self.private_key_pem_encrypted = f.encrypt(plaintext_key.encode()).decode()

    def get_private_key(self) -> str:
        """Decrypt and return the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        if not self.private_key_pem_encrypted:
            return ""
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.decrypt(self.private_key_pem_encrypted.encode()).decode()

    @property
    def is_expired(self) -> bool:
        """Check if the CA certificate has expired."""
        if not self.not_after:
            return False
        return timezone.now() > self.not_after

    @property
    def days_until_expiry(self) -> int | None:
        """Days until CA certificate expires."""
        if not self.not_after:
            return None
        delta = self.not_after - timezone.now()
        return max(0, delta.days)


class Certificate(models.Model):
    """
    Individual certificate issued by the CA.

    Supports both server-side key generation and CSR-based issuance.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ca = models.ForeignKey(
        CertificateAuthority,
        on_delete=models.PROTECT,
        related_name='certificates'
    )

    # Certificate type
    type = models.CharField(
        max_length=20,
        choices=CertificateType.choices,
        default=CertificateType.SERVER_TLS
    )

    # Subject information
    common_name = models.CharField(max_length=255)
    organization = models.CharField(max_length=255, blank=True)

    # Subject Alternative Names (SANs)
    san_dns_names = models.JSONField(default=list, blank=True)
    san_ip_addresses = models.JSONField(default=list, blank=True)
    san_email_addresses = models.JSONField(default=list, blank=True)

    # Key configuration
    key_algorithm = models.CharField(
        max_length=10,
        choices=KeyAlgorithm.choices,
        default=KeyAlgorithm.RSA
    )
    key_size = models.IntegerField(default=2048)
    validity_days = models.IntegerField(default=365)

    # Certificate data
    certificate_pem = models.TextField(blank=True)
    private_key_pem_encrypted = models.TextField(
        blank=True,
        help_text="Only stored for server-generated keys"
    )
    public_key_pem = models.TextField(blank=True)
    csr_pem = models.TextField(blank=True, help_text="Original CSR if user-submitted")
    serial_number = models.CharField(max_length=255, blank=True)

    # Validity dates
    not_before = models.DateTimeField(null=True, blank=True)
    not_after = models.DateTimeField(null=True, blank=True)

    # Status and revocation
    status = models.CharField(
        max_length=20,
        choices=CertificateStatus.choices,
        default=CertificateStatus.ACTIVE
    )
    revoked_at = models.DateTimeField(null=True, blank=True)
    revocation_reason = models.CharField(
        max_length=30,
        choices=RevocationReason.choices,
        blank=True
    )

    # Audit fields
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='created_certificates'
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.common_name} ({self.get_type_display()})"

    def set_private_key(self, plaintext_key: str) -> None:
        """Encrypt and store the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        self.private_key_pem_encrypted = f.encrypt(plaintext_key.encode()).decode()

    def get_private_key(self) -> str:
        """Decrypt and return the private key."""
        if not settings.ENCRYPTION_KEY:
            raise ValueError("ENCRYPTION_KEY not configured")
        if not self.private_key_pem_encrypted:
            return ""
        f = Fernet(settings.ENCRYPTION_KEY.encode())
        return f.decrypt(self.private_key_pem_encrypted.encode()).decode()

    @property
    def has_private_key(self) -> bool:
        """Check if private key is stored (server-generated)."""
        return bool(self.private_key_pem_encrypted)

    @property
    def is_expired(self) -> bool:
        """Check if the certificate has expired."""
        if not self.not_after:
            return False
        return timezone.now() > self.not_after

    @property
    def days_until_expiry(self) -> int | None:
        """Days until certificate expires."""
        if not self.not_after:
            return None
        delta = self.not_after - timezone.now()
        return max(0, delta.days)

    @property
    def is_expiring_soon(self) -> bool:
        """Check if certificate expires within 30 days."""
        days = self.days_until_expiry
        return days is not None and days <= 30

    def revoke(self, reason: str = RevocationReason.UNSPECIFIED) -> None:
        """Mark the certificate as revoked."""
        self.status = CertificateStatus.REVOKED
        self.revoked_at = timezone.now()
        self.revocation_reason = reason
        self.save(update_fields=['status', 'revoked_at', 'revocation_reason'])


class AuditLog(models.Model):
    """
    Immutable audit log for all certificate operations.

    Records who did what, when, and from where.
    """

    class Action(models.TextChoices):
        CA_CREATED = 'ca_created', 'CA Created'
        CA_UPDATED = 'ca_updated', 'CA Updated'
        CERT_ISSUED = 'cert_issued', 'Certificate Issued'
        CERT_REVOKED = 'cert_revoked', 'Certificate Revoked'
        CERT_DOWNLOADED = 'cert_downloaded', 'Certificate Downloaded'
        USER_LOGIN = 'user_login', 'User Login'
        USER_LOGOUT = 'user_logout', 'User Logout'

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)
    user = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )
    action = models.CharField(max_length=30, choices=Action.choices, db_index=True)
    resource_type = models.CharField(max_length=50, db_index=True)
    resource_id = models.UUIDField(null=True, blank=True)
    resource_name = models.CharField(max_length=255, blank=True)
    details = models.JSONField(default=dict, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=500, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"

    def __str__(self):
        return f"{self.timestamp} - {self.get_action_display()} by {self.user}"

    @classmethod
    def log(
        cls,
        action: str,
        resource_type: str,
        resource_id: uuid.UUID | None = None,
        resource_name: str = "",
        user: User | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
        user_agent: str = ""
    ) -> "AuditLog":
        """Create an audit log entry."""
        return cls.objects.create(
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            resource_name=resource_name,
            user=user,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent
        )
