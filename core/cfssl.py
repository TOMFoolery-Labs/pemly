"""
Helper functions for certificate issuance using CFSSL.

Provides a simplified interface to CFSSL for issuing certificates from CSRs.
"""

import logging
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from core.services.cfssl import CFSSLClient
from core.models import CertificateType

logger = logging.getLogger(__name__)


def issue_certificate_from_csr(ca, csr_pem, cert_type=CertificateType.SERVER_TLS, validity_days=365):
    """
    Issue a certificate from a CSR using the specified CA.

    Args:
        ca: CertificateAuthority instance to sign with
        csr_pem: PEM-encoded CSR string
        cert_type: Type of certificate (server_tls, client_auth, etc.)
        validity_days: Certificate validity period in days

    Returns:
        Dictionary with:
        - certificate: PEM-encoded certificate
        - serial_number: Certificate serial number (hex string)
        - not_before: Certificate start date
        - not_after: Certificate expiration date

    Raises:
        ValueError: If CA cannot sign or CSR is invalid
        Exception: If CFSSL signing fails
    """
    # Verify CA can sign
    if not ca.can_sign:
        raise ValueError(f"CA '{ca.name}' cannot sign certificates (may be expired or air-gapped)")

    # Get CA private key
    try:
        ca_key = ca.get_private_key()
    except Exception as e:
        raise ValueError(f"Failed to decrypt CA private key: {e}")

    # Map certificate type to CFSSL profile
    profile_map = {
        CertificateType.SERVER_TLS: 'server_tls',
        CertificateType.CLIENT_AUTH: 'client_auth',
        CertificateType.EMAIL_PROTECTION: 'email_protection',
        CertificateType.DOCUMENT_SIGNING: 'document_signing',
    }
    profile = profile_map.get(cert_type, 'default')

    # Calculate expiry in hours for CFSSL
    expiry = f"{validity_days * 24}h"

    # Get OCSP URL if configured
    ocsp_url = ca.ocsp_responder_url if ca.has_ocsp_responder else None

    # Sign the CSR using CFSSL
    cfssl = CFSSLClient()
    result = cfssl.sign(
        csr=csr_pem,
        ca_cert=ca.certificate_pem,
        ca_key=ca_key,
        profile=profile,
        expiry=expiry,
        ocsp_url=ocsp_url
    )

    # Parse the issued certificate to extract metadata
    cert_pem = result['certificate']
    cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())

    # Extract serial number and validity dates
    serial_number = format(cert.serial_number, 'x').upper()
    not_before = cert.not_valid_before_utc.replace(tzinfo=timezone.utc)
    not_after = cert.not_valid_after_utc.replace(tzinfo=timezone.utc)

    return {
        'certificate': cert_pem,
        'serial_number': serial_number,
        'not_before': not_before,
        'not_after': not_after,
    }
