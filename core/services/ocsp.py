"""
OCSP Service

Handles OCSP (Online Certificate Status Protocol) operations including:
- Creating OCSP signing certificates
- Parsing OCSP requests
- Building and signing OCSP responses
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.x509 import ocsp

from core.services.cfssl import CFSSLError, CertificateRequest, get_cfssl_client

if TYPE_CHECKING:
    from core.models import CertificateAuthority

logger = logging.getLogger(__name__)


class OCSPError(Exception):
    """Exception raised for OCSP errors."""
    pass


def create_ocsp_signing_certificate(
    ca: "CertificateAuthority",
    validity_days: int = 365,
    key_algorithm: str = "rsa",
    key_size: int = 2048
) -> dict[str, str]:
    """
    Create an OCSP signing certificate for a CA.

    This generates a new key pair and certificate specifically for signing
    OCSP responses. The certificate includes the id-kp-OCSPSigning EKU.

    Args:
        ca: The Certificate Authority to create the OCSP signer for
        validity_days: How long the OCSP certificate should be valid
        key_algorithm: Key algorithm (rsa or ecdsa)
        key_size: Key size in bits

    Returns:
        Dictionary with 'certificate' and 'private_key' PEM strings

    Raises:
        OCSPError: If creation fails
        ValueError: If CA cannot sign (no private key, expired, etc.)
    """
    if not ca.can_sign:
        raise ValueError("CA cannot sign certificates (missing key, expired, or air-gapped)")

    client = get_cfssl_client()

    # Generate OCSP signer common name
    ocsp_cn = f"OCSP Responder for {ca.common_name}"

    # Generate key pair and CSR
    request = CertificateRequest(
        common_name=ocsp_cn,
        organization=ca.organization,
        country=ca.country,
        state=ca.state,
        locality=ca.locality,
        key_algorithm=key_algorithm,
        key_size=key_size,
    )

    try:
        key_result = client.generate_key(request)
    except CFSSLError as e:
        raise OCSPError(f"Failed to generate OCSP signing key: {e}")

    # Calculate expiry in hours
    expiry_hours = validity_days * 24
    expiry = f"{expiry_hours}h"

    # Sign the CSR with the OCSP responder profile
    try:
        sign_result = client.sign_ocsp_responder(
            csr=key_result['csr'],
            ca_cert=ca.certificate_pem,
            ca_key=ca.get_private_key(),
            expiry=expiry
        )
    except CFSSLError as e:
        raise OCSPError(f"Failed to sign OCSP certificate: {e}")

    return {
        'certificate': sign_result['certificate'],
        'private_key': key_result['private_key'],
    }


def parse_ocsp_request(der_data: bytes) -> ocsp.OCSPRequest:
    """
    Parse a DER-encoded OCSP request.

    Args:
        der_data: DER-encoded OCSP request bytes

    Returns:
        Parsed OCSPRequest object

    Raises:
        OCSPError: If parsing fails
    """
    try:
        return ocsp.load_der_ocsp_request(der_data)
    except Exception as e:
        raise OCSPError(f"Invalid OCSP request: {e}")


def get_certificate_status(
    ca: "CertificateAuthority",
    serial_number: int,
) -> tuple[ocsp.OCSPCertStatus, datetime | None, x509.ReasonFlags | None, x509.Certificate | None]:
    """
    Look up the status of a certificate.

    Args:
        ca: The CA that issued the certificate
        serial_number: Certificate serial number

    Returns:
        Tuple of (status, revocation_time, revocation_reason, certificate)
        - status: GOOD, REVOKED, or UNKNOWN
        - revocation_time: When revoked (if applicable)
        - revocation_reason: Why revoked (if applicable)
        - certificate: The X.509 certificate object (if found)
    """
    from core.models import Certificate, CertificateStatus, RevocationReason

    # Convert serial number to hex string (matching our storage format)
    serial_hex = format(serial_number, 'x')

    # Look up certificate
    try:
        cert = Certificate.objects.get(
            ca=ca,
            serial_number__iexact=serial_hex
        )
    except Certificate.DoesNotExist:
        # Try with different hex format variations
        try:
            cert = Certificate.objects.get(
                ca=ca,
                serial_number__iexact=serial_hex.upper()
            )
        except Certificate.DoesNotExist:
            return (ocsp.OCSPCertStatus.UNKNOWN, None, None, None)

    # Load the X.509 certificate
    try:
        x509_cert = x509.load_pem_x509_certificate(cert.certificate_pem.encode())
    except Exception as e:
        logger.error(f"Failed to load certificate PEM: {e}")
        return (ocsp.OCSPCertStatus.UNKNOWN, None, None, None)

    # Check certificate status
    if cert.status == CertificateStatus.REVOKED:
        # Map our revocation reasons to X.509 reason flags
        reason_map = {
            RevocationReason.KEY_COMPROMISE: x509.ReasonFlags.key_compromise,
            RevocationReason.CA_COMPROMISE: x509.ReasonFlags.ca_compromise,
            RevocationReason.AFFILIATION_CHANGED: x509.ReasonFlags.affiliation_changed,
            RevocationReason.SUPERSEDED: x509.ReasonFlags.superseded,
            RevocationReason.CESSATION_OF_OPERATION: x509.ReasonFlags.cessation_of_operation,
            RevocationReason.CERTIFICATE_HOLD: x509.ReasonFlags.certificate_hold,
            RevocationReason.PRIVILEGE_WITHDRAWN: x509.ReasonFlags.privilege_withdrawn,
            RevocationReason.UNSPECIFIED: x509.ReasonFlags.unspecified,
        }
        reason = reason_map.get(cert.revocation_reason, x509.ReasonFlags.unspecified)
        revocation_time = cert.revoked_at
        if revocation_time and revocation_time.tzinfo is None:
            revocation_time = revocation_time.replace(tzinfo=timezone.utc)
        return (ocsp.OCSPCertStatus.REVOKED, revocation_time, reason, x509_cert)

    # Check if expired (still report as GOOD per RFC 6960, let client decide)
    return (ocsp.OCSPCertStatus.GOOD, None, None, x509_cert)


def build_ocsp_response(
    ca: "CertificateAuthority",
    ocsp_request: ocsp.OCSPRequest,
    this_update: datetime | None = None,
    next_update: datetime | None = None,
) -> bytes:
    """
    Build and sign an OCSP response.

    Args:
        ca: The CA to respond for
        ocsp_request: The parsed OCSP request
        this_update: When this response was generated (default: now)
        next_update: When the next update will be available (default: +1 hour)

    Returns:
        DER-encoded OCSP response

    Raises:
        OCSPError: If response generation fails
    """
    if not ca.has_ocsp_responder:
        raise OCSPError("CA does not have an OCSP responder configured")

    if ca.ocsp_is_expired:
        raise OCSPError("OCSP signing certificate has expired")

    # Load OCSP signing certificate and key
    try:
        ocsp_cert = x509.load_pem_x509_certificate(ca.ocsp_certificate_pem.encode())
        ocsp_key = load_pem_private_key(
            ca.get_ocsp_private_key().encode(),
            password=None
        )
    except Exception as e:
        raise OCSPError(f"Failed to load OCSP signing credentials: {e}")

    # Load CA certificate for the response
    ca_cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())

    # Set timestamps
    now = datetime.now(timezone.utc)
    if this_update is None:
        this_update = now
    if next_update is None:
        next_update = now + timedelta(hours=1)

    # Get certificate status and the actual certificate
    cert_status, revocation_time, revocation_reason, subject_cert = get_certificate_status(
        ca=ca,
        serial_number=ocsp_request.serial_number,
    )

    # If we don't have the certificate (UNKNOWN status), we can't build a proper response
    # Return an "unauthorized" response since we can't vouch for unknown certificates
    if subject_cert is None:
        return build_ocsp_error_response(ocsp.OCSPResponseStatus.UNAUTHORIZED)

    # Build response
    try:
        builder = ocsp.OCSPResponseBuilder()

        # Use the same hash algorithm as the request for the response
        # This ensures the CertID in response matches what the client expects
        request_hash_algo = ocsp_request.hash_algorithm
        if isinstance(request_hash_algo, hashes.SHA1):
            response_hash_algo = hashes.SHA1()
        elif isinstance(request_hash_algo, hashes.SHA256):
            response_hash_algo = hashes.SHA256()
        elif isinstance(request_hash_algo, hashes.SHA384):
            response_hash_algo = hashes.SHA384()
        elif isinstance(request_hash_algo, hashes.SHA512):
            response_hash_algo = hashes.SHA512()
        else:
            # Default to SHA1 for maximum compatibility
            response_hash_algo = hashes.SHA1()

        # Add the response for this certificate
        builder = builder.add_response(
            cert=subject_cert,
            issuer=ca_cert,
            algorithm=response_hash_algo,
            cert_status=cert_status,
            this_update=this_update,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason
        )

        # Add responder certificate identity
        builder = builder.responder_id(
            ocsp.OCSPResponderEncoding.HASH,
            ocsp_cert
        )

        # Include the OCSP responder certificate in the response
        # so clients can verify the signature
        builder = builder.certificates([ocsp_cert])

        # Sign the response
        response = builder.sign(ocsp_key, hashes.SHA256())

        return response.public_bytes(serialization.Encoding.DER)

    except Exception as e:
        logger.exception("Failed to build OCSP response")
        raise OCSPError(f"Failed to build OCSP response: {e}")


def build_ocsp_error_response(status: ocsp.OCSPResponseStatus) -> bytes:
    """
    Build an OCSP error response.

    Args:
        status: The error status (e.g., MALFORMED_REQUEST, INTERNAL_ERROR)

    Returns:
        DER-encoded OCSP error response
    """
    response = ocsp.OCSPResponseBuilder.build_unsuccessful(status)
    return response.public_bytes(serialization.Encoding.DER)
