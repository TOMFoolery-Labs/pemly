"""
CFSSL API Client

Provides a Python interface to the CloudFlare CFSSL PKI toolkit API.
"""

import logging
from dataclasses import dataclass
from typing import Any

import requests
from django.conf import settings

logger = logging.getLogger(__name__)


class CFSSLError(Exception):
    """Exception raised for CFSSL API errors."""

    def __init__(self, message: str, code: int | None = None, errors: list | None = None):
        self.message = message
        self.code = code
        self.errors = errors or []
        super().__init__(self.message)


@dataclass
class CAInitRequest:
    """Request parameters for initializing a CA."""
    common_name: str
    organization: str
    organizational_unit: str = ""
    country: str = ""
    state: str = ""
    locality: str = ""
    key_algorithm: str = "rsa"
    key_size: int = 4096
    expiry: str = "87600h"  # 10 years


@dataclass
class CertificateRequest:
    """Request parameters for generating a certificate."""
    common_name: str
    organization: str = ""
    organizational_unit: str = ""
    country: str = ""
    state: str = ""
    locality: str = ""
    hosts: list[str] | None = None
    key_algorithm: str = "rsa"
    key_size: int = 2048


@dataclass
class SignRequest:
    """Request parameters for signing a CSR."""
    csr: str
    profile: str = "default"
    hosts: list[str] | None = None


class CFSSLClient:
    """
    Client for CFSSL API communication.

    Provides methods to initialize CAs, generate keys, sign CSRs, and revoke certificates.
    """

    def __init__(self, base_url: str | None = None, auth_key: str | None = None):
        self.base_url = (base_url or settings.CFSSL_API_URL).rstrip('/')
        self.auth_key = auth_key or settings.CFSSL_AUTH_KEY
        self.session = requests.Session()
        if self.auth_key:
            self.session.headers['Authorization'] = f'Bearer {self.auth_key}'

    def _request(self, endpoint: str, data: dict | None = None) -> dict:
        """Make a request to the CFSSL API."""
        url = f"{self.base_url}/api/v1/cfssl/{endpoint}"
        logger.debug(f"CFSSL request to {endpoint}: {data}")

        try:
            response = self.session.post(url, json=data or {}, timeout=30)
            response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            raise CFSSLError(f"Cannot connect to CFSSL server at {self.base_url}: {e}")
        except requests.exceptions.Timeout:
            raise CFSSLError("CFSSL request timed out")
        except requests.exceptions.HTTPError as e:
            raise CFSSLError(f"CFSSL HTTP error: {e}")

        result = response.json()
        logger.debug(f"CFSSL response: {result}")

        if not result.get('success', False):
            errors = result.get('errors', [])
            error_msgs = [e.get('message', str(e)) for e in errors]
            raise CFSSLError(
                f"CFSSL error: {'; '.join(error_msgs)}",
                errors=errors
            )

        return result.get('result', {})

    def health_check(self) -> bool:
        """Check if CFSSL server is available."""
        try:
            url = f"{self.base_url}/api/v1/cfssl/health"
            response = self.session.get(url, timeout=5)
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False

    def init_ca(self, request: CAInitRequest) -> dict[str, str]:
        """
        Initialize a new Certificate Authority.

        Args:
            request: CA initialization parameters

        Returns:
            Dictionary with 'certificate', 'private_key', and 'csr' PEM strings
        """
        # Build the CSR request
        names = [{
            "C": request.country,
            "ST": request.state,
            "L": request.locality,
            "O": request.organization,
        }]
        if request.organizational_unit:
            names[0]["OU"] = request.organizational_unit

        # Filter out empty values
        names[0] = {k: v for k, v in names[0].items() if v}

        data = {
            "CN": request.common_name,
            "names": names,
            "key": {
                "algo": request.key_algorithm,
                "size": request.key_size,
            },
            "ca": {
                "expiry": request.expiry,
            }
        }

        result = self._request("init_ca", data)

        return {
            'certificate': result.get('certificate', ''),
            'private_key': result.get('private_key', ''),
            'csr': result.get('csr', ''),
        }

    def generate_key(self, request: CertificateRequest) -> dict[str, str]:
        """
        Generate a new key pair and CSR.

        Args:
            request: Certificate request parameters

        Returns:
            Dictionary with 'private_key' and 'csr' PEM strings
        """
        names = [{
            "C": request.country,
            "ST": request.state,
            "L": request.locality,
            "O": request.organization,
        }]
        if request.organizational_unit:
            names[0]["OU"] = request.organizational_unit

        # Filter out empty values
        names[0] = {k: v for k, v in names[0].items() if v}

        data = {
            "CN": request.common_name,
            "names": names if names[0] else [],
            "hosts": request.hosts or [],
            "key": {
                "algo": request.key_algorithm,
                "size": request.key_size,
            }
        }

        result = self._request("newkey", data)

        return {
            'private_key': result.get('private_key', ''),
            'csr': result.get('certificate_request', ''),
        }

    def sign(
        self,
        csr: str,
        ca_cert: str,
        ca_key: str,
        profile: str = "default",
        hosts: list[str] | None = None,
        expiry: str = "8760h"
    ) -> dict[str, str]:
        """
        Sign a CSR with the CA.

        Args:
            csr: PEM-encoded CSR
            ca_cert: PEM-encoded CA certificate
            ca_key: PEM-encoded CA private key
            profile: Signing profile name
            hosts: Additional hostnames/IPs for the certificate
            expiry: Certificate validity period (default 1 year)

        Returns:
            Dictionary with 'certificate' PEM string
        """
        data = {
            "certificate_request": csr,
            "profile": profile,
            "hosts": hosts or [],
        }

        # Include CA certificate and key for signing
        # CFSSL needs these to sign the certificate
        data["ca"] = ca_cert
        data["ca_key"] = ca_key

        # Custom config with expiry
        data["config"] = {
            "signing": {
                "default": {
                    "expiry": expiry,
                    "usages": [
                        "signing",
                        "key encipherment",
                        "server auth",
                        "client auth"
                    ]
                },
                "profiles": {
                    "server_tls": {
                        "expiry": expiry,
                        "usages": [
                            "signing",
                            "key encipherment",
                            "server auth"
                        ]
                    },
                    "client_auth": {
                        "expiry": expiry,
                        "usages": [
                            "signing",
                            "key encipherment",
                            "client auth"
                        ]
                    }
                }
            }
        }

        result = self._request("sign", data)

        return {
            'certificate': result.get('certificate', ''),
        }

    def info(self, label: str = "") -> dict[str, Any]:
        """
        Get information about the CA.

        Args:
            label: Optional CA label

        Returns:
            Dictionary with CA information
        """
        data = {"label": label} if label else {}
        return self._request("info", data)

    def revoke(
        self,
        serial: str,
        authority_key_id: str,
        reason: str = "unspecified"
    ) -> dict:
        """
        Revoke a certificate.

        Args:
            serial: Certificate serial number
            authority_key_id: Authority key identifier
            reason: Revocation reason

        Returns:
            Empty dict on success
        """
        data = {
            "serial": serial,
            "authority_key_id": authority_key_id,
            "reason": reason,
        }

        return self._request("revoke", data)

    def get_crl(self) -> bytes:
        """
        Get the Certificate Revocation List.

        Returns:
            CRL in PEM format
        """
        url = f"{self.base_url}/api/v1/cfssl/crl"
        try:
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            result = response.json()
            if result.get('success'):
                return result.get('result', '').encode()
            raise CFSSLError("Failed to get CRL")
        except requests.exceptions.RequestException as e:
            raise CFSSLError(f"Failed to get CRL: {e}")


def get_cfssl_client() -> CFSSLClient:
    """Get a configured CFSSL client instance."""
    return CFSSLClient()
