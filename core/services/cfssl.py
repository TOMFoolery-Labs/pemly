"""
CFSSL API Client

Provides a Python interface to the CloudFlare CFSSL PKI toolkit API.
Uses HTTP API for key generation and CLI for signing operations.
"""

import json
import logging
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
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
    Uses HTTP API for key generation and CLI for signing (to support multiple CAs).
    """

    def __init__(self, base_url: str | None = None, auth_key: str | None = None):
        self.base_url = (base_url or settings.CFSSL_API_URL).rstrip('/')
        self.auth_key = auth_key or settings.CFSSL_AUTH_KEY
        self.session = requests.Session()
        if self.auth_key:
            self.session.headers['Authorization'] = f'Bearer {self.auth_key}'
        self._binary_path = None

    def _find_binary(self) -> str:
        """Find the CFSSL binary path."""
        if self._binary_path:
            return self._binary_path

        # Check if we have a configured path
        binary_path = getattr(settings, 'CFSSL_BINARY_PATH', None)
        if binary_path and Path(binary_path).is_file():
            self._binary_path = binary_path
            return self._binary_path

        # Check system PATH
        binary = shutil.which('cfssl')
        if binary:
            self._binary_path = binary
            return self._binary_path

        # Check common locations
        common_paths = [
            '/usr/local/bin/cfssl',
            '/usr/bin/cfssl',
            Path.home() / 'go' / 'bin' / 'cfssl',
        ]
        for path in common_paths:
            if Path(path).is_file():
                self._binary_path = str(path)
                return self._binary_path

        raise CFSSLError("CFSSL binary not found. Install with: brew install cfssl")

    def _run_cli(self, args: list[str], stdin: str | None = None) -> str:
        """Run a CFSSL CLI command and return stdout."""
        binary = self._find_binary()
        cmd = [binary] + args

        logger.debug(f"Running CFSSL CLI: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                raise CFSSLError(f"CFSSL CLI error: {result.stderr}")

            return result.stdout

        except subprocess.TimeoutExpired:
            raise CFSSLError("CFSSL CLI command timed out")
        except FileNotFoundError:
            raise CFSSLError(f"CFSSL binary not found at {binary}")

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
        expiry: str = "8760h",
        ocsp_url: str | None = None,
        issuer_urls: list[str] | None = None
    ) -> dict[str, str]:
        """
        Sign a CSR with the CA using the CFSSL CLI.

        Args:
            csr: PEM-encoded CSR
            ca_cert: PEM-encoded CA certificate
            ca_key: PEM-encoded CA private key
            profile: Signing profile name
            hosts: Additional hostnames/IPs for the certificate
            expiry: Certificate validity period (default 1 year)
            ocsp_url: OCSP responder URL to include in AIA extension
            issuer_urls: CA issuer URLs to include in AIA extension

        Returns:
            Dictionary with 'certificate' PEM string
        """
        # Base profile settings
        default_settings = {
            "expiry": expiry,
            "usages": [
                "signing",
                "key encipherment",
                "server auth",
                "client auth"
            ]
        }
        server_tls_settings = {
            "expiry": expiry,
            "usages": [
                "signing",
                "key encipherment",
                "server auth"
            ]
        }
        client_auth_settings = {
            "expiry": expiry,
            "usages": [
                "signing",
                "key encipherment",
                "client auth"
            ]
        }

        # Add AIA extension if OCSP URL or issuer URLs provided
        if ocsp_url:
            default_settings["ocsp_url"] = ocsp_url
            server_tls_settings["ocsp_url"] = ocsp_url
            client_auth_settings["ocsp_url"] = ocsp_url
        if issuer_urls:
            default_settings["issuer_urls"] = issuer_urls
            server_tls_settings["issuer_urls"] = issuer_urls
            client_auth_settings["issuer_urls"] = issuer_urls

        # Create config for signing profiles
        config = {
            "signing": {
                "default": default_settings,
                "profiles": {
                    "server_tls": server_tls_settings,
                    "client_auth": client_auth_settings
                }
            }
        }

        # Use temp files for CA cert, key, config, and CSR
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            ca_cert_file = tmppath / "ca.pem"
            ca_key_file = tmppath / "ca-key.pem"
            config_file = tmppath / "config.json"
            csr_file = tmppath / "csr.pem"

            ca_cert_file.write_text(ca_cert)
            ca_key_file.write_text(ca_key)
            config_file.write_text(json.dumps(config))
            csr_file.write_text(csr)

            # Build command - CSR file must come last (after all flags)
            args = [
                "sign",
                "-ca", str(ca_cert_file),
                "-ca-key", str(ca_key_file),
                "-config", str(config_file),
                "-profile", profile,
            ]

            # Add hosts if provided
            if hosts:
                args.extend(["-hostname", ",".join(hosts)])

            # CSR file must be the last argument (positional)
            args.append(str(csr_file))

            output = self._run_cli(args)

            # Parse JSON output
            try:
                result = json.loads(output)
                return {
                    'certificate': result.get('cert', ''),
                }
            except json.JSONDecodeError as e:
                raise CFSSLError(f"Failed to parse CFSSL output: {e}")

    def sign_intermediate(
        self,
        csr: str,
        ca_cert: str,
        ca_key: str,
        path_length: int = 0,
        expiry: str = "43800h"  # 5 years default
    ) -> dict[str, str]:
        """
        Sign an intermediate CA certificate using the CFSSL CLI.

        Args:
            csr: PEM-encoded CSR for the intermediate CA
            ca_cert: PEM-encoded parent CA certificate
            ca_key: PEM-encoded parent CA private key
            path_length: Maximum path length for the intermediate (0 = can only sign end-entity)
            expiry: Certificate validity period

        Returns:
            Dictionary with 'certificate' PEM string
        """
        # Create config with intermediate CA profile
        config = {
            "signing": {
                "default": {
                    "expiry": expiry,
                },
                "profiles": {
                    "intermediate_ca": {
                        "expiry": expiry,
                        "usages": [
                            "signing",
                            "key encipherment",
                            "cert sign",
                            "crl sign"
                        ],
                        "ca_constraint": {
                            "is_ca": True,
                            "max_path_len": path_length,
                            "max_path_len_zero": path_length == 0
                        }
                    }
                }
            }
        }

        # Use temp files for CA cert, key, config, and CSR
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            ca_cert_file = tmppath / "ca.pem"
            ca_key_file = tmppath / "ca-key.pem"
            config_file = tmppath / "config.json"
            csr_file = tmppath / "csr.pem"

            ca_cert_file.write_text(ca_cert)
            ca_key_file.write_text(ca_key)
            config_file.write_text(json.dumps(config))
            csr_file.write_text(csr)

            # Build command
            args = [
                "sign",
                "-ca", str(ca_cert_file),
                "-ca-key", str(ca_key_file),
                "-config", str(config_file),
                "-profile", "intermediate_ca",
                str(csr_file),
            ]

            output = self._run_cli(args)

            # Parse JSON output
            try:
                result = json.loads(output)
                return {
                    'certificate': result.get('cert', ''),
                }
            except json.JSONDecodeError as e:
                raise CFSSLError(f"Failed to parse CFSSL output: {e}")

    def sign_ocsp_responder(
        self,
        csr: str,
        ca_cert: str,
        ca_key: str,
        expiry: str = "8760h"  # 1 year default
    ) -> dict[str, str]:
        """
        Sign an OCSP responder certificate using the CFSSL CLI.

        The OCSP responder certificate is a delegated signer that can sign
        OCSP responses on behalf of the CA. It includes the id-kp-OCSPSigning
        extended key usage.

        Args:
            csr: PEM-encoded CSR for the OCSP responder
            ca_cert: PEM-encoded CA certificate
            ca_key: PEM-encoded CA private key
            expiry: Certificate validity period (default 1 year)

        Returns:
            Dictionary with 'certificate' PEM string
        """
        # Create config with OCSP responder profile
        # OID 1.3.6.1.5.5.7.3.9 = id-kp-OCSPSigning
        # OID 1.3.6.1.5.5.7.48.1.5 = id-pkix-ocsp-nocheck (OCSP No Check extension)
        config = {
            "signing": {
                "default": {
                    "expiry": expiry,
                },
                "profiles": {
                    "ocsp_responder": {
                        "expiry": expiry,
                        "usages": [
                            "digital signature",
                            "ocsp signing"
                        ],
                        "ocsp_no_check": True
                    }
                }
            }
        }

        # Use temp files for CA cert, key, config, and CSR
        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            ca_cert_file = tmppath / "ca.pem"
            ca_key_file = tmppath / "ca-key.pem"
            config_file = tmppath / "config.json"
            csr_file = tmppath / "csr.pem"

            ca_cert_file.write_text(ca_cert)
            ca_key_file.write_text(ca_key)
            config_file.write_text(json.dumps(config))
            csr_file.write_text(csr)

            # Build command
            args = [
                "sign",
                "-ca", str(ca_cert_file),
                "-ca-key", str(ca_key_file),
                "-config", str(config_file),
                "-profile", "ocsp_responder",
                str(csr_file),
            ]

            output = self._run_cli(args)

            # Parse JSON output
            try:
                result = json.loads(output)
                return {
                    'certificate': result.get('cert', ''),
                }
            except json.JSONDecodeError as e:
                raise CFSSLError(f"Failed to parse CFSSL output: {e}")

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
