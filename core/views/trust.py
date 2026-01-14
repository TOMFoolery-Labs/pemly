"""
Public Trust Portal Views

Public-facing views for CA certificate distribution and device trust.
No authentication required - these are public by design.
"""

import base64
import io
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404, render
from django.views import View

from core.models import CertificateAuthority, CAStatus


class TrustPortalView(View):
    """
    Public trust portal for CA certificate distribution.

    Shows CA information with device-specific installation instructions
    and download options.
    """

    template_name = 'trust/portal.html'

    def get(self, request: HttpRequest, pk) -> HttpResponse:
        # Only show active CAs (not pending, revoked, etc.)
        ca = get_object_or_404(
            CertificateAuthority,
            pk=pk,
            status__in=[CAStatus.ACTIVE, CAStatus.AIR_GAPPED]
        )

        # Detect device type from User-Agent
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        device_type = self._detect_device(user_agent)

        # Generate QR code data URL for the current page
        current_url = request.build_absolute_uri()
        qr_data_url = self._generate_qr_code(current_url)

        # Get certificate fingerprints for verification
        fingerprints = self._get_fingerprints(ca)

        context = {
            'ca': ca,
            'device_type': device_type,
            'qr_data_url': qr_data_url,
            'current_url': current_url,
            'fingerprints': fingerprints,
            'has_chain': ca.parent is not None,
        }

        return render(request, self.template_name, context)

    def _detect_device(self, user_agent: str) -> str:
        """Detect device type from User-Agent string."""
        if 'iphone' in user_agent or 'ipad' in user_agent:
            return 'ios'
        elif 'android' in user_agent:
            return 'android'
        elif 'mac os' in user_agent or 'macintosh' in user_agent:
            return 'macos'
        elif 'windows' in user_agent:
            return 'windows'
        elif 'linux' in user_agent:
            return 'linux'
        return 'desktop'

    def _generate_qr_code(self, url: str) -> Optional[str]:
        """Generate QR code as base64 data URL."""
        try:
            import qrcode
            from qrcode.image.pure import PyPNGImage

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=2,
            )
            qr.add_data(url)
            qr.make(fit=True)

            img = qr.make_image(image_factory=PyPNGImage)
            buffer = io.BytesIO()
            img.save(buffer)
            buffer.seek(0)

            b64 = base64.b64encode(buffer.getvalue()).decode()
            return f"data:image/png;base64,{b64}"
        except ImportError:
            # qrcode library not installed
            return None

    def _get_fingerprints(self, ca: CertificateAuthority) -> dict:
        """Get certificate fingerprints for user verification."""
        try:
            cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())

            sha256 = cert.fingerprint(hashes.SHA256()).hex().upper()
            sha1 = cert.fingerprint(hashes.SHA1()).hex().upper()

            # Format with colons for readability
            sha256_formatted = ':'.join(sha256[i:i+2] for i in range(0, len(sha256), 2))
            sha1_formatted = ':'.join(sha1[i:i+2] for i in range(0, len(sha1), 2))

            return {
                'sha256': sha256_formatted,
                'sha1': sha1_formatted,
            }
        except Exception:
            return {}


class TrustPortalDownloadView(View):
    """
    Download CA certificate in various formats.

    Supports:
    - DER format (.cer) - universal, works on iOS/Android/Windows
    - PEM format (.crt/.pem) - for Linux/macOS/servers
    - Full chain option for both formats
    """

    def get(self, request: HttpRequest, pk, format: str) -> HttpResponse:
        ca = get_object_or_404(
            CertificateAuthority,
            pk=pk,
            status__in=[CAStatus.ACTIVE, CAStatus.AIR_GAPPED]
        )

        # Check if chain download requested
        include_chain = request.GET.get('chain') == '1'

        # Sanitize CA name for filename
        safe_name = ca.name.replace(' ', '_').replace('/', '-').replace('\\', '-')

        if format == 'der':
            return self._download_der(ca, safe_name, include_chain)
        elif format == 'pem':
            return self._download_pem(ca, safe_name, include_chain)
        else:
            return HttpResponse("Invalid format", status=400)

    def _download_der(
        self,
        ca: CertificateAuthority,
        safe_name: str,
        include_chain: bool
    ) -> HttpResponse:
        """Download in DER format (.cer)."""
        cert = x509.load_pem_x509_certificate(ca.certificate_pem.encode())
        der_data = cert.public_bytes(Encoding.DER)

        # Note: For chain downloads, DER format only returns the single cert
        # as DER doesn't support concatenation like PEM does
        suffix = '_chain' if include_chain else ''
        filename = f"{safe_name}{suffix}.cer"

        response = HttpResponse(der_data, content_type='application/x-x509-ca-cert')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    def _download_pem(
        self,
        ca: CertificateAuthority,
        safe_name: str,
        include_chain: bool
    ) -> HttpResponse:
        """Download in PEM format (.crt)."""
        if include_chain:
            content = ca.get_chain_pem()
            suffix = '_chain'
        else:
            content = ca.certificate_pem
            suffix = ''

        filename = f"{safe_name}{suffix}.crt"

        response = HttpResponse(content, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
