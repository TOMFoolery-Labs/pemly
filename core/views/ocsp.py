"""
OCSP Responder Views

Handles OCSP (Online Certificate Status Protocol) requests.
Provides real-time certificate revocation status checking.
"""

import base64
import logging
from uuid import UUID

from cryptography.x509 import ocsp
from django.http import HttpRequest, HttpResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

from core.models import CertificateAuthority
from core.services.ocsp import (
    OCSPError,
    build_ocsp_error_response,
    build_ocsp_response,
    parse_ocsp_request,
)

logger = logging.getLogger(__name__)

# OCSP Content Types
OCSP_REQUEST_CONTENT_TYPE = "application/ocsp-request"
OCSP_RESPONSE_CONTENT_TYPE = "application/ocsp-response"


@method_decorator(csrf_exempt, name='dispatch')
class OCSPResponderView(View):
    """
    OCSP Responder endpoint.

    Accepts OCSP requests via POST (DER in body) or GET (DER base64 in URL).
    Returns DER-encoded OCSP responses.

    URL pattern: /ocsp/<ca_id>/
    """

    def get(self, request: HttpRequest, ca_id: str) -> HttpResponse:
        """
        Handle GET OCSP request (base64-encoded DER in URL path).

        URL format: /ocsp/<ca_id>/<base64-encoded-request>
        """
        # The request data comes after the ca_id in the path
        # Django URL routing should capture it, but for flexibility
        # we also check the path
        path = request.path
        try:
            # Extract base64 data from URL (everything after /ocsp/<ca_id>/)
            prefix = f"/ocsp/{ca_id}/"
            if path.startswith(prefix):
                b64_data = path[len(prefix):]
                if b64_data:
                    # URL-safe base64 decode
                    b64_data = b64_data.replace('-', '+').replace('_', '/')
                    # Add padding if needed
                    padding = 4 - len(b64_data) % 4
                    if padding != 4:
                        b64_data += '=' * padding
                    der_data = base64.b64decode(b64_data)
                    return self._handle_ocsp_request(request, ca_id, der_data)
        except Exception as e:
            logger.warning(f"Failed to decode GET OCSP request: {e}")

        return self._error_response(
            ocsp.OCSPResponseStatus.MALFORMED_REQUEST,
            "Invalid GET request format"
        )

    def post(self, request: HttpRequest, ca_id: str) -> HttpResponse:
        """
        Handle POST OCSP request (DER in request body).
        """
        # Validate content type
        content_type = request.content_type
        if content_type and OCSP_REQUEST_CONTENT_TYPE not in content_type:
            logger.warning(f"Invalid OCSP content type: {content_type}")
            # Be lenient - some clients don't set the right content type

        der_data = request.body
        if not der_data:
            return self._error_response(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST,
                "Empty request body"
            )

        return self._handle_ocsp_request(request, ca_id, der_data)

    def _handle_ocsp_request(
        self,
        request: HttpRequest,
        ca_id: UUID,
        der_data: bytes
    ) -> HttpResponse:
        """
        Process an OCSP request and return a response.
        """
        # Get the CA (ca_id is already a UUID from Django's URL converter)
        try:
            ca = CertificateAuthority.objects.get(id=ca_id)
        except CertificateAuthority.DoesNotExist:
            logger.warning(f"OCSP request for unknown CA: {ca_id}")
            return self._error_response(
                ocsp.OCSPResponseStatus.UNAUTHORIZED,
                f"Unknown CA: {ca_id}"
            )

        # Check if CA has OCSP configured
        if not ca.has_ocsp_responder:
            logger.warning(f"OCSP request for CA without OCSP configured: {ca.name}")
            return self._error_response(
                ocsp.OCSPResponseStatus.UNAUTHORIZED,
                "OCSP not configured for this CA"
            )

        # Parse the OCSP request
        try:
            ocsp_request = parse_ocsp_request(der_data)
        except OCSPError as e:
            logger.warning(f"Malformed OCSP request: {e}")
            return self._error_response(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST,
                str(e)
            )

        # Build the response
        try:
            response_der = build_ocsp_response(ca, ocsp_request)

            # Log the OCSP query (without user since this is unauthenticated)
            serial_hex = format(ocsp_request.serial_number, 'x')
            logger.info(f"OCSP query for CA={ca.name}, serial={serial_hex}")

            return HttpResponse(
                response_der,
                content_type=OCSP_RESPONSE_CONTENT_TYPE
            )

        except OCSPError as e:
            logger.error(f"OCSP response error: {e}")
            return self._error_response(
                ocsp.OCSPResponseStatus.INTERNAL_ERROR,
                str(e)
            )

    def _error_response(
        self,
        status: ocsp.OCSPResponseStatus,
        message: str
    ) -> HttpResponse:
        """
        Build an OCSP error response.
        """
        logger.debug(f"OCSP error response: {status.name} - {message}")
        response_der = build_ocsp_error_response(status)
        return HttpResponse(
            response_der,
            content_type=OCSP_RESPONSE_CONTENT_TYPE
        )


# Also support URL path-based GET requests
@method_decorator(csrf_exempt, name='dispatch')
class OCSPResponderGetView(View):
    """
    Handle GET OCSP requests with the request in the URL path.

    URL format: /ocsp/<ca_id>/<base64-encoded-request>
    """

    def get(self, request: HttpRequest, ca_id: UUID, ocsp_request: str) -> HttpResponse:
        """
        Handle GET OCSP request with base64-encoded DER in URL.
        """
        try:
            # URL-safe base64 decode
            b64_data = ocsp_request.replace('-', '+').replace('_', '/')
            # Add padding if needed
            padding = 4 - len(b64_data) % 4
            if padding != 4:
                b64_data += '=' * padding
            der_data = base64.b64decode(b64_data)
        except Exception as e:
            logger.warning(f"Failed to decode GET OCSP request: {e}")
            response_der = build_ocsp_error_response(
                ocsp.OCSPResponseStatus.MALFORMED_REQUEST
            )
            return HttpResponse(
                response_der,
                content_type=OCSP_RESPONSE_CONTENT_TYPE
            )

        # Delegate to the main view
        view = OCSPResponderView()
        return view._handle_ocsp_request(request, ca_id, der_data)
