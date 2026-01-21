"""
REST API views for certificate management.
"""

from datetime import timedelta
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, extend_schema_view, OpenApiParameter
from drf_spectacular.types import OpenApiTypes
from django.utils import timezone
from cryptography import x509

from .models import (
    Certificate, CertificateAuthority, PendingCertificateRequest, APIKey,
    AuditLog, CertificateStatus, CertificateType, KeyAlgorithm
)
from .serializers import (
    CertificateListSerializer, CertificateDetailSerializer,
    CertificateCreateSerializer, CertificateRevokeSerializer,
    CertificateAuthoritySerializer, PendingCertificateRequestSerializer,
    RequestApproveSerializer, RequestRejectSerializer,
    APIKeySerializer, APIKeyCreateSerializer
)
from .services import CFSSLClient, CFSSLError
from .services.cfssl import CertificateRequest
from .cfssl import issue_certificate_from_csr
from .permissions import (
    user_can_issue_certificates,
    user_can_revoke_certificates,
    user_can_approve_requests,
)


@extend_schema_view(
    list=extend_schema(
        summary="List all certificates",
        description="Retrieve a paginated list of all certificates",
        tags=["Certificates"]
    ),
    retrieve=extend_schema(
        summary="Get certificate details",
        description="Retrieve detailed information about a specific certificate",
        tags=["Certificates"]
    ),
    create=extend_schema(
        summary="Create a new certificate",
        description="Issue a new certificate with the specified parameters",
        tags=["Certificates"]
    ),
)
class CertificateViewSet(viewsets.ModelViewSet):
    """
    API endpoints for certificate management.

    list: Get a paginated list of all certificates
    retrieve: Get details of a specific certificate
    create: Issue a new certificate
    revoke: Revoke an active certificate
    download: Download certificate in various formats
    """
    queryset = Certificate.objects.all().select_related('ca', 'created_by')
    permission_classes = [permissions.IsAuthenticated]

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return CertificateListSerializer
        elif self.action == 'create':
            return CertificateCreateSerializer
        elif self.action == 'revoke':
            return CertificateRevokeSerializer
        return CertificateDetailSerializer

    def get_queryset(self):
        """Filter queryset based on query parameters."""
        queryset = super().get_queryset()

        # Filter by status
        status_param = self.request.query_params.get('status', None)
        if status_param:
            queryset = queryset.filter(status=status_param)

        # Filter by type
        type_param = self.request.query_params.get('type', None)
        if type_param:
            queryset = queryset.filter(type=type_param)

        # Filter by CA
        ca_param = self.request.query_params.get('ca', None)
        if ca_param:
            queryset = queryset.filter(ca_id=ca_param)

        # Search by common name
        search = self.request.query_params.get('search', None)
        if search:
            queryset = queryset.filter(common_name__icontains=search)

        return queryset

    def create(self, request, *args, **kwargs):
        """Create a new certificate."""
        # Check permissions
        if not user_can_issue_certificates(request.user):
            return Response(
                {"detail": "You do not have permission to issue certificates."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        ca = serializer.validated_data['ca']

        # Verify the CA can sign
        if not ca.can_sign:
            return Response(
                {"detail": "Selected CA cannot sign certificates."},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            cfssl = CFSSLClient()

            # Prepare hosts list
            common_name = serializer.validated_data['common_name']
            hosts = [common_name]
            hosts.extend(serializer.validated_data.get('san_dns_names', []))
            hosts.extend(serializer.validated_data.get('san_ip_addresses', []))

            # Calculate expiry
            validity_days = serializer.validated_data['validity_days']
            validity_hours = validity_days * 24

            # Generate key pair
            cert_request = CertificateRequest(
                common_name=common_name,
                organization=serializer.validated_data.get('organization', '') or ca.organization,
                hosts=hosts,
                key_algorithm=serializer.validated_data['key_algorithm'],
                key_size=serializer.validated_data['key_size'],
            )
            key_result = cfssl.generate_key(cert_request)
            private_key = key_result['private_key']
            csr = key_result['csr']

            # Determine profile based on certificate type
            cert_type = serializer.validated_data['type']
            profile_mapping = {
                CertificateType.SERVER_TLS: 'server_tls',
                CertificateType.CLIENT_AUTH: 'client_auth',
                CertificateType.EMAIL_PROTECTION: 'email_protection',
                CertificateType.DOCUMENT_SIGNING: 'document_signing',
                CertificateType.USER_AUTHENTICATION: 'user_authentication',
            }
            profile = profile_mapping.get(cert_type, 'server_tls')

            # Sign the CSR
            sign_result = cfssl.sign(
                csr=csr,
                ca_cert=ca.certificate_pem,
                ca_key=ca.get_private_key(),
                profile=profile,
                hosts=hosts,
                expiry=f"{validity_hours}h",
                ocsp_url=ca.ocsp_responder_url if ca.ocsp_responder_url else None,
            )

            # Create certificate record
            certificate = Certificate(
                ca=ca,
                type=cert_type,
                common_name=common_name,
                organization=serializer.validated_data.get('organization', '') or ca.organization,
                san_dns_names=serializer.validated_data.get('san_dns_names', []),
                san_ip_addresses=serializer.validated_data.get('san_ip_addresses', []),
                san_email_addresses=serializer.validated_data.get('san_email_addresses', []),
                key_algorithm=serializer.validated_data['key_algorithm'],
                key_size=serializer.validated_data['key_size'],
                validity_days=validity_days,
                certificate_pem=sign_result['certificate'],
                status=CertificateStatus.ACTIVE,
                not_before=timezone.now(),
                not_after=timezone.now() + timedelta(days=validity_days),
                created_by=request.user,
            )

            if private_key:
                certificate.set_private_key(private_key)

            # Parse certificate for serial number and exact dates
            try:
                cert = x509.load_pem_x509_certificate(sign_result['certificate'].encode())
                certificate.serial_number = format(cert.serial_number, 'x')
                certificate.not_before = cert.not_valid_before_utc
                certificate.not_after = cert.not_valid_after_utc
            except Exception:
                pass

            certificate.save()

            # Log the certificate issuance
            AuditLog.log(
                action=AuditLog.Action.CERT_ISSUED,
                resource_type='certificate',
                resource_id=certificate.id,
                resource_name=certificate.common_name,
                user=request.user,
                details={
                    'type': certificate.type,
                    'generation_method': 'api',
                    'validity_days': certificate.validity_days,
                    'san_dns_names': certificate.san_dns_names,
                    'san_ip_addresses': certificate.san_ip_addresses,
                    'signing_ca': ca.name,
                    'signing_ca_id': str(ca.id),
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            detail_serializer = CertificateDetailSerializer(certificate)
            return Response(detail_serializer.data, status=status.HTTP_201_CREATED)

        except CFSSLError as e:
            return Response(
                {"detail": f"CFSSL Error: {e.message}"},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {"detail": f"Failed to issue certificate: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @extend_schema(
        summary="Revoke a certificate",
        description="Revoke an active certificate with a specified reason",
        request=CertificateRevokeSerializer,
        tags=["Certificates"]
    )
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """Revoke a certificate."""
        # Check permissions
        if not user_can_revoke_certificates(request.user):
            return Response(
                {"detail": "You do not have permission to revoke certificates."},
                status=status.HTTP_403_FORBIDDEN
            )

        certificate = self.get_object()

        if certificate.status == CertificateStatus.REVOKED:
            return Response(
                {"detail": "Certificate is already revoked."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = CertificateRevokeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            reason = serializer.validated_data['reason']

            # Revoke the certificate
            certificate.revoke(reason=reason)

            # Refresh CRL to include the newly revoked certificate
            try:
                certificate.ca.refresh_crl(force=True)
            except Exception:
                # CRL refresh failure shouldn't block revocation
                pass

            # Log the revocation
            AuditLog.log(
                action=AuditLog.Action.CERT_REVOKED,
                resource_type='certificate',
                resource_id=certificate.id,
                resource_name=certificate.common_name,
                user=request.user,
                details={
                    'reason': reason,
                    'serial_number': certificate.serial_number,
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            detail_serializer = CertificateDetailSerializer(certificate)
            return Response(detail_serializer.data)

        except Exception as e:
            return Response(
                {"detail": f"Failed to revoke certificate: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @extend_schema(
        summary="Download certificate",
        description="Download certificate in various formats (pem, chain)",
        parameters=[
            OpenApiParameter(
                name='output_format',
                type=OpenApiTypes.STR,
                location=OpenApiParameter.QUERY,
                description='Download format (pem, chain)',
                required=False
            )
        ],
        tags=["Certificates"]
    )
    @action(detail=True, methods=['get'])
    def download(self, request, pk=None):
        """Download certificate in specified format."""
        certificate = self.get_object()
        # Use output_format to avoid conflict with DRF's format parameter
        format_type = request.query_params.get('output_format', 'pem')

        if format_type == 'pem':
            return Response({
                'certificate': certificate.certificate_pem,
                'format': 'pem'
            })
        elif format_type == 'chain':
            # Build certificate chain
            chain_parts = [certificate.certificate_pem]
            ca = certificate.ca
            while ca.parent_ca:
                chain_parts.append(ca.certificate_pem)
                ca = ca.parent_ca
            return Response({
                'chain': '\n'.join(chain_parts),
                'format': 'pem'
            })
        else:
            return Response(
                {"detail": f"Unsupported format: {format_type}"},
                status=status.HTTP_400_BAD_REQUEST
            )


@extend_schema_view(
    list=extend_schema(
        summary="List certificate authorities",
        description="Retrieve a list of all certificate authorities",
        tags=["Certificate Authorities"]
    ),
    retrieve=extend_schema(
        summary="Get CA details",
        description="Retrieve detailed information about a specific certificate authority",
        tags=["Certificate Authorities"]
    ),
)
class CertificateAuthorityViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoints for certificate authorities (read-only).

    list: Get a list of all certificate authorities
    retrieve: Get details of a specific certificate authority
    """
    queryset = CertificateAuthority.objects.filter(is_active=True)
    serializer_class = CertificateAuthoritySerializer
    permission_classes = [permissions.IsAuthenticated]


@extend_schema_view(
    list=extend_schema(
        summary="List pending certificate requests",
        description="Retrieve a list of pending certificate requests",
        tags=["Certificate Requests"]
    ),
    retrieve=extend_schema(
        summary="Get request details",
        description="Retrieve detailed information about a specific certificate request",
        tags=["Certificate Requests"]
    ),
    create=extend_schema(
        summary="Submit a certificate request",
        description="Submit a new certificate request for approval",
        tags=["Certificate Requests"]
    ),
)
class PendingCertificateRequestViewSet(viewsets.ModelViewSet):
    """
    API endpoints for pending certificate requests.

    list: Get a list of pending requests
    retrieve: Get details of a specific request
    create: Submit a new certificate request
    approve: Approve a pending request
    reject: Reject a pending request
    """
    queryset = PendingCertificateRequest.objects.all().select_related(
        'ca', 'requested_by', 'reviewed_by'
    )
    serializer_class = PendingCertificateRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        """Filter queryset based on permissions and parameters."""
        queryset = super().get_queryset()

        # Non-admins can only see their own requests
        if not user_can_approve_requests(self.request.user):
            queryset = queryset.filter(requested_by=self.request.user)

        # Filter by status
        status_param = self.request.query_params.get('status', None)
        if status_param:
            queryset = queryset.filter(status=status_param)

        return queryset

    def create(self, request, *args, **kwargs):
        """Submit a new certificate request."""
        if not request.user.is_authenticated:
            return Response(
                {"detail": "You do not have permission to request certificates."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Set the requesting user
        data = request.data.copy()
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)

        # Create the request
        cert_request = serializer.save(requested_by=request.user)

        return Response(
            self.get_serializer(cert_request).data,
            status=status.HTTP_201_CREATED
        )

    @extend_schema(
        summary="Approve a certificate request",
        description="Approve a pending certificate request and issue the certificate",
        request=RequestApproveSerializer,
        tags=["Certificate Requests"]
    )
    @action(detail=True, methods=['post'])
    def approve(self, request, pk=None):
        """Approve a certificate request."""
        if not user_can_approve_requests(request.user):
            return Response(
                {"detail": "You do not have permission to approve requests."},
                status=status.HTTP_403_FORBIDDEN
            )

        cert_request = self.get_object()

        if cert_request.status != 'pending':
            return Response(
                {"detail": "Only pending requests can be approved."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prevent approving own requests
        if cert_request.requested_by == request.user:
            return Response(
                {"detail": "You cannot approve your own certificate request."},
                status=status.HTTP_403_FORBIDDEN
            )

        try:
            # Issue the certificate using CFSSL
            cert_data = issue_certificate_from_csr(
                ca=cert_request.ca,
                csr_pem=cert_request.csr_pem,
                cert_type=cert_request.type,
                validity_days=cert_request.validity_days
            )

            # Create the Certificate object
            certificate = Certificate.objects.create(
                ca=cert_request.ca,
                common_name=cert_request.common_name,
                organization=cert_request.organization or cert_request.ca.organization,
                type=cert_request.type,
                key_algorithm=cert_request.key_algorithm,
                key_size=cert_request.key_size,
                san_dns_names=cert_request.san_dns_names,
                san_ip_addresses=cert_request.san_ip_addresses,
                san_email_addresses=cert_request.san_email_addresses,
                certificate_pem=cert_data['certificate'],
                serial_number=cert_data['serial_number'],
                not_before=cert_data['not_before'],
                not_after=cert_data['not_after'],
                created_by=cert_request.requested_by,  # Original requester
            )

            # Update pending request
            cert_request.status = 'issued'
            cert_request.reviewed_by = request.user
            cert_request.reviewed_at = timezone.now()
            cert_request.issued_certificate = certificate
            cert_request.save()

            # Audit log for approval
            AuditLog.log(
                action=AuditLog.Action.CERT_REQUEST_APPROVED,
                resource_type='certificate_request',
                resource_id=str(cert_request.id),
                resource_name=cert_request.common_name,
                user=request.user,
                details={
                    'requester': cert_request.requested_by.username,
                    'common_name': certificate.common_name,
                    'serial_number': certificate.serial_number,
                    'issued_certificate_id': str(certificate.id),
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            # Audit log for certificate issuance
            AuditLog.log(
                action=AuditLog.Action.CERT_ISSUED,
                resource_type='certificate',
                resource_id=str(certificate.id),
                resource_name=certificate.common_name,
                user=request.user,
                details={
                    'serial_number': certificate.serial_number,
                    'type': certificate.get_type_display(),
                    'ca': certificate.ca.name,
                    'requester': cert_request.requested_by.username,
                    'via_approval': True,
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            return Response({
                "detail": "Certificate request approved successfully.",
                "certificate_id": str(certificate.id)
            })

        except Exception as e:
            return Response(
                {"detail": f"Failed to approve request: {str(e)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

    @extend_schema(
        summary="Reject a certificate request",
        description="Reject a pending certificate request with a reason",
        request=RequestRejectSerializer,
        tags=["Certificate Requests"]
    )
    @action(detail=True, methods=['post'])
    def reject(self, request, pk=None):
        """Reject a certificate request."""
        if not user_can_approve_requests(request.user):
            return Response(
                {"detail": "You do not have permission to reject requests."},
                status=status.HTTP_403_FORBIDDEN
            )

        cert_request = self.get_object()

        if cert_request.status != 'pending':
            return Response(
                {"detail": "Only pending requests can be rejected."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = RequestRejectSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        cert_request.status = 'rejected'
        cert_request.reviewed_by = request.user
        cert_request.reviewed_at = timezone.now()
        cert_request.rejection_reason = serializer.validated_data['reason']
        cert_request.save()

        return Response({
            "detail": "Certificate request rejected successfully."
        })


@extend_schema_view(
    list=extend_schema(
        summary="List API keys",
        description="Retrieve a list of your API keys",
        tags=["API Keys"]
    ),
    create=extend_schema(
        summary="Create an API key",
        description="Generate a new API key for programmatic access",
        tags=["API Keys"]
    ),
    destroy=extend_schema(
        summary="Delete an API key",
        description="Revoke and delete an API key",
        tags=["API Keys"]
    ),
)
class APIKeyViewSet(viewsets.ModelViewSet):
    """
    API endpoints for managing API keys.

    list: Get a list of your API keys
    create: Generate a new API key
    destroy: Delete an API key
    """
    serializer_class = APIKeySerializer
    permission_classes = [permissions.IsAuthenticated]
    http_method_names = ['get', 'post', 'delete']

    def get_queryset(self):
        """Return only the current user's API keys."""
        return APIKey.objects.filter(user=self.request.user)

    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'create':
            return APIKeyCreateSerializer
        return APIKeySerializer

    def create(self, request, *args, **kwargs):
        """Create a new API key."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        api_key = serializer.save()

        # Return the full key (only shown once)
        response_data = APIKeySerializer(api_key).data
        response_data['key'] = api_key.full_key

        return Response(response_data, status=status.HTTP_201_CREATED)
