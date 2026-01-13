import json
from datetime import timedelta

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import DetailView, ListView

from core.models import (
    AuditLog,
    CAStatus,
    Certificate,
    CertificateAuthority,
    CertificateProfile,
    CertificateStatus,
    CertificateType,
    KeyAlgorithm,
    RevocationReason,
)
from core.permissions import CanManageCertificatesMixin, get_certificates_for_user
from core.services import CFSSLClient, CFSSLError
from core.services.cfssl import CertificateRequest


def get_signing_cas():
    """Get CAs that can sign certificates (have private key and are active)."""
    return CertificateAuthority.objects.filter(
        status=CAStatus.ACTIVE,
    ).exclude(
        private_key_pem_encrypted=''
    ).order_by('ca_type', 'name')


class CertificateCreateForm(forms.Form):
    """Form for creating a new certificate."""

    GENERATION_CHOICES = [
        ('generate', 'Generate key pair on server'),
        ('csr', 'Sign existing CSR'),
    ]

    # CA selection
    signing_ca = forms.UUIDField(
        help_text="Select which CA will sign this certificate"
    )

    generation_method = forms.ChoiceField(
        choices=GENERATION_CHOICES,
        initial='generate',
        widget=forms.RadioSelect,
        help_text="How to generate the certificate"
    )

    # Certificate type
    certificate_type = forms.ChoiceField(
        choices=CertificateType.choices,
        initial=CertificateType.SERVER_TLS,
        help_text="Type of certificate to issue"
    )

    # Subject information
    common_name = forms.CharField(
        max_length=255,
        help_text="The primary hostname or identifier (e.g., 'www.example.com')"
    )
    organization = forms.CharField(
        max_length=255,
        required=False,
        help_text="Organization name (optional, inherits from CA if blank)"
    )

    # SANs
    san_dns_names = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 3}),
        help_text="Additional DNS names, one per line"
    )
    san_ip_addresses = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 2}),
        help_text="IP addresses, one per line"
    )

    # Key configuration (for server-side generation)
    key_algorithm = forms.ChoiceField(
        choices=KeyAlgorithm.choices,
        initial=KeyAlgorithm.RSA,
        required=False,
    )
    key_size = forms.ChoiceField(
        choices=[
            (2048, 'RSA 2048-bit (Recommended)'),
            (4096, 'RSA 4096-bit'),
            (256, 'ECDSA P-256'),
            (384, 'ECDSA P-384'),
        ],
        initial=2048,
        required=False,
    )

    # Validity
    validity_days = forms.IntegerField(
        min_value=1,
        max_value=825,  # Maximum per CA/Browser Forum guidelines
        initial=365,
        help_text="Certificate validity in days (max 825)"
    )

    # CSR (for CSR-based generation)
    csr_pem = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'rows': 10, 'placeholder': '-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----'}),
        help_text="Paste your PEM-encoded CSR here"
    )

    def clean_san_dns_names(self):
        value = self.cleaned_data.get('san_dns_names', '')
        if not value.strip():
            return []
        return [line.strip() for line in value.split('\n') if line.strip()]

    def clean_san_ip_addresses(self):
        value = self.cleaned_data.get('san_ip_addresses', '')
        if not value.strip():
            return []
        return [line.strip() for line in value.split('\n') if line.strip()]

    def clean(self):
        cleaned_data = super().clean()
        method = cleaned_data.get('generation_method')

        if method == 'csr':
            csr = cleaned_data.get('csr_pem', '').strip()
            if not csr:
                self.add_error('csr_pem', 'CSR is required when signing an existing CSR')
            elif '-----BEGIN CERTIFICATE REQUEST-----' not in csr:
                self.add_error('csr_pem', 'Invalid CSR format. Must be PEM-encoded.')

        return cleaned_data


class CertificateListView(LoginRequiredMixin, ListView):
    """List all certificates (filtered by role)."""

    model = Certificate
    template_name = 'certificates/list.html'
    context_object_name = 'certificates'
    paginate_by = 25

    def get_queryset(self):
        # Get certificates visible to this user (role-based filtering)
        queryset = get_certificates_for_user(self.request.user).select_related('ca', 'created_by')

        # Filter archived certificates (exclude by default)
        show_archived = self.request.GET.get('show_archived', '').lower() == 'true'
        if not show_archived:
            queryset = queryset.filter(is_archived=False)

        # Filter by status
        status = self.request.GET.get('status')
        if status in [s.value for s in CertificateStatus]:
            queryset = queryset.filter(status=status)

        # Filter by type
        cert_type = self.request.GET.get('type')
        if cert_type in [t.value for t in CertificateType]:
            queryset = queryset.filter(type=cert_type)

        # Search
        search = self.request.GET.get('search', '').strip()
        if search:
            queryset = queryset.filter(common_name__icontains=search)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['statuses'] = CertificateStatus.choices
        context['types'] = CertificateType.choices
        context['current_status'] = self.request.GET.get('status', '')
        context['current_type'] = self.request.GET.get('type', '')
        context['search'] = self.request.GET.get('search', '')
        context['show_archived'] = self.request.GET.get('show_archived', '').lower() == 'true'
        return context


class CertificateCreateView(CanManageCertificatesMixin, View):
    """Create a new certificate (Certificate Managers and above only)."""

    template_name = 'certificates/create.html'

    def get(self, request):
        signing_cas = get_signing_cas()
        if not signing_cas.exists():
            messages.warning(request, "No Certificate Authority available for signing. Please set up a CA first.")
            return redirect('core:ca_setup')

        # Default to first available CA (prefer intermediates over root)
        default_ca = signing_cas.filter(ca_type='intermediate').first() or signing_cas.first()

        form = CertificateCreateForm(initial={
            'organization': default_ca.organization,
            'signing_ca': default_ca.id,
        })

        # Get all profiles for the dropdown
        profiles = CertificateProfile.objects.all()

        return render(request, self.template_name, {
            'form': form,
            'signing_cas': signing_cas,
            'selected_ca': default_ca,
            'profiles': profiles,
        })

    def post(self, request):
        signing_cas = get_signing_cas()
        if not signing_cas.exists():
            return redirect('core:ca_setup')

        form = CertificateCreateForm(request.POST)

        if form.is_valid():
            try:
                # Get the selected CA
                ca = get_object_or_404(
                    CertificateAuthority,
                    pk=form.cleaned_data['signing_ca']
                )

                # Verify the CA can sign
                if not ca.can_sign:
                    messages.error(request, "Selected CA cannot sign certificates.")
                    return render(request, self.template_name, {
                        'form': form,
                        'signing_cas': signing_cas,
                        'selected_ca': ca,
                    })

                cfssl = CFSSLClient()

                # Prepare hosts list
                hosts = [form.cleaned_data['common_name']]
                hosts.extend(form.cleaned_data['san_dns_names'])
                hosts.extend(form.cleaned_data['san_ip_addresses'])

                # Calculate expiry
                validity_hours = form.cleaned_data['validity_days'] * 24

                method = form.cleaned_data['generation_method']
                private_key = None
                csr = None

                if method == 'generate':
                    # Generate key pair
                    cert_request = CertificateRequest(
                        common_name=form.cleaned_data['common_name'],
                        organization=form.cleaned_data['organization'] or ca.organization,
                        hosts=hosts,
                        key_algorithm=form.cleaned_data['key_algorithm'],
                        key_size=int(form.cleaned_data['key_size']),
                    )
                    key_result = cfssl.generate_key(cert_request)
                    private_key = key_result['private_key']
                    csr = key_result['csr']
                else:
                    # Use provided CSR
                    csr = form.cleaned_data['csr_pem']

                # Sign the CSR
                # Determine profile based on certificate type
                cert_type = form.cleaned_data['certificate_type']
                profile_mapping = {
                    CertificateType.SERVER_TLS: 'server_tls',
                    CertificateType.CLIENT_AUTH: 'client_auth',
                    CertificateType.EMAIL_PROTECTION: 'email_protection',
                    CertificateType.DOCUMENT_SIGNING: 'document_signing',
                }
                profile = profile_mapping.get(cert_type, 'server_tls')

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
                    type=form.cleaned_data['certificate_type'],
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'] or ca.organization,
                    san_dns_names=form.cleaned_data['san_dns_names'],
                    san_ip_addresses=form.cleaned_data['san_ip_addresses'],
                    key_algorithm=form.cleaned_data.get('key_algorithm', KeyAlgorithm.RSA),
                    key_size=int(form.cleaned_data.get('key_size', 2048)),
                    validity_days=form.cleaned_data['validity_days'],
                    certificate_pem=sign_result['certificate'],
                    csr_pem=csr if method == 'csr' else '',
                    status=CertificateStatus.ACTIVE,
                    not_before=timezone.now(),
                    not_after=timezone.now() + timedelta(days=form.cleaned_data['validity_days']),
                    created_by=request.user,
                )

                if private_key:
                    certificate.set_private_key(private_key)

                # Parse certificate for serial number and exact dates
                try:
                    from cryptography import x509
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
                        'generation_method': method,
                        'validity_days': certificate.validity_days,
                        'san_dns_names': certificate.san_dns_names,
                        'san_ip_addresses': certificate.san_ip_addresses,
                        'signing_ca': ca.name,
                        'signing_ca_id': str(ca.id),
                    },
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                )

                messages.success(request, f"Certificate for '{certificate.common_name}' issued successfully!")
                return redirect('core:certificate_detail', pk=certificate.pk)

            except CFSSLError as e:
                messages.error(request, f"CFSSL Error: {e.message}")
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")

        return render(request, self.template_name, {
            'form': form,
            'signing_cas': signing_cas,
            'selected_ca': signing_cas.first(),
        })


class CertificateDetailView(LoginRequiredMixin, DetailView):
    """View certificate details."""

    model = Certificate
    template_name = 'certificates/detail.html'
    context_object_name = 'certificate'


class CertificateRevokeView(CanManageCertificatesMixin, View):
    """Revoke a certificate (Certificate Managers and above only)."""

    template_name = 'certificates/revoke.html'

    def get(self, request, pk):
        certificate = get_object_or_404(Certificate, pk=pk)

        if certificate.status == CertificateStatus.REVOKED:
            messages.warning(request, "This certificate is already revoked.")
            return redirect('core:certificate_detail', pk=pk)

        return render(request, self.template_name, {
            'certificate': certificate,
            'reasons': RevocationReason.choices,
        })

    def post(self, request, pk):
        certificate = get_object_or_404(Certificate, pk=pk)

        if certificate.status == CertificateStatus.REVOKED:
            messages.warning(request, "This certificate is already revoked.")
            return redirect('core:certificate_detail', pk=pk)

        reason = request.POST.get('reason', RevocationReason.UNSPECIFIED)

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

        # Send notification to certificate owner
        try:
            from core.services.email import send_notification
            import logging

            send_notification(
                to_user=certificate.created_by,
                notification_type='certificate_revoked',
                context={
                    'subject': f'Certificate Revoked: {certificate.common_name}',
                    'certificate': certificate,
                    'revoker': request.user,
                    'reason': certificate.get_revocation_reason_display(),
                }
            )
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send certificate revoked notification: {e}")

        messages.success(request, f"Certificate '{certificate.common_name}' has been revoked.")
        return redirect('core:certificate_detail', pk=pk)


class CertificateArchiveView(CanManageCertificatesMixin, View):
    """Archive a revoked certificate (Certificate Managers and above only)."""

    def post(self, request, pk):
        certificate = get_object_or_404(Certificate, pk=pk)

        # Check if certificate is already archived
        if certificate.is_archived:
            messages.warning(request, "This certificate is already archived.")
            return redirect('core:certificate_detail', pk=pk)

        # Archive the certificate
        try:
            certificate.archive(user=request.user)
        except ValueError as e:
            messages.error(request, str(e))
            return redirect('core:certificate_detail', pk=pk)

        # Log the archive action
        AuditLog.log(
            action=AuditLog.Action.CERT_ARCHIVED,
            resource_type='certificate',
            resource_id=certificate.id,
            resource_name=certificate.common_name,
            user=request.user,
            details={
                'serial_number': certificate.serial_number,
            },
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        messages.success(request, f"Certificate '{certificate.common_name}' has been archived.")
        return redirect('core:certificate_list')


class CertificateUnarchiveView(CanManageCertificatesMixin, View):
    """Unarchive a certificate (Certificate Managers and above only)."""

    def post(self, request, pk):
        certificate = get_object_or_404(Certificate, pk=pk)

        # Check if certificate is archived
        if not certificate.is_archived:
            messages.warning(request, "This certificate is not archived.")
            return redirect('core:certificate_detail', pk=pk)

        # Unarchive the certificate
        certificate.unarchive()

        # Log the unarchive action
        AuditLog.log(
            action=AuditLog.Action.CERT_UNARCHIVED,
            resource_type='certificate',
            resource_id=certificate.id,
            resource_name=certificate.common_name,
            user=request.user,
            details={
                'serial_number': certificate.serial_number,
            },
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        messages.success(request, f"Certificate '{certificate.common_name}' has been unarchived.")
        return redirect('core:certificate_detail', pk=pk)


class CertificateRenewView(CanManageCertificatesMixin, View):
    """Renew a certificate (Certificate Managers and above only)."""

    template_name = 'certificates/renew.html'

    def get(self, request, pk):
        # Get the certificate to renew
        old_certificate = get_object_or_404(Certificate, pk=pk)

        # Check if CA is still available and can sign
        if not old_certificate.ca.can_sign:
            messages.error(request, "The issuing CA is no longer available or cannot sign certificates.")
            return redirect('core:certificate_detail', pk=pk)

        # Check if renewing more than 30 days early
        early_renewal_warning = False
        if old_certificate.days_until_expiry and old_certificate.days_until_expiry > 30:
            early_renewal_warning = True

        # Pre-fill form with certificate data
        form = CertificateCreateForm(initial={
            'signing_ca': old_certificate.ca.id,
            'generation_method': 'generate',  # Default to generate new key
            'certificate_type': old_certificate.type,
            'common_name': old_certificate.common_name,
            'organization': old_certificate.organization,
            'san_dns_names': '\n'.join(old_certificate.san_dns_names),
            'san_ip_addresses': '\n'.join(old_certificate.san_ip_addresses),
            'key_algorithm': old_certificate.key_algorithm,
            'key_size': old_certificate.key_size,
            'validity_days': old_certificate.validity_days,
        })

        return render(request, self.template_name, {
            'form': form,
            'old_certificate': old_certificate,
            'early_renewal_warning': early_renewal_warning,
            'can_reuse_key': old_certificate.has_private_key,
        })

    def post(self, request, pk):
        old_certificate = get_object_or_404(Certificate, pk=pk)

        # Check if CA can sign
        if not old_certificate.ca.can_sign:
            messages.error(request, "The issuing CA is no longer available or cannot sign certificates.")
            return redirect('core:certificate_detail', pk=pk)

        form = CertificateCreateForm(request.POST)

        if form.is_valid():
            try:
                ca = old_certificate.ca
                cfssl = CFSSLClient()

                # Prepare hosts list
                hosts = [form.cleaned_data['common_name']]
                hosts.extend(form.cleaned_data['san_dns_names'])
                hosts.extend(form.cleaned_data['san_ip_addresses'])

                # Calculate expiry
                validity_hours = form.cleaned_data['validity_days'] * 24

                # Check if user wants to reuse key
                reuse_key = request.POST.get('reuse_key') == 'true'
                revoke_old = request.POST.get('revoke_old', 'true') == 'true'

                private_key = None
                csr = None

                if reuse_key and old_certificate.has_private_key:
                    # Reuse existing private key - generate new CSR with it
                    from cryptography.hazmat.primitives.serialization import load_pem_private_key
                    from cryptography.x509 import NameAttribute, Name, CertificateSigningRequestBuilder
                    from cryptography.hazmat.primitives.asymmetric import rsa, ec
                    from cryptography.hazmat.primitives import hashes
                    from cryptography.x509.oid import NameOID

                    old_private_key = old_certificate.get_private_key()
                    private_key = old_private_key

                    # Load the existing private key
                    loaded_key = load_pem_private_key(old_private_key.encode(), password=None)

                    # Build CSR
                    subject_attrs = [
                        NameAttribute(NameOID.COMMON_NAME, form.cleaned_data['common_name']),
                    ]
                    if form.cleaned_data['organization'] or ca.organization:
                        subject_attrs.append(
                            NameAttribute(NameOID.ORGANIZATION_NAME, form.cleaned_data['organization'] or ca.organization)
                        )

                    csr_builder = CertificateSigningRequestBuilder()
                    csr_builder = csr_builder.subject_name(Name(subject_attrs))

                    # Sign the CSR with the existing private key
                    csr_obj = csr_builder.sign(loaded_key, hashes.SHA256())

                    # Convert CSR to PEM
                    from cryptography.hazmat.primitives.serialization import Encoding
                    csr = csr_obj.public_bytes(Encoding.PEM).decode()
                else:
                    # Generate new key pair
                    cert_request = CertificateRequest(
                        common_name=form.cleaned_data['common_name'],
                        organization=form.cleaned_data['organization'] or ca.organization,
                        hosts=hosts,
                        key_algorithm=form.cleaned_data['key_algorithm'],
                        key_size=int(form.cleaned_data['key_size']),
                    )
                    key_result = cfssl.generate_key(cert_request)
                    private_key = key_result['private_key']
                    csr = key_result['csr']

                # Sign the CSR
                # Determine profile based on certificate type
                cert_type = form.cleaned_data['certificate_type']
                profile_mapping = {
                    CertificateType.SERVER_TLS: 'server_tls',
                    CertificateType.CLIENT_AUTH: 'client_auth',
                    CertificateType.EMAIL_PROTECTION: 'email_protection',
                    CertificateType.DOCUMENT_SIGNING: 'document_signing',
                }
                profile = profile_mapping.get(cert_type, 'server_tls')

                sign_result = cfssl.sign(
                    csr=csr,
                    ca_cert=ca.certificate_pem,
                    ca_key=ca.get_private_key(),
                    profile=profile,
                    hosts=hosts,
                    expiry=f"{validity_hours}h",
                    ocsp_url=ca.ocsp_responder_url if ca.ocsp_responder_url else None,
                )

                # Create new certificate record
                new_certificate = Certificate(
                    ca=ca,
                    type=form.cleaned_data['certificate_type'],
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'] or ca.organization,
                    san_dns_names=form.cleaned_data['san_dns_names'],
                    san_ip_addresses=form.cleaned_data['san_ip_addresses'],
                    key_algorithm=form.cleaned_data.get('key_algorithm', KeyAlgorithm.RSA),
                    key_size=int(form.cleaned_data.get('key_size', 2048)),
                    validity_days=form.cleaned_data['validity_days'],
                    certificate_pem=sign_result['certificate'],
                    status=CertificateStatus.ACTIVE,
                    not_before=timezone.now(),
                    not_after=timezone.now() + timedelta(days=form.cleaned_data['validity_days']),
                    created_by=request.user,
                    renewed_from=old_certificate,  # Link to old certificate
                )

                if private_key:
                    new_certificate.set_private_key(private_key)

                # Parse certificate for serial number and exact dates
                try:
                    cert = x509.load_pem_x509_certificate(sign_result['certificate'].encode())
                    new_certificate.serial_number = format(cert.serial_number, 'x')
                    new_certificate.not_before = cert.not_valid_before_utc
                    new_certificate.not_after = cert.not_valid_after_utc
                except Exception:
                    pass

                new_certificate.save()

                # Revoke old certificate if requested
                if revoke_old and old_certificate.status == CertificateStatus.ACTIVE:
                    old_certificate.revoke(reason=RevocationReason.SUPERSEDED)

                    # Refresh CRL
                    try:
                        ca.refresh_crl(force=True)
                    except Exception:
                        pass

                # Log the renewal
                AuditLog.log(
                    action=AuditLog.Action.CERT_RENEWED,
                    resource_type='certificate',
                    resource_id=new_certificate.id,
                    resource_name=new_certificate.common_name,
                    user=request.user,
                    details={
                        'renewed_from_serial': old_certificate.serial_number,
                        'renewed_from_id': str(old_certificate.id),
                        'reused_key': reuse_key,
                        'revoked_old': revoke_old,
                        'validity_days': new_certificate.validity_days,
                    },
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                )

                if revoke_old and old_certificate.status == CertificateStatus.REVOKED:
                    messages.success(request, f"Certificate renewed successfully! Old certificate has been revoked.")
                else:
                    messages.success(request, f"Certificate renewed successfully!")

                return redirect('core:certificate_detail', pk=new_certificate.pk)

            except CFSSLError as e:
                messages.error(request, f"CFSSL Error: {e.message}")
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")

        return render(request, self.template_name, {
            'form': form,
            'old_certificate': old_certificate,
            'can_reuse_key': old_certificate.has_private_key,
        })


class CertificateDownloadView(LoginRequiredMixin, View):
    """Download certificate files."""

    def get(self, request, pk, file_type):
        certificate = get_object_or_404(Certificate, pk=pk)

        # Log the download
        AuditLog.log(
            action=AuditLog.Action.CERT_DOWNLOADED,
            resource_type='certificate',
            resource_id=certificate.id,
            resource_name=certificate.common_name,
            user=request.user,
            details={'file_type': file_type},
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        filename_base = certificate.common_name.replace(' ', '_').replace('*', 'wildcard')

        if file_type == 'cert':
            content = certificate.certificate_pem
            filename = f"{filename_base}.crt"
            content_type = 'application/x-pem-file'
        elif file_type == 'key':
            if not certificate.has_private_key:
                messages.error(request, "Private key not available for this certificate.")
                return redirect('core:certificate_detail', pk=pk)
            content = certificate.get_private_key()
            filename = f"{filename_base}.key"
            content_type = 'application/x-pem-file'
        elif file_type == 'chain':
            # Full certificate chain: cert → intermediate(s) → root
            content = certificate.get_chain_pem()
            chain_depth = certificate.ca.depth + 2  # cert + CA chain
            filename = f"{filename_base}-fullchain.crt"
            content_type = 'application/x-pem-file'
        elif file_type == 'ca':
            # Full CA chain from signing CA to root
            content = certificate.ca.get_chain_pem()
            filename = "ca-chain.crt"
            content_type = 'application/x-pem-file'
        else:
            messages.error(request, "Invalid file type.")
            return redirect('core:certificate_detail', pk=pk)

        response = HttpResponse(content, content_type=content_type)
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


class CSRParseView(LoginRequiredMixin, View):
    """Parse a CSR and return subject information as JSON."""

    def post(self, request):
        try:
            data = json.loads(request.body)
            csr_pem = data.get('csr', '')

            if not csr_pem:
                return JsonResponse({'error': 'No CSR provided'}, status=400)

            # Parse the CSR
            csr = x509.load_pem_x509_csr(csr_pem.encode())

            # Extract subject attributes
            subject = csr.subject
            result = {
                'common_name': '',
                'organization': '',
                'organizational_unit': '',
                'country': '',
                'state': '',
                'locality': '',
                'dns_names': [],
                'ip_addresses': [],
            }

            # Get subject components
            for attr in subject:
                if attr.oid == x509.oid.NameOID.COMMON_NAME:
                    result['common_name'] = attr.value
                elif attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                    result['organization'] = attr.value
                elif attr.oid == x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME:
                    result['organizational_unit'] = attr.value
                elif attr.oid == x509.oid.NameOID.COUNTRY_NAME:
                    result['country'] = attr.value
                elif attr.oid == x509.oid.NameOID.STATE_OR_PROVINCE_NAME:
                    result['state'] = attr.value
                elif attr.oid == x509.oid.NameOID.LOCALITY_NAME:
                    result['locality'] = attr.value

            # Extract SANs if present
            try:
                san_ext = csr.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        result['dns_names'].append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        result['ip_addresses'].append(str(name.value))
            except x509.ExtensionNotFound:
                pass

            return JsonResponse(result)

        except ValueError as e:
            return JsonResponse({'error': f'Invalid CSR: {e}'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)
