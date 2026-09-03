from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, ListView

from core.models import (
    AuditLog,
    CertificateAuthority,
    CAStatus,
    CAType,
    KeyAlgorithm,
)
from core.permissions import AdminOrSuperAdminRequiredMixin, SuperAdminRequiredMixin
from core.services import CFSSLClient, CFSSLError
from core.services.cfssl import CertificateRequest
from core.utils import get_client_ip


class CASetupForm(forms.Form):
    """Form for setting up the Certificate Authority."""

    name = forms.CharField(
        max_length=255,
        help_text="A friendly name for your CA (e.g., 'My Organization Root CA')"
    )
    common_name = forms.CharField(
        max_length=255,
        help_text="The CN for the CA certificate (e.g., 'My Organization Root CA')"
    )
    organization = forms.CharField(
        max_length=255,
        help_text="Your organization name"
    )
    organizational_unit = forms.CharField(
        max_length=255,
        required=False,
        help_text="Department or unit (optional)"
    )
    country = forms.CharField(
        max_length=2,
        help_text="Two-letter country code (e.g., 'US')"
    )
    state = forms.CharField(
        max_length=255,
        help_text="State or province"
    )
    locality = forms.CharField(
        max_length=255,
        help_text="City or locality"
    )
    key_algorithm = forms.ChoiceField(
        choices=KeyAlgorithm.choices,
        initial=KeyAlgorithm.RSA,
        help_text="Key algorithm to use"
    )
    key_size = forms.ChoiceField(
        choices=[
            (2048, 'RSA 2048-bit'),
            (4096, 'RSA 4096-bit (Recommended)'),
            (256, 'ECDSA P-256'),
            (384, 'ECDSA P-384'),
        ],
        initial=4096,
        help_text="Key size"
    )
    validity_years = forms.IntegerField(
        min_value=1,
        max_value=30,
        initial=10,
        help_text="How long the CA certificate should be valid"
    )


class CASetupView(AdminOrSuperAdminRequiredMixin, View):
    """View for initial CA setup wizard."""

    template_name = 'ca/setup.html'

    def get(self, request):
        # Check if CFSSL binary is available - redirect to settings if not
        if not request.session.get('cfssl_check_done'):
            try:
                from core.services import get_cfssl_manager
                manager = get_cfssl_manager()
                if not manager.find_binary():
                    request.session['cfssl_check_done'] = True
                    messages.error(
                        request,
                        "CFSSL binary not found. Please install CFSSL or configure the binary path before setting up a CA."
                    )
                    return redirect('core:settings')
                request.session['cfssl_check_done'] = True
            except Exception:
                pass  # If check fails, continue

        form = CASetupForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = CASetupForm(request.POST)

        if form.is_valid():
            try:
                # Initialize CFSSL client
                cfssl = CFSSLClient()

                # Check CFSSL connectivity
                if not cfssl.health_check():
                    messages.error(
                        request,
                        "Cannot connect to CFSSL server. Please ensure it is running."
                    )
                    return render(request, self.template_name, {'form': form})

                # Calculate expiry in hours
                validity_hours = form.cleaned_data['validity_years'] * 365 * 24

                # Create CA request
                from core.services.cfssl import CAInitRequest
                ca_request = CAInitRequest(
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'],
                    organizational_unit=form.cleaned_data['organizational_unit'],
                    country=form.cleaned_data['country'],
                    state=form.cleaned_data['state'],
                    locality=form.cleaned_data['locality'],
                    key_algorithm=form.cleaned_data['key_algorithm'],
                    key_size=int(form.cleaned_data['key_size']),
                    expiry=f"{validity_hours}h",
                )

                # Initialize CA via CFSSL
                result = cfssl.init_ca(ca_request)

                # Create CA record
                ca = CertificateAuthority(
                    name=form.cleaned_data['name'],
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'],
                    organizational_unit=form.cleaned_data['organizational_unit'],
                    country=form.cleaned_data['country'],
                    state=form.cleaned_data['state'],
                    locality=form.cleaned_data['locality'],
                    key_algorithm=form.cleaned_data['key_algorithm'],
                    key_size=int(form.cleaned_data['key_size']),
                    validity_years=form.cleaned_data['validity_years'],
                    certificate_pem=result['certificate'],
                    public_key_pem=result.get('csr', ''),  # CSR contains public key info
                    is_active=True,
                    not_before=timezone.now(),
                    not_after=timezone.now() + timedelta(days=365 * form.cleaned_data['validity_years']),
                    created_by=request.user,
                )
                ca.set_private_key(result['private_key'])
                ca.save()

                # Parse serial number from certificate if possible
                try:
                    from cryptography import x509
                    cert = x509.load_pem_x509_certificate(result['certificate'].encode())
                    ca.serial_number = format(cert.serial_number, 'x')
                    ca.not_before = cert.not_valid_before_utc
                    ca.not_after = cert.not_valid_after_utc
                    ca.save()
                except Exception:
                    pass  # Serial number extraction is optional

                # Log the CA creation
                AuditLog.log(
                    action=AuditLog.Action.CA_CREATED,
                    resource_type='certificate_authority',
                    resource_id=ca.id,
                    resource_name=ca.name,
                    user=request.user,
                    details={
                        'common_name': ca.common_name,
                        'organization': ca.organization,
                        'key_algorithm': ca.key_algorithm,
                        'key_size': ca.key_size,
                        'validity_years': ca.validity_years,
                    },
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                )

                messages.success(request, f"Certificate Authority '{ca.name}' created successfully!")
                return redirect('core:dashboard')

            except CFSSLError as e:
                messages.error(request, f"CFSSL Error: {e.message}")
            except ValueError as e:
                messages.error(request, str(e))
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")

        return render(request, self.template_name, {'form': form})


class CADetailView(LoginRequiredMixin, DetailView):
    """View for displaying CA details."""

    model = CertificateAuthority
    template_name = 'ca/detail.html'
    context_object_name = 'ca'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ca = self.object
        if ca:
            context['certificate_count'] = ca.certificates.count()
            context['active_count'] = ca.certificates.filter(status='active').count()
            context['child_cas'] = ca.children.all()
            context['has_active_children'] = ca.children.filter(status=CAStatus.ACTIVE).exists()
        return context


class CADownloadView(LoginRequiredMixin, View):
    """Download CA certificate or chain."""

    def get(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        # Check if chain download requested
        download_chain = request.GET.get('chain') == '1'

        # Log the download
        AuditLog.log(
            action=AuditLog.Action.CERT_DOWNLOADED,
            resource_type='certificate_authority',
            resource_id=ca.id,
            resource_name=ca.name,
            user=request.user,
            details={'file_type': 'ca_chain' if download_chain else 'ca_certificate'},
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        if download_chain:
            # Download full chain from this CA up to root
            content = ca.get_chain_pem()
            filename = ca.name.replace(' ', '_').replace('/', '-') + '_chain.crt'
        else:
            # Download just this CA's certificate
            content = ca.certificate_pem
            filename = ca.name.replace(' ', '_').replace('/', '-') + '.crt'

        response = HttpResponse(content, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


class CRLView(View):
    """
    Public endpoint to serve the Certificate Revocation List.

    No authentication required - CRLs are public by design.
    Returns DER-encoded CRL with standard content-type.
    """

    def get(self, request, pk=None):
        if pk:
            ca = get_object_or_404(CertificateAuthority, pk=pk)
        else:
            ca = CertificateAuthority.objects.filter(is_active=True).first()

        if not ca:
            return HttpResponse("No CA configured", status=404)

        try:
            # Refresh CRL if cache is invalid
            if not ca.crl_cache_valid:
                ca.refresh_crl()

            # Prefer DER format (standard for CRL distribution)
            if ca.crl_der:
                response = HttpResponse(
                    bytes(ca.crl_der),
                    content_type='application/pkix-crl'
                )
                response['Content-Disposition'] = 'inline; filename="ca.crl"'
            else:
                # Fall back to PEM if DER not available
                response = HttpResponse(
                    ca.crl_pem,
                    content_type='application/x-pem-file'
                )
                response['Content-Disposition'] = 'inline; filename="ca.crl"'

            # Cache headers
            response['Cache-Control'] = 'public, max-age=3600'  # 1 hour client cache
            return response

        except Exception as e:
            return HttpResponse(f"Error generating CRL: {e}", status=503)


class CAListView(LoginRequiredMixin, ListView):
    """List all CAs showing hierarchy."""
    model = CertificateAuthority
    template_name = 'ca/list.html'
    context_object_name = 'cas'

    def get_queryset(self):
        return CertificateAuthority.objects.select_related(
            'parent', 'created_by'
        ).order_by('ca_type', 'name')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Build tree structure for template
        root_cas = self.get_queryset().filter(parent__isnull=True)
        context['ca_tree'] = self._build_tree(root_cas)
        return context

    def _build_tree(self, cas):
        """Recursively build CA hierarchy tree."""
        tree = []
        for ca in cas:
            node = {
                'ca': ca,
                'children': self._build_tree(ca.children.all())
            }
            tree.append(node)
        return tree


class IntermediateCAForm(forms.Form):
    """Form for creating an intermediate CA."""

    name = forms.CharField(
        max_length=255,
        help_text="A friendly name for this intermediate CA"
    )
    common_name = forms.CharField(
        max_length=255,
        help_text="The CN for the intermediate CA certificate"
    )
    organization = forms.CharField(
        max_length=255,
        help_text="Your organization name"
    )
    organizational_unit = forms.CharField(
        max_length=255,
        required=False,
        help_text="Department or unit (optional)"
    )
    country = forms.CharField(
        max_length=2,
        help_text="Two-letter country code"
    )
    state = forms.CharField(
        max_length=255,
        help_text="State or province"
    )
    locality = forms.CharField(
        max_length=255,
        help_text="City or locality"
    )
    key_algorithm = forms.ChoiceField(
        choices=KeyAlgorithm.choices,
        initial=KeyAlgorithm.RSA,
        help_text="Key algorithm to use"
    )
    key_size = forms.ChoiceField(
        choices=[
            (2048, 'RSA 2048-bit'),
            (4096, 'RSA 4096-bit (Recommended)'),
            (256, 'ECDSA P-256'),
            (384, 'ECDSA P-384'),
        ],
        initial=4096,
        help_text="Key size"
    )
    validity_years = forms.IntegerField(
        min_value=1,
        max_value=20,
        initial=5,
        help_text="How long the intermediate CA certificate should be valid"
    )
    path_length = forms.IntegerField(
        min_value=0,
        max_value=5,
        initial=0,
        help_text="Maximum chain depth below this CA (0 = can only sign end-entity certificates)"
    )


class IntermediateCACreateView(AdminOrSuperAdminRequiredMixin, View):
    """Create an intermediate CA signed directly by parent."""

    template_name = 'ca/create_intermediate.html'

    def get(self, request, pk):
        parent_ca = get_object_or_404(CertificateAuthority, pk=pk)
        if not parent_ca.can_sign:
            messages.error(request, "Parent CA cannot sign (air-gapped, expired, or no private key)")
            return redirect('core:ca_detail', pk=pk)

        # Pre-populate form with parent's values
        initial = {
            'organization': parent_ca.organization,
            'organizational_unit': parent_ca.organizational_unit,
            'country': parent_ca.country,
            'state': parent_ca.state,
            'locality': parent_ca.locality,
            'key_algorithm': parent_ca.key_algorithm,
        }
        form = IntermediateCAForm(initial=initial)
        return render(request, self.template_name, {'form': form, 'parent_ca': parent_ca})

    def post(self, request, pk):
        parent_ca = get_object_or_404(CertificateAuthority, pk=pk)
        if not parent_ca.can_sign:
            messages.error(request, "Parent CA cannot sign")
            return redirect('core:ca_detail', pk=pk)

        form = IntermediateCAForm(request.POST)
        if form.is_valid():
            try:
                cfssl = CFSSLClient()

                if not cfssl.health_check():
                    messages.error(request, "Cannot connect to CFSSL server")
                    return render(request, self.template_name, {'form': form, 'parent_ca': parent_ca})

                # Generate key pair and CSR for the intermediate CA
                csr_request = CertificateRequest(
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'],
                    organizational_unit=form.cleaned_data['organizational_unit'],
                    country=form.cleaned_data['country'],
                    state=form.cleaned_data['state'],
                    locality=form.cleaned_data['locality'],
                    key_algorithm=form.cleaned_data['key_algorithm'],
                    key_size=int(form.cleaned_data['key_size']),
                )
                key_result = cfssl.generate_key(csr_request)

                # Calculate expiry in hours
                validity_hours = form.cleaned_data['validity_years'] * 365 * 24

                # Sign the CSR with the parent CA
                sign_result = cfssl.sign_intermediate(
                    csr=key_result['csr'],
                    ca_cert=parent_ca.certificate_pem,
                    ca_key=parent_ca.get_private_key(),
                    path_length=form.cleaned_data['path_length'],
                    expiry=f"{validity_hours}h",
                )

                # Create the intermediate CA record
                intermediate_ca = CertificateAuthority(
                    name=form.cleaned_data['name'],
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'],
                    organizational_unit=form.cleaned_data['organizational_unit'],
                    country=form.cleaned_data['country'],
                    state=form.cleaned_data['state'],
                    locality=form.cleaned_data['locality'],
                    ca_type=CAType.INTERMEDIATE,
                    parent=parent_ca,
                    status=CAStatus.ACTIVE,
                    path_length=form.cleaned_data['path_length'],
                    key_algorithm=form.cleaned_data['key_algorithm'],
                    key_size=int(form.cleaned_data['key_size']),
                    validity_years=form.cleaned_data['validity_years'],
                    certificate_pem=sign_result['certificate'],
                    csr_pem=key_result['csr'],
                    is_active=True,
                    created_by=request.user,
                )
                intermediate_ca.set_private_key(key_result['private_key'])

                # Parse certificate for dates and serial
                try:
                    from cryptography import x509
                    cert = x509.load_pem_x509_certificate(sign_result['certificate'].encode())
                    intermediate_ca.serial_number = format(cert.serial_number, 'x')
                    intermediate_ca.not_before = cert.not_valid_before_utc
                    intermediate_ca.not_after = cert.not_valid_after_utc
                except Exception:
                    intermediate_ca.not_before = timezone.now()
                    intermediate_ca.not_after = timezone.now() + timedelta(
                        days=365 * form.cleaned_data['validity_years']
                    )

                intermediate_ca.save()

                # Log creation
                AuditLog.log(
                    action=AuditLog.Action.INTERMEDIATE_CA_CREATED,
                    resource_type='certificate_authority',
                    resource_id=intermediate_ca.id,
                    resource_name=intermediate_ca.name,
                    user=request.user,
                    details={
                        'common_name': intermediate_ca.common_name,
                        'parent_ca_name': parent_ca.name,
                        'parent_ca_id': str(parent_ca.id),
                        'path_length': intermediate_ca.path_length,
                        'validity_years': intermediate_ca.validity_years,
                    },
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                )

                messages.success(
                    request,
                    f"Intermediate CA '{intermediate_ca.name}' created successfully!"
                )
                return redirect('core:ca_list')

            except CFSSLError as e:
                messages.error(request, f"CFSSL Error: {e.message}")
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")

        return render(request, self.template_name, {'form': form, 'parent_ca': parent_ca})


class CAKeyExportView(AdminOrSuperAdminRequiredMixin, View):
    """Export CA private key for offline storage."""

    def get(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        if not ca.has_private_key:
            messages.error(request, "No private key available (CA may be air-gapped)")
            return redirect('core:ca_detail', pk=pk)

        # Log the export
        AuditLog.log(
            action=AuditLog.Action.CA_KEY_EXPORTED,
            resource_type='certificate_authority',
            resource_id=ca.id,
            resource_name=ca.name,
            user=request.user,
            details={'action': 'private_key_export'},
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        private_key = ca.get_private_key()
        filename = ca.name.replace(' ', '_').replace('/', '-') + '_private_key.pem'
        response = HttpResponse(private_key, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


class CAKeyRemoveView(AdminOrSuperAdminRequiredMixin, View):
    """Permanently remove CA private key from database (air-gap)."""

    template_name = 'ca/remove_key.html'

    def get(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        if not ca.has_private_key:
            messages.error(request, "No private key to remove")
            return redirect('core:ca_detail', pk=pk)

        # For root CAs, check that at least one intermediate exists
        if ca.is_root and not ca.children.filter(status=CAStatus.ACTIVE).exists():
            messages.warning(
                request,
                "You should create at least one intermediate CA before air-gapping the root CA."
            )

        return render(request, self.template_name, {'ca': ca})

    def post(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        if not ca.has_private_key:
            messages.error(request, "No private key to remove")
            return redirect('core:ca_detail', pk=pk)

        # Confirmation check - user must type CA name
        confirmation = request.POST.get('confirm', '')
        if confirmation != ca.name:
            messages.error(request, "Confirmation failed. Please type the CA name exactly.")
            return render(request, self.template_name, {'ca': ca})

        try:
            # Remove the private key
            ca.remove_private_key(request.user)

            # Log the removal
            AuditLog.log(
                action=AuditLog.Action.CA_KEY_REMOVED,
                resource_type='certificate_authority',
                resource_id=ca.id,
                resource_name=ca.name,
                user=request.user,
                details={'action': 'air_gap'},
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            messages.success(
                request,
                f"Private key removed from '{ca.name}'. The CA is now air-gapped."
            )
            return redirect('core:ca_list')

        except ValueError as e:
            messages.error(request, str(e))
            return render(request, self.template_name, {'ca': ca})


class CAKeyRestoreView(AdminOrSuperAdminRequiredMixin, View):
    """Temporarily restore an air-gapped CA's private key."""

    template_name = 'ca/restore_key.html'

    def get(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        if not ca.is_air_gapped:
            messages.error(request, "This CA is not air-gapped")
            return redirect('core:ca_detail', pk=pk)

        return render(request, self.template_name, {'ca': ca})

    def post(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        if not ca.is_air_gapped:
            messages.error(request, "This CA is not air-gapped")
            return redirect('core:ca_detail', pk=pk)

        private_key_pem = request.POST.get('private_key_pem', '').strip()
        if not private_key_pem:
            messages.error(request, "Please provide the private key")
            return render(request, self.template_name, {'ca': ca})

        try:
            # Restore the private key (validates it matches the certificate)
            ca.restore_private_key(private_key_pem, request.user)

            # Log the restoration
            AuditLog.log(
                action=AuditLog.Action.CA_KEY_RESTORED,
                resource_type='certificate_authority',
                resource_id=ca.id,
                resource_name=ca.name,
                user=request.user,
                details={'action': 'key_restore'},
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            messages.success(
                request,
                f"Private key restored for '{ca.name}'. The CA can now sign certificates."
            )
            return redirect('core:ca_list')

        except ValueError as e:
            messages.error(request, str(e))
            return render(request, self.template_name, {'ca': ca})


class IntermediateCACSRView(AdminOrSuperAdminRequiredMixin, View):
    """Generate CSR for an intermediate CA to be signed offline (Administrators and Super Admins only)."""

    template_name = 'ca/create_intermediate_csr.html'

    def get(self, request, pk):
        parent_ca = get_object_or_404(CertificateAuthority, pk=pk)
        # Pre-populate form with parent's values
        initial = {
            'organization': parent_ca.organization,
            'organizational_unit': parent_ca.organizational_unit,
            'country': parent_ca.country,
            'state': parent_ca.state,
            'locality': parent_ca.locality,
            'key_algorithm': parent_ca.key_algorithm,
        }
        form = IntermediateCAForm(initial=initial)
        return render(request, self.template_name, {'form': form, 'parent_ca': parent_ca})

    def post(self, request, pk):
        parent_ca = get_object_or_404(CertificateAuthority, pk=pk)
        form = IntermediateCAForm(request.POST)

        if form.is_valid():
            try:
                cfssl = CFSSLClient()

                if not cfssl.health_check():
                    messages.error(request, "Cannot connect to CFSSL server")
                    return render(request, self.template_name, {'form': form, 'parent_ca': parent_ca})

                # Generate key pair and CSR
                csr_request = CertificateRequest(
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'],
                    organizational_unit=form.cleaned_data['organizational_unit'],
                    country=form.cleaned_data['country'],
                    state=form.cleaned_data['state'],
                    locality=form.cleaned_data['locality'],
                    key_algorithm=form.cleaned_data['key_algorithm'],
                    key_size=int(form.cleaned_data['key_size']),
                )
                key_result = cfssl.generate_key(csr_request)

                # Create pending CA record
                pending_ca = CertificateAuthority(
                    name=form.cleaned_data['name'],
                    common_name=form.cleaned_data['common_name'],
                    organization=form.cleaned_data['organization'],
                    organizational_unit=form.cleaned_data['organizational_unit'],
                    country=form.cleaned_data['country'],
                    state=form.cleaned_data['state'],
                    locality=form.cleaned_data['locality'],
                    ca_type=CAType.INTERMEDIATE,
                    parent=parent_ca,
                    status=CAStatus.PENDING,
                    path_length=form.cleaned_data['path_length'],
                    key_algorithm=form.cleaned_data['key_algorithm'],
                    key_size=int(form.cleaned_data['key_size']),
                    validity_years=form.cleaned_data['validity_years'],
                    csr_pem=key_result['csr'],
                    is_active=False,  # Not active until certificate is imported
                    created_by=request.user,
                )
                pending_ca.set_private_key(key_result['private_key'])
                pending_ca.save()

                # Log CSR generation
                AuditLog.log(
                    action=AuditLog.Action.CA_CSR_GENERATED,
                    resource_type='certificate_authority',
                    resource_id=pending_ca.id,
                    resource_name=pending_ca.name,
                    user=request.user,
                    details={
                        'common_name': pending_ca.common_name,
                        'parent_ca_name': parent_ca.name,
                        'status': 'pending',
                    },
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                )

                # Return CSR for download
                filename = pending_ca.name.replace(' ', '_').replace('/', '-') + '.csr'
                response = HttpResponse(key_result['csr'], content_type='application/pkcs10')
                response['Content-Disposition'] = f'attachment; filename="{filename}"'

                messages.info(
                    request,
                    f"CSR generated for '{pending_ca.name}'. Sign it with the parent CA's key and "
                    f"import the certificate."
                )
                return response

            except CFSSLError as e:
                messages.error(request, f"CFSSL Error: {e.message}")
            except Exception as e:
                messages.error(request, f"An error occurred: {str(e)}")

        return render(request, self.template_name, {'form': form, 'parent_ca': parent_ca})


class IntermediateCAImportView(AdminOrSuperAdminRequiredMixin, View):
    """Import an externally-signed certificate for a pending intermediate CA (Administrators and Super Admins only)."""

    template_name = 'ca/import_certificate.html'

    def get(self, request, pk):
        pending_ca = get_object_or_404(
            CertificateAuthority, pk=pk, status=CAStatus.PENDING
        )
        return render(request, self.template_name, {'ca': pending_ca})

    def post(self, request, pk):
        pending_ca = get_object_or_404(
            CertificateAuthority, pk=pk, status=CAStatus.PENDING
        )

        certificate_pem = request.POST.get('certificate_pem', '').strip()
        if not certificate_pem:
            messages.error(request, "Please provide the signed certificate")
            return render(request, self.template_name, {'ca': pending_ca})

        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            # Parse the uploaded certificate
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())

            # Validate that the certificate's public key matches our CSR
            csr = x509.load_pem_x509_csr(pending_ca.csr_pem.encode())
            cert_pub = cert.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
            csr_pub = csr.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

            if cert_pub != csr_pub:
                messages.error(
                    request,
                    "Certificate public key does not match the CSR. "
                    "Please ensure you're uploading the correct certificate."
                )
                return render(request, self.template_name, {'ca': pending_ca})

            # Validate the certificate chains to the parent
            if pending_ca.parent:
                parent_cert = x509.load_pem_x509_certificate(
                    pending_ca.parent.certificate_pem.encode()
                )
                if cert.issuer != parent_cert.subject:
                    messages.error(
                        request,
                        "Certificate was not signed by the expected parent CA."
                    )
                    return render(request, self.template_name, {'ca': pending_ca})

            # Update the CA record
            pending_ca.certificate_pem = certificate_pem
            pending_ca.serial_number = format(cert.serial_number, 'x')
            pending_ca.not_before = cert.not_valid_before_utc
            pending_ca.not_after = cert.not_valid_after_utc
            pending_ca.status = CAStatus.ACTIVE
            pending_ca.is_active = True
            pending_ca.save()

            # Log certificate import
            AuditLog.log(
                action=AuditLog.Action.CA_CERT_IMPORTED,
                resource_type='certificate_authority',
                resource_id=pending_ca.id,
                resource_name=pending_ca.name,
                user=request.user,
                details={
                    'serial_number': pending_ca.serial_number,
                    'not_before': str(pending_ca.not_before),
                    'not_after': str(pending_ca.not_after),
                },
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            messages.success(
                request,
                f"Certificate imported successfully. '{pending_ca.name}' is now active."
            )
            return redirect('core:ca_list')

        except ValueError as e:
            messages.error(request, f"Invalid certificate: {e}")
        except Exception as e:
            messages.error(request, f"Error processing certificate: {e}")

        return render(request, self.template_name, {'ca': pending_ca})


class OCSPConfigForm(forms.Form):
    """Form for configuring OCSP responder settings."""

    ocsp_responder_url = forms.URLField(
        required=False,
        help_text="URL of the OCSP responder (e.g., https://ocsp.example.com/ocsp/<ca-id>/)"
    )


class OCSPConfigView(AdminOrSuperAdminRequiredMixin, View):
    """View for configuring OCSP responder settings (Administrators and Super Admins only)."""

    template_name = 'ca/ocsp_config.html'

    def get(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)
        form = OCSPConfigForm(initial={
            'ocsp_responder_url': ca.ocsp_responder_url,
        })
        return render(request, self.template_name, {'ca': ca, 'form': form})

    def post(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)
        form = OCSPConfigForm(request.POST)

        if form.is_valid():
            ca.ocsp_responder_url = form.cleaned_data['ocsp_responder_url']
            ca.save(update_fields=['ocsp_responder_url'])

            messages.success(request, "OCSP configuration updated successfully.")
            return redirect('core:ca_detail', pk=pk)

        return render(request, self.template_name, {'ca': ca, 'form': form})


class OCSPGenerateCertView(AdminOrSuperAdminRequiredMixin, View):
    """View for generating or regenerating the OCSP signing certificate (Administrators and Super Admins only)."""

    def post(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        if not ca.can_sign:
            messages.error(
                request,
                "CA cannot sign certificates (missing key, expired, or air-gapped)"
            )
            return redirect('core:ca_ocsp_config', pk=pk)

        try:
            from core.services.ocsp import create_ocsp_signing_certificate

            # Generate OCSP signing certificate
            result = create_ocsp_signing_certificate(
                ca=ca,
                validity_days=365,  # 1 year
                key_algorithm=ca.key_algorithm,
                key_size=ca.key_size if ca.key_algorithm == 'rsa' else 256
            )

            # Save the OCSP signing certificate and key
            ca.ocsp_certificate_pem = result['certificate']
            ca.set_ocsp_private_key(result['private_key'])

            # Parse certificate for serial and dates
            try:
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(result['certificate'].encode())
                ca.ocsp_serial_number = format(cert.serial_number, 'x')
                ca.ocsp_not_before = cert.not_valid_before_utc
                ca.ocsp_not_after = cert.not_valid_after_utc
            except Exception:
                ca.ocsp_not_before = timezone.now()
                ca.ocsp_not_after = timezone.now() + timedelta(days=365)

            ca.save()

            # Log the action
            AuditLog.log(
                action=AuditLog.Action.CA_UPDATED,
                resource_type='certificate_authority',
                resource_id=ca.id,
                resource_name=ca.name,
                user=request.user,
                details={'action': 'ocsp_certificate_generated'},
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            messages.success(request, "OCSP signing certificate generated successfully.")

        except Exception as e:
            messages.error(request, f"Failed to generate OCSP certificate: {e}")

        return redirect('core:ca_ocsp_config', pk=pk)


class CADeleteView(SuperAdminRequiredMixin, View):
    """Permanently delete a Certificate Authority and all its certificates."""

    template_name = 'ca/delete.html'

    def get(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        # Get counts for display
        child_cas = ca.children.all()
        certificates_count = ca.certificates.count()
        pending_requests_count = ca.pending_requests.count()

        context = {
            'ca': ca,
            'child_cas': child_cas,
            'certificates_count': certificates_count,
            'pending_requests_count': pending_requests_count,
            'can_delete': not child_cas.exists(),
        }
        return render(request, self.template_name, context)

    def post(self, request, pk):
        ca = get_object_or_404(CertificateAuthority, pk=pk)

        # Cannot delete if has child CAs
        if ca.children.exists():
            messages.error(
                request,
                "Cannot delete this CA because it has child CAs. Delete child CAs first."
            )
            return redirect('core:ca_delete', pk=pk)

        # Confirmation check - user must type CA name
        confirmation = request.POST.get('confirm', '')
        if confirmation != ca.name:
            messages.error(request, "Confirmation failed. Please type the CA name exactly.")
            return self.get(request, pk)

        # Store info for audit log before deletion
        ca_id = ca.id
        ca_name = ca.name
        certificates_count = ca.certificates.count()
        pending_requests_count = ca.pending_requests.count()

        # Delete certificates and pending requests (cascade)
        ca.certificates.all().delete()
        ca.pending_requests.all().delete()

        # Delete the CA
        ca.delete()

        # Log the deletion
        AuditLog.log(
            action=AuditLog.Action.CA_DELETED,
            resource_type='certificate_authority',
            resource_id=ca_id,
            resource_name=ca_name,
            user=request.user,
            details={
                'certificates_deleted': certificates_count,
                'pending_requests_deleted': pending_requests_count,
            },
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        messages.success(
            request,
            f"Certificate Authority '{ca_name}' has been deleted along with "
            f"{certificates_count} certificate(s) and {pending_requests_count} pending request(s)."
        )
        return redirect('core:ca_list')
