from datetime import timedelta

from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView

from core.models import AuditLog, CertificateAuthority, KeyAlgorithm
from core.services import CFSSLClient, CFSSLError


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


class CASetupView(LoginRequiredMixin, View):
    """View for initial CA setup wizard."""

    template_name = 'ca/setup.html'

    def get(self, request):
        # Redirect to dashboard if CA already exists
        if CertificateAuthority.objects.filter(is_active=True).exists():
            return redirect('core:dashboard')

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
                    ip_address=request.META.get('REMOTE_ADDR'),
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

    template_name = 'ca/detail.html'
    context_object_name = 'ca'

    def get_object(self):
        return CertificateAuthority.objects.filter(is_active=True).first()

    def get(self, request, *args, **kwargs):
        obj = self.get_object()
        if not obj:
            return redirect('core:ca_setup')
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        ca = self.object
        if ca:
            context['certificate_count'] = ca.certificates.count()
            context['active_count'] = ca.certificates.filter(status='active').count()
        return context


class CADownloadView(LoginRequiredMixin, View):
    """Download CA certificate."""

    def get(self, request):
        ca = CertificateAuthority.objects.filter(is_active=True).first()
        if not ca:
            messages.error(request, "No Certificate Authority configured.")
            return redirect('core:ca_setup')

        # Log the download
        AuditLog.log(
            action=AuditLog.Action.CERT_DOWNLOADED,
            resource_type='certificate_authority',
            resource_id=ca.id,
            resource_name=ca.name,
            user=request.user,
            details={'file_type': 'ca_certificate'},
            ip_address=request.META.get('REMOTE_ADDR'),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        filename = ca.name.replace(' ', '_').replace('/', '-') + '.crt'
        response = HttpResponse(ca.certificate_pem, content_type='application/x-pem-file')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
