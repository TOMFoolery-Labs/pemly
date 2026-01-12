"""
Forms for certificate request and approval workflow.
"""

from django import forms
from django.core.exceptions import ValidationError
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from core.models import PendingCertificateRequest, CertificateAuthority, CertificateType


class CertificateRequestForm(forms.ModelForm):
    """
    Form for Certificate Requesters to submit certificate signing requests.

    Requires a CSR in PEM format. Extracts subject information from the CSR
    and allows selection of CA and certificate type.
    """

    ca = forms.ModelChoiceField(
        queryset=CertificateAuthority.objects.all(),  # Will filter in __init__
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg'
        }),
        help_text="Select the CA that will sign your certificate"
    )

    type = forms.ChoiceField(
        choices=CertificateType.choices,
        initial=CertificateType.SERVER_TLS,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-select mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg'
        }),
        help_text="Type of certificate you need"
    )

    csr_pem = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg font-mono text-sm',
            'rows': 12,
            'placeholder': '-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----'
        }),
        help_text="Paste your Certificate Signing Request in PEM format",
        label="Certificate Signing Request (CSR)"
    )

    notes = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'rows': 3,
            'placeholder': 'Optional notes for the approver...'
        }),
        help_text="Optional notes to help the approver understand your request"
    )

    class Meta:
        model = PendingCertificateRequest
        fields = ['ca', 'type', 'csr_pem']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Filter to only active CAs that can sign
        self.fields['ca'].queryset = CertificateAuthority.objects.filter(
            status='active'
        ).exclude(private_key_pem_encrypted='')

    def clean_csr_pem(self):
        """Validate and parse the CSR."""
        csr_pem = self.cleaned_data.get('csr_pem', '').strip()

        if not csr_pem:
            raise ValidationError("CSR is required.")

        # Validate PEM format
        if '-----BEGIN CERTIFICATE REQUEST-----' not in csr_pem:
            raise ValidationError("Invalid CSR format. Must be in PEM format.")

        try:
            # Parse the CSR to validate it
            csr = x509.load_pem_x509_csr(csr_pem.encode(), default_backend())

            # Verify the signature
            if not csr.is_signature_valid:
                raise ValidationError("CSR signature is invalid.")

            # Extract subject information for validation
            subject = csr.subject
            cn_attrs = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)

            if not cn_attrs:
                raise ValidationError("CSR must contain a Common Name (CN).")

            # Store parsed CSR for use in save()
            self._parsed_csr = csr

        except Exception as e:
            raise ValidationError(f"Failed to parse CSR: {str(e)}")

        return csr_pem

    def clean(self):
        """Validate the form as a whole."""
        cleaned_data = super().clean()
        ca = cleaned_data.get('ca')

        # Ensure CA can sign
        if ca and not ca.can_sign:
            raise ValidationError({
                'ca': f"Selected CA '{ca.name}' cannot sign certificates (may be expired or air-gapped)."
            })

        return cleaned_data

    def save(self, commit=True, requested_by=None):
        """
        Create the pending certificate request.

        Args:
            commit: Whether to save to database
            requested_by: User submitting the request

        Returns:
            The created PendingCertificateRequest instance
        """
        request = super().save(commit=False)
        request.requested_by = requested_by

        # Extract information from the parsed CSR
        if hasattr(self, '_parsed_csr'):
            csr = self._parsed_csr
            subject = csr.subject

            # Extract common name
            cn_attrs = subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
            if cn_attrs:
                request.common_name = cn_attrs[0].value

            # Extract organization
            org_attrs = subject.get_attributes_for_oid(x509.oid.NameOID.ORGANIZATION_NAME)
            if org_attrs:
                request.organization = org_attrs[0].value

            # Extract SANs from extensions
            try:
                san_ext = csr.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                san = san_ext.value

                # Extract DNS names
                dns_names = []
                for name in san:
                    if isinstance(name, x509.DNSName):
                        dns_names.append(name.value)
                request.san_dns_names = dns_names

                # Extract IP addresses
                ip_addresses = []
                for name in san:
                    if isinstance(name, x509.IPAddress):
                        ip_addresses.append(str(name.value))
                request.san_ip_addresses = ip_addresses

                # Extract email addresses
                email_addresses = []
                for name in san:
                    if isinstance(name, x509.RFC822Name):
                        email_addresses.append(name.value)
                request.san_email_addresses = email_addresses

            except x509.ExtensionNotFound:
                # No SANs in CSR
                pass

            # Extract key information
            public_key = csr.public_key()
            if hasattr(public_key, 'key_size'):
                request.key_size = public_key.key_size
                request.key_algorithm = 'rsa'
            elif hasattr(public_key, 'curve'):
                request.key_algorithm = 'ecdsa'
                # Map curve to key size equivalent
                curve_name = public_key.curve.name
                if 'secp256r1' in curve_name or 'prime256v1' in curve_name:
                    request.key_size = 256
                elif 'secp384r1' in curve_name:
                    request.key_size = 384
                elif 'secp521r1' in curve_name:
                    request.key_size = 521

        if commit:
            request.save()

        return request


class RejectRequestForm(forms.Form):
    """Form for rejecting a certificate request."""

    rejection_reason = forms.CharField(
        required=True,
        widget=forms.Textarea(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'rows': 4,
            'placeholder': 'Please provide a reason for rejection...'
        }),
        label="Rejection Reason",
        help_text="This will be visible to the requester"
    )
