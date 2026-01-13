from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect, render
from django.views import View

from core.models import AppSettings


class AppSettingsForm(forms.ModelForm):
    """Form for application settings."""

    # Add password fields that don't show encrypted values
    smtp_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'Leave blank to keep existing password'
        }),
        help_text="SMTP password"
    )
    sendgrid_api_key = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'Leave blank to keep existing key'
        }),
        help_text="SendGrid API key"
    )
    mailgun_api_key = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'Leave blank to keep existing key'
        }),
        help_text="Mailgun API key"
    )
    ses_access_key_id = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'Leave blank to keep existing key'
        }),
        help_text="AWS Access Key ID"
    )
    ses_secret_access_key = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'Leave blank to keep existing key'
        }),
        help_text="AWS Secret Access Key"
    )

    class Meta:
        model = AppSettings
        fields = [
            'cfssl_auto_start',
            'cfssl_binary_path',
            'cfssl_host',
            'cfssl_port',
            # Email fields
            'email_enabled',
            'email_backend',
            'email_from_address',
            'email_from_name',
            # SMTP
            'smtp_host',
            'smtp_port',
            'smtp_username',
            'smtp_use_tls',
            'smtp_use_ssl',
            # Mailgun
            'mailgun_domain',
            'mailgun_region',
            # AWS SES
            'ses_region',
            # Notification toggles
            'notify_on_request_submitted',
            'notify_on_request_approved',
            'notify_on_request_rejected',
            'notify_on_certificate_revoked',
            'notify_expiration_warnings',
        ]
        widgets = {
            'cfssl_binary_path': forms.TextInput(attrs={
                'placeholder': 'Leave empty for auto-detection',
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            }),
            'cfssl_host': forms.TextInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            }),
            'cfssl_port': forms.NumberInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
                'min': 1,
                'max': 65535,
            }),
            'email_backend': forms.Select(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            }),
            'email_from_address': forms.EmailInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
                'placeholder': 'pki@example.com'
            }),
            'email_from_name': forms.TextInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            }),
            'smtp_host': forms.TextInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
                'placeholder': 'smtp.example.com'
            }),
            'smtp_port': forms.NumberInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            }),
            'smtp_username': forms.TextInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            }),
            'mailgun_domain': forms.TextInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
                'placeholder': 'mg.example.com'
            }),
            'ses_region': forms.TextInput(attrs={
                'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
                'placeholder': 'us-east-1'
            }),
        }

    def save(self, commit=True):
        instance = super().save(commit=False)

        # Handle encrypted fields only if new values provided
        if self.cleaned_data.get('smtp_password'):
            instance.set_smtp_password(self.cleaned_data['smtp_password'])
        if self.cleaned_data.get('sendgrid_api_key'):
            instance.set_sendgrid_api_key(self.cleaned_data['sendgrid_api_key'])
        if self.cleaned_data.get('mailgun_api_key'):
            instance.set_mailgun_api_key(self.cleaned_data['mailgun_api_key'])
        if self.cleaned_data.get('ses_access_key_id'):
            instance.set_ses_access_key_id(self.cleaned_data['ses_access_key_id'])
        if self.cleaned_data.get('ses_secret_access_key'):
            instance.set_ses_secret_access_key(self.cleaned_data['ses_secret_access_key'])

        if commit:
            instance.save()
        return instance


class SettingsView(LoginRequiredMixin, View):
    """View for managing application settings."""

    template_name = 'settings/index.html'

    def get(self, request):
        settings_obj = AppSettings.get()
        form = AppSettingsForm(instance=settings_obj)

        # Get CFSSL status
        cfssl_status = self._get_cfssl_status()

        return render(request, self.template_name, {
            'form': form,
            'settings': settings_obj,
            'cfssl_status': cfssl_status,
        })

    def post(self, request):
        settings_obj = AppSettings.get()
        form = AppSettingsForm(request.POST, instance=settings_obj)

        if form.is_valid():
            form.save()
            messages.success(request, "Settings saved successfully.")

            # Check if CFSSL action was requested
            action = request.POST.get('cfssl_action')
            if action == 'start':
                self._start_cfssl()
            elif action == 'stop':
                self._stop_cfssl()
            elif action == 'restart':
                self._restart_cfssl()

            return redirect('core:settings')

        cfssl_status = self._get_cfssl_status()
        return render(request, self.template_name, {
            'form': form,
            'settings': settings_obj,
            'cfssl_status': cfssl_status,
        })

    def _get_cfssl_status(self) -> dict:
        """Get current CFSSL status."""
        try:
            from core.services import get_cfssl_manager
            manager = get_cfssl_manager()
            status = manager.get_status()
            status['binary_found'] = manager.find_binary()
            return status
        except Exception as e:
            return {
                'running': False,
                'healthy': False,
                'error': str(e),
            }

    def _start_cfssl(self):
        """Start CFSSL server."""
        try:
            from core.services import get_cfssl_manager
            manager = get_cfssl_manager()
            if manager.start():
                messages.success(None, "CFSSL started successfully.")
            else:
                messages.error(None, "Failed to start CFSSL.")
        except Exception as e:
            messages.error(None, f"Error starting CFSSL: {e}")

    def _stop_cfssl(self):
        """Stop CFSSL server."""
        try:
            from core.services import get_cfssl_manager
            manager = get_cfssl_manager()
            manager.stop()
            messages.success(None, "CFSSL stopped.")
        except Exception as e:
            messages.error(None, f"Error stopping CFSSL: {e}")

    def _restart_cfssl(self):
        """Restart CFSSL server."""
        try:
            from core.services import get_cfssl_manager
            manager = get_cfssl_manager()
            if manager.restart():
                messages.success(None, "CFSSL restarted successfully.")
            else:
                messages.error(None, "Failed to restart CFSSL.")
        except Exception as e:
            messages.error(None, f"Error restarting CFSSL: {e}")


class CFSSLActionView(LoginRequiredMixin, View):
    """Handle CFSSL control actions via POST."""

    def post(self, request):
        action = request.POST.get('action')

        try:
            from core.services import get_cfssl_manager
            manager = get_cfssl_manager()

            if action == 'start':
                if manager.start():
                    messages.success(request, "CFSSL started successfully.")
                else:
                    messages.error(request, "Failed to start CFSSL. Check if the binary is installed.")
            elif action == 'stop':
                manager.stop()
                messages.success(request, "CFSSL stopped.")
            elif action == 'restart':
                if manager.restart():
                    messages.success(request, "CFSSL restarted successfully.")
                else:
                    messages.error(request, "Failed to restart CFSSL.")
            else:
                messages.error(request, "Invalid action.")

        except Exception as e:
            messages.error(request, f"Error: {e}")

        return redirect('core:settings')


class SendTestEmailView(LoginRequiredMixin, View):
    """Send a test email to verify email configuration."""

    def post(self, request):
        if not request.user.profile.can_manage_settings():
            raise PermissionDenied("You don't have permission to send test emails.")

        recipient = request.POST.get('recipient')
        if not recipient:
            messages.error(request, "Please provide a recipient email address.")
            return redirect('core:settings')

        try:
            from core.services.email import get_email_service
            email_service = get_email_service()

            if not email_service:
                messages.error(request, "Email notifications are disabled. Enable them first.")
                return redirect('core:settings')

            success = email_service.send_test_email(recipient)

            if success:
                messages.success(request, f"Test email sent successfully to {recipient}")
            else:
                messages.error(request, "Failed to send test email. Check logs for details.")

        except Exception as e:
            messages.error(request, f"Error sending test email: {str(e)}")

        return redirect('core:settings')
