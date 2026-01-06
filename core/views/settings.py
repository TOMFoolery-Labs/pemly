from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect, render
from django.views import View

from core.models import AppSettings


class AppSettingsForm(forms.ModelForm):
    """Form for application settings."""

    class Meta:
        model = AppSettings
        fields = [
            'cfssl_auto_start',
            'cfssl_binary_path',
            'cfssl_host',
            'cfssl_port',
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
        }


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
