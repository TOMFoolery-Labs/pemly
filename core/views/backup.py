"""
Backup and restore views for PKI data.
"""
from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse
from django.shortcuts import redirect, render
from django.utils import timezone
from django.views import View

from core.models import AuditLog
from core.services.backup import BackupService, BackupError


class BackupForm(forms.Form):
    """Form for creating a backup."""

    include_audit_logs = forms.BooleanField(
        required=False,
        initial=False,
        help_text="Include audit log entries in the backup"
    )
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Leave empty for unencrypted backup',
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
        }),
        help_text="Optional: encrypt backup with AES-256"
    )
    confirm_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Confirm password',
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
        }),
    )

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')

        if password and password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match')

        return cleaned_data


class RestoreForm(forms.Form):
    """Form for restoring a backup."""

    backup_file = forms.FileField(
        help_text="Select a .pemly-backup file"
    )
    password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Enter password if backup is encrypted',
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
        }),
    )


class RestoreConfirmForm(forms.Form):
    """Form for confirming restore operation."""

    mode = forms.ChoiceField(
        choices=[
            ('merge', 'Merge - Add new items, skip existing'),
            ('replace', 'Replace - Delete all existing data and restore'),
        ],
        widget=forms.RadioSelect,
        initial='merge',
    )


class BackupView(LoginRequiredMixin, View):
    """Create and download PKI backups."""

    template_name = 'backup/index.html'

    def get(self, request):
        backup_form = BackupForm()
        restore_form = RestoreForm()
        return render(request, self.template_name, {
            'backup_form': backup_form,
            'restore_form': restore_form,
        })

    def post(self, request):
        backup_form = BackupForm(request.POST)

        if backup_form.is_valid():
            try:
                # Create backup
                archive = BackupService.create_backup(
                    include_audit_logs=backup_form.cleaned_data['include_audit_logs'],
                    password=backup_form.cleaned_data.get('password') or None,
                )

                # Log the backup
                AuditLog.log(
                    action=AuditLog.Action.BACKUP_CREATED,
                    resource_type='backup',
                    resource_name='PKI Backup',
                    user=request.user,
                    details={
                        'include_audit_logs': backup_form.cleaned_data['include_audit_logs'],
                        'encrypted': bool(backup_form.cleaned_data.get('password')),
                        'size_bytes': len(archive),
                    },
                    ip_address=request.META.get('REMOTE_ADDR'),
                    user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
                )

                # Return file download
                timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
                filename = f"pemly_backup_{timestamp}.pemly-backup"

                response = HttpResponse(archive, content_type='application/octet-stream')
                response['Content-Disposition'] = f'attachment; filename="{filename}"'
                return response

            except Exception as e:
                messages.error(request, f"Failed to create backup: {str(e)}")

        restore_form = RestoreForm()
        return render(request, self.template_name, {
            'backup_form': backup_form,
            'restore_form': restore_form,
        })


class RestoreUploadView(LoginRequiredMixin, View):
    """Handle backup file upload and show preview."""

    def post(self, request):
        restore_form = RestoreForm(request.POST, request.FILES)

        if restore_form.is_valid():
            try:
                backup_file = request.FILES['backup_file']
                archive = backup_file.read()
                password = restore_form.cleaned_data.get('password') or None

                # Parse and validate backup
                parsed = BackupService.parse_backup(archive, password)

                # Store in session for confirmation step
                request.session['pending_restore'] = {
                    'archive_hex': archive.hex(),  # Store as hex for JSON serialization
                    'password': password,
                }

                # Generate preview
                preview = BackupService.get_backup_preview(parsed)

                return render(request, 'backup/restore_preview.html', {
                    'preview': preview,
                    'confirm_form': RestoreConfirmForm(),
                })

            except BackupError as e:
                messages.error(request, str(e))
            except Exception as e:
                messages.error(request, f"Failed to read backup: {str(e)}")

        return redirect('core:backup')


class RestoreConfirmView(LoginRequiredMixin, View):
    """Execute the restore after confirmation."""

    def post(self, request):
        confirm_form = RestoreConfirmForm(request.POST)

        if not confirm_form.is_valid():
            messages.error(request, "Invalid form submission")
            return redirect('core:backup')

        pending = request.session.get('pending_restore')
        if not pending:
            messages.error(request, "No pending restore found. Please upload the backup file again.")
            return redirect('core:backup')

        try:
            # Recover archive from session
            archive = bytes.fromhex(pending['archive_hex'])
            password = pending.get('password')
            mode = confirm_form.cleaned_data['mode']

            # Parse and restore
            parsed = BackupService.parse_backup(archive, password)
            summary = BackupService.restore_backup(parsed, mode=mode)

            # Clear pending restore
            del request.session['pending_restore']

            # Log the restore
            AuditLog.log(
                action=AuditLog.Action.BACKUP_RESTORED,
                resource_type='backup',
                resource_name='PKI Restore',
                user=request.user,
                details={
                    'mode': mode,
                    'summary': summary,
                },
                ip_address=request.META.get('REMOTE_ADDR'),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
            )

            messages.success(
                request,
                f"Backup restored successfully! "
                f"CAs: {summary['certificate_authorities']['created']} created, "
                f"Certificates: {summary['certificates']['created']} created"
            )
            return redirect('core:dashboard')

        except BackupError as e:
            messages.error(request, str(e))
        except Exception as e:
            messages.error(request, f"Restore failed: {str(e)}")

        return redirect('core:backup')
