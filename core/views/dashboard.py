from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.views.generic import TemplateView

from core.models import AuditLog, Certificate, CertificateAuthority, CertificateStatus


class DashboardView(LoginRequiredMixin, TemplateView):
    """Main dashboard view showing CA status and certificate overview."""

    template_name = 'dashboard/index.html'

    def get(self, request, *args, **kwargs):
        # Redirect to CA setup if no CA exists
        if not CertificateAuthority.objects.filter(is_active=True).exists():
            return redirect('core:ca_setup')
        return super().get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get active CA
        ca = CertificateAuthority.objects.filter(is_active=True).first()
        context['ca'] = ca

        if ca:
            # Certificate statistics
            certificates = Certificate.objects.filter(ca=ca)
            context['total_certificates'] = certificates.count()
            context['active_certificates'] = certificates.filter(
                status=CertificateStatus.ACTIVE
            ).count()
            context['revoked_certificates'] = certificates.filter(
                status=CertificateStatus.REVOKED
            ).count()

            # Expiring soon (within 30 days)
            from django.utils import timezone
            from datetime import timedelta
            expiry_threshold = timezone.now() + timedelta(days=30)
            context['expiring_soon'] = certificates.filter(
                status=CertificateStatus.ACTIVE,
                not_after__lte=expiry_threshold,
                not_after__gt=timezone.now()
            ).count()

            # Recent certificates
            context['recent_certificates'] = certificates[:5]

        # Recent audit logs
        context['recent_logs'] = AuditLog.objects.all()[:10]

        return context
