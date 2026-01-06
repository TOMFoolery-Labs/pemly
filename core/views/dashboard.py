from datetime import timedelta

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.utils import timezone
from django.views.generic import TemplateView

from core.models import AuditLog, Certificate, CertificateAuthority, CertificateStatus


class DashboardView(LoginRequiredMixin, TemplateView):
    """Main dashboard view showing CA status and certificate overview."""

    template_name = 'dashboard/index.html'

    def get(self, request, *args, **kwargs):
        # Check if CFSSL binary is available - redirect to settings if not
        if not request.session.get('cfssl_check_done'):
            try:
                from core.services import get_cfssl_manager
                manager = get_cfssl_manager()
                if not manager.find_binary():
                    request.session['cfssl_check_done'] = True
                    messages.error(
                        request,
                        "CFSSL binary not found. Please install CFSSL or configure the binary path below."
                    )
                    return redirect('core:settings')
                request.session['cfssl_check_done'] = True
            except Exception:
                pass  # If check fails, continue to dashboard

        # Redirect to CA setup if no CA exists
        if not CertificateAuthority.objects.filter(is_active=True).exists():
            return redirect('core:ca_setup')
        return super().get(request, *args, **kwargs)

    def get_all_descendant_cas(self, root_ca):
        """Get all CAs in a hierarchy (root + all intermediates)."""
        cas = [root_ca]
        children = list(CertificateAuthority.objects.filter(parent=root_ca, is_active=True))
        for child in children:
            cas.extend(self.get_all_descendant_cas(child))
        return cas

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # Get all root CAs (no parent)
        root_cas = CertificateAuthority.objects.filter(
            is_active=True,
            ca_type='root'
        ).order_by('name')
        context['root_cas'] = root_cas

        # Determine selected CA from query param or use first root
        selected_ca_id = self.request.GET.get('ca')
        if selected_ca_id:
            try:
                selected_ca = root_cas.get(pk=selected_ca_id)
            except (CertificateAuthority.DoesNotExist, ValueError):
                selected_ca = root_cas.first()
        else:
            selected_ca = root_cas.first()

        context['ca'] = selected_ca
        context['selected_ca_id'] = str(selected_ca.pk) if selected_ca else None

        if selected_ca:
            # Get all CAs in this hierarchy for statistics
            hierarchy_cas = self.get_all_descendant_cas(selected_ca)
            context['hierarchy_cas'] = hierarchy_cas

            # Certificate statistics across entire hierarchy
            certificates = Certificate.objects.filter(ca__in=hierarchy_cas)
            context['total_certificates'] = certificates.count()
            context['active_certificates'] = certificates.filter(
                status=CertificateStatus.ACTIVE
            ).count()
            context['revoked_certificates'] = certificates.filter(
                status=CertificateStatus.REVOKED
            ).count()

            # Expiring soon (within 30 days)
            expiry_threshold = timezone.now() + timedelta(days=30)
            context['expiring_soon'] = certificates.filter(
                status=CertificateStatus.ACTIVE,
                not_after__lte=expiry_threshold,
                not_after__gt=timezone.now()
            ).count()

            # Recent certificates from hierarchy
            context['recent_certificates'] = certificates.order_by('-created_at')[:5]

        # Recent audit logs
        context['recent_logs'] = AuditLog.objects.all()[:10]

        return context
