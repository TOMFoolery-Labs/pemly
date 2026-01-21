from django.views.generic import ListView

from core.models import AuditLog
from core.permissions import CanViewAuditLogMixin


class AuditLogView(CanViewAuditLogMixin, ListView):
    """View audit logs (Managers, Auditors, and Admins only)."""

    model = AuditLog
    template_name = 'audit/list.html'
    context_object_name = 'logs'
    paginate_by = 50

    def get_queryset(self):
        queryset = AuditLog.objects.select_related('user')

        # Filter by action
        action = self.request.GET.get('action')
        if action:
            queryset = queryset.filter(action=action)

        # Filter by resource type
        resource_type = self.request.GET.get('resource_type')
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)

        # Filter by user
        user_id = self.request.GET.get('user')
        if user_id:
            queryset = queryset.filter(user_id=user_id)

        return queryset

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['actions'] = AuditLog.Action.choices
        context['resource_types'] = AuditLog.objects.values_list(
            'resource_type', flat=True
        ).distinct()
        context['current_action'] = self.request.GET.get('action', '')
        context['current_resource_type'] = self.request.GET.get('resource_type', '')
        return context
