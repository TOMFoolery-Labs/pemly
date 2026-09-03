"""
Views for API key management.
"""

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import ListView

from core.models import APIKey, AuditLog
from core.authentication import generate_api_key
from core.utils import get_client_ip


class APIKeyListView(LoginRequiredMixin, ListView):
    """List user's API keys."""

    model = APIKey
    template_name = 'api_keys/list.html'
    context_object_name = 'api_keys'

    def get_queryset(self):
        """Return only the current user's API keys."""
        return APIKey.objects.filter(user=self.request.user).order_by('-created_at')


class APIKeyCreateView(LoginRequiredMixin, View):
    """Create a new API key."""

    template_name = 'api_keys/create.html'

    def get(self, request):
        """Show API key creation form."""
        return render(request, self.template_name)

    def post(self, request):
        """Generate a new API key."""
        name = request.POST.get('name', '').strip()

        if not name:
            messages.error(request, "API key name is required.")
            return render(request, self.template_name)

        # Generate API key
        full_key, prefix, hashed_key = generate_api_key()

        # Create API key object
        api_key = APIKey.objects.create(
            name=name,
            prefix=prefix,
            hashed_key=hashed_key,
            user=request.user,
            expires_at=None  # Could add expiration date from form
        )

        # Log the creation
        AuditLog.log(
            action=AuditLog.Action.API_KEY_CREATED,
            resource_type='api_key',
            resource_id=str(api_key.id),
            resource_name=api_key.name,
            user=request.user,
            details={
                'prefix': prefix,
            },
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        # Show the full key (only time it's visible)
        return render(request, 'api_keys/created.html', {
            'api_key': api_key,
            'full_key': full_key,
        })


class APIKeyDeleteView(LoginRequiredMixin, View):
    """Delete an API key."""

    def post(self, request, pk):
        """Delete the API key."""
        api_key = get_object_or_404(APIKey, pk=pk, user=request.user)

        # Log the deletion
        AuditLog.log(
            action=AuditLog.Action.API_KEY_DELETED,
            resource_type='api_key',
            resource_id=str(api_key.id),
            resource_name=api_key.name,
            user=request.user,
            details={
                'prefix': api_key.prefix,
            },
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        )

        api_key.delete()

        messages.success(request, f"API key '{api_key.name}' has been deleted.")
        return redirect('core:api_key_list')
