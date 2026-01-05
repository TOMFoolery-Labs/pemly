from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import redirect, render
from django.views import View

from core.models import AuditLog


def get_client_ip(request) -> str | None:
    """Extract client IP from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        return x_forwarded_for.split(',')[0].strip()
    return request.META.get('REMOTE_ADDR')


class LoginView(View):
    """User login view."""

    template_name = 'accounts/login.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('core:dashboard')
        form = AuthenticationForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)

            # Log the login
            AuditLog.log(
                action=AuditLog.Action.USER_LOGIN,
                resource_type='user',
                resource_name=user.username,
                user=user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )

            return redirect('core:dashboard')

        return render(request, self.template_name, {'form': form})


class LogoutView(View):
    """User logout view."""

    def get(self, request):
        return self.post(request)

    def post(self, request):
        if request.user.is_authenticated:
            # Log the logout before we lose the user
            AuditLog.log(
                action=AuditLog.Action.USER_LOGOUT,
                resource_type='user',
                resource_name=request.user.username,
                user=request.user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )
            logout(request)

        return redirect('accounts:login')
