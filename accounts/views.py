from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login, logout, update_session_auth_hash
from django.contrib.auth.forms import AuthenticationForm
from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse_lazy
from django.views import View
from django.views.generic import DeleteView, ListView

from accounts.forms import UserCreateForm, UserEditForm
from accounts.models import UserProfile
from accounts.throttling import is_throttled, record_blocked
from core.models import AuditLog
from core.utils import get_client_ip
from core.permissions import SuperAdminRequiredMixin


class LoginView(View):
    """User login view."""

    template_name = 'accounts/login.html'

    def get(self, request):
        if request.user.is_authenticated:
            return redirect('core:dashboard')
        form = AuthenticationForm()
        return render(request, self.template_name, {'form': form})

    def post(self, request):
        # Enforcement is in accounts.backends.ThrottledModelBackend; this check
        # exists so a locked-out person sees why, and a 429, instead of the
        # generic bad-password error. It runs before the password is checked so
        # timing gives nothing away.
        username = (request.POST.get('username') or '').strip()
        if is_throttled(username, get_client_ip(request)):
            record_blocked(username, get_client_ip(request), request.META.get('HTTP_USER_AGENT', ''))
            # An unbound form cannot carry an error, and binding it would run the
            # password check we are refusing to run, so the message travels
            # beside the form rather than inside it.
            return render(
                request,
                self.template_name,
                {
                    'form': AuthenticationForm(request),
                    'throttle_error': (
                        "Too many failed sign-in attempts. Wait "
                        f"{settings.LOGIN_FAILURE_WINDOW_MINUTES} minutes and try again."
                    ),
                },
                status=429,
            )

        # Success and failure are both audited by accounts.signals, whichever
        # view the attempt came through.
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            login(request, form.get_user())
            return redirect('core:dashboard')

        return render(request, self.template_name, {'form': form})


class LogoutView(View):
    """User logout view."""

    def get(self, request):
        return self.post(request)

    def post(self, request):
        if request.user.is_authenticated:
            logout(request)  # audited by accounts.signals

        return redirect('accounts:login')


# User Management Views (Super Admin Only)

class UserListView(SuperAdminRequiredMixin, ListView):
    """List all users with their roles."""

    model = User
    template_name = 'accounts/user_list.html'
    context_object_name = 'users'
    paginate_by = 25

    def get_queryset(self):
        """Get all users with their profiles."""
        return User.objects.select_related('profile').order_by('-date_joined')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        # Add count of users per role
        context['role_counts'] = {
            'super_admin': UserProfile.objects.filter(role='super_admin').count(),
            'administrator': UserProfile.objects.filter(role='administrator').count(),
            'certificate_manager': UserProfile.objects.filter(role='certificate_manager').count(),
            'certificate_requester': UserProfile.objects.filter(role='certificate_requester').count(),
            'auditor': UserProfile.objects.filter(role='auditor').count(),
        }
        return context


class UserCreateView(SuperAdminRequiredMixin, View):
    """Create a new user with role assignment."""

    template_name = 'accounts/user_form.html'

    def get(self, request):
        form = UserCreateForm()
        return render(request, self.template_name, {
            'form': form,
            'action': 'Create',
            'is_edit': False
        })

    def post(self, request):
        form = UserCreateForm(request.POST)
        if form.is_valid():
            user = form.save(
                created_by=request.user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )
            # Refresh the profile relationship to get the updated role
            user.refresh_from_db()
            messages.success(
                request,
                f"User '{user.username}' created successfully with role {user.profile.get_role_display()}."
            )
            return redirect('accounts:user_list')

        return render(request, self.template_name, {
            'form': form,
            'action': 'Create',
            'is_edit': False
        })


class UserEditView(SuperAdminRequiredMixin, View):
    """Edit an existing user's details and role."""

    template_name = 'accounts/user_form.html'

    def get(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        form = UserEditForm(instance=user)
        return render(request, self.template_name, {
            'form': form,
            'action': 'Edit',
            'is_edit': True,
            'user_being_edited': user
        })

    def post(self, request, pk):
        user = get_object_or_404(User, pk=pk)
        form = UserEditForm(request.POST, instance=user)

        if form.is_valid():
            changed_own_password = (
                user.pk == request.user.pk
                and form.cleaned_data.get('change_password')
                and form.cleaned_data.get('new_password')
            )

            form.save(
                updated_by=request.user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
            )

            if changed_own_password:
                # set_password() rotates the session auth hash, which invalidates
                # the current session on the next request. Without this the admin
                # who just changed their own password is silently logged out and
                # bounced off the page they are being redirected to.
                update_session_auth_hash(request, user)

            messages.success(
                request,
                f"User '{user.username}' updated successfully."
            )
            return redirect('accounts:user_list')

        return render(request, self.template_name, {
            'form': form,
            'action': 'Edit',
            'is_edit': True,
            'user_being_edited': user
        })


class UserDeleteView(SuperAdminRequiredMixin, DeleteView):
    """Delete a user (with safeguards for last Super Admin)."""

    model = User
    template_name = 'accounts/user_confirm_delete.html'
    success_url = reverse_lazy('accounts:user_list')

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        user_to_delete = self.get_object()

        # Check if user can be deleted
        can_delete, reason = UserProfile.can_delete_user(user_to_delete)
        context['can_delete'] = can_delete
        context['cannot_delete_reason'] = reason

        return context

    def post(self, request, *args, **kwargs):
        user_to_delete = self.get_object()

        # Check if user can be deleted
        can_delete, reason = UserProfile.can_delete_user(user_to_delete)
        if not can_delete:
            messages.error(request, reason)
            return redirect('accounts:user_list')

        # Prevent users from deleting themselves
        if user_to_delete == request.user:
            messages.error(request, "You cannot delete your own account.")
            return redirect('accounts:user_list')

        username = user_to_delete.username
        role = user_to_delete.profile.get_role_display() if hasattr(user_to_delete, 'profile') else 'Unknown'

        # Audit log before deletion
        AuditLog.log(
            action=AuditLog.Action.USER_DELETED,
            resource_type='user',
            resource_id=user_to_delete.id,
            resource_name=username,
            user=request.user,
            details={
                'deleted_username': username,
                'deleted_user_role': role,
            },
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', '')[:500]
        )

        # Delete the user
        user_to_delete.delete()

        messages.success(request, f"User '{username}' deleted successfully.")
        return redirect(self.success_url)
