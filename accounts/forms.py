"""
Forms for user management.

Provides forms for creating and editing users with role assignment,
enforcing Super Admin limits and other RBAC rules.
"""

from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError

from accounts.models import UserProfile
from core.models import AuditLog


class UserCreateForm(forms.ModelForm):
    """
    Form for creating a new user with role assignment.

    Enforces Super Admin limit and validates all fields.
    """

    username = forms.CharField(
        max_length=150,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'johndoe'
        }),
        help_text="Letters, digits and @/./+/-/_ only."
    )

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'john@example.com'
        })
    )

    first_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'John'
        })
    )

    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': 'Doe'
        })
    )

    password = forms.CharField(
        required=True,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': '••••••••'
        }),
        help_text="Minimum 8 characters. Cannot be too common or entirely numeric."
    )

    password_confirm = forms.CharField(
        required=True,
        label="Confirm Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': '••••••••'
        })
    )

    role = forms.ChoiceField(
        choices=UserProfile.Role.choices,
        initial=UserProfile.Role.CERTIFICATE_REQUESTER,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-select mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg'
        }),
        help_text="The user's role determines their permissions."
    )

    class Meta:
        model = User
        fields = ['username', 'email', 'first_name', 'last_name']

    def clean_username(self):
        """Validate username is unique."""
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise ValidationError(f"Username '{username}' is already taken.")
        return username

    def clean_email(self):
        """Validate email is unique."""
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise ValidationError(f"Email '{email}' is already in use.")
        return email

    def clean_password(self):
        """Validate password meets Django's password requirements."""
        password = self.cleaned_data.get('password')
        if password:
            # Use Django's built-in password validators
            validate_password(password)
        return password

    def clean(self):
        """Validate the form as a whole."""
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        role = cleaned_data.get('role')

        # Check passwords match
        if password and password_confirm and password != password_confirm:
            raise ValidationError({'password_confirm': "Passwords do not match."})

        # Enforce Super Admin limit
        if role == UserProfile.Role.SUPER_ADMIN:
            existing_super_admins = UserProfile.objects.filter(
                role=UserProfile.Role.SUPER_ADMIN
            ).count()
            if existing_super_admins >= 2:
                raise ValidationError({
                    'role': "Cannot create more than 2 Super Admin users. This is a security requirement."
                })

        return cleaned_data

    def save(self, commit=True, created_by=None, ip_address=None, user_agent=''):
        """
        Create the user and their profile.

        Args:
            commit: Whether to save to database
            created_by: User creating this user (for audit log)
            ip_address: IP address of request (for audit log)
            user_agent: User agent of request (for audit log)

        Returns:
            The created User instance
        """
        # Create the User instance
        user = super().save(commit=False)
        user.set_password(self.cleaned_data['password'])

        if commit:
            user.save()

            # Get or create the UserProfile (signal may have already created it)
            # and update with the selected role
            role = self.cleaned_data['role']
            profile, created = UserProfile.objects.get_or_create(user=user)
            profile.role = role
            profile.save()

            # Audit log
            AuditLog.log(
                action=AuditLog.Action.USER_CREATED,
                resource_type='user',
                resource_id=user.id,
                resource_name=user.username,
                user=created_by,
                details={
                    'username': user.username,
                    'email': user.email,
                    'role': profile.get_role_display(),
                },
                ip_address=ip_address,
                user_agent=user_agent
            )

        return user


class UserEditForm(forms.ModelForm):
    """
    Form for editing an existing user.

    Allows changing email, name, and role. Username cannot be changed.
    Enforces Super Admin limits and other RBAC rules.
    """

    email = forms.EmailField(
        required=True,
        widget=forms.EmailInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg'
        })
    )

    first_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg'
        })
    )

    last_name = forms.CharField(
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg'
        })
    )

    role = forms.ChoiceField(
        choices=UserProfile.Role.choices,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-select mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg'
        }),
        help_text="The user's role determines their permissions."
    )

    change_password = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-checkbox h-4 w-4 text-primary-600'
        }),
        help_text="Check to set a new password"
    )

    new_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': '••••••••'
        }),
        help_text="Minimum 8 characters. Cannot be too common or entirely numeric."
    )

    new_password_confirm = forms.CharField(
        required=False,
        label="Confirm New Password",
        widget=forms.PasswordInput(attrs={
            'class': 'form-input mt-1 block w-full px-3 py-2 border border-slate-300 rounded-lg',
            'placeholder': '••••••••'
        })
    )

    class Meta:
        model = User
        fields = ['email', 'first_name', 'last_name']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Pre-populate role from user's profile
        if self.instance and hasattr(self.instance, 'profile'):
            self.fields['role'].initial = self.instance.profile.role

    def clean_email(self):
        """Validate email is unique (excluding current user)."""
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exclude(pk=self.instance.pk).exists():
            raise ValidationError(f"Email '{email}' is already in use by another user.")
        return email

    def clean(self):
        """Validate the form as a whole."""
        cleaned_data = super().clean()
        role = cleaned_data.get('role')
        change_password = cleaned_data.get('change_password')
        new_password = cleaned_data.get('new_password')
        new_password_confirm = cleaned_data.get('new_password_confirm')

        # Validate password change
        if change_password:
            if not new_password:
                raise ValidationError({'new_password': "Please enter a new password."})
            if new_password != new_password_confirm:
                raise ValidationError({'new_password_confirm': "Passwords do not match."})
            # Validate password strength
            validate_password(new_password, user=self.instance)

        # Check if role can be changed
        can_change, reason = UserProfile.can_change_role(self.instance, role)
        if not can_change:
            raise ValidationError({'role': reason})

        return cleaned_data

    def save(self, commit=True, updated_by=None, ip_address=None, user_agent=''):
        """
        Update the user and their profile.

        Args:
            commit: Whether to save to database
            updated_by: User making the changes (for audit log)
            ip_address: IP address of request (for audit log)
            user_agent: User agent of request (for audit log)

        Returns:
            The updated User instance
        """
        user = super().save(commit=False)

        # Handle password change
        if self.cleaned_data.get('change_password') and self.cleaned_data.get('new_password'):
            user.set_password(self.cleaned_data['new_password'])

        if commit:
            user.save()

            # Update role if changed
            old_role = user.profile.role
            new_role = self.cleaned_data['role']

            if old_role != new_role:
                user.profile.role = new_role
                user.profile.save()

                # Audit log role change
                AuditLog.log(
                    action=AuditLog.Action.USER_ROLE_CHANGED,
                    resource_type='user',
                    resource_id=user.id,
                    resource_name=user.username,
                    user=updated_by,
                    details={
                        'old_role': UserProfile.Role(old_role).label,
                        'new_role': UserProfile.Role(new_role).label,
                    },
                    ip_address=ip_address,
                    user_agent=user_agent
                )

            # Audit log general update
            AuditLog.log(
                action=AuditLog.Action.USER_UPDATED,
                resource_type='user',
                resource_id=user.id,
                resource_name=user.username,
                user=updated_by,
                details={
                    'email': user.email,
                    'role': user.profile.get_role_display(),
                    'password_changed': self.cleaned_data.get('change_password', False),
                },
                ip_address=ip_address,
                user_agent=user_agent
            )

        return user
