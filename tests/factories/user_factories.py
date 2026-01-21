"""
User and UserProfile factories for testing.
"""

import factory
from django.contrib.auth.models import User

from accounts.models import UserProfile


class UserFactory(factory.django.DjangoModelFactory):
    """Factory for creating Django User instances."""

    class Meta:
        model = User
        skip_postgeneration_save = True

    username = factory.Sequence(lambda n: f'user{n}')
    email = factory.LazyAttribute(lambda obj: f'{obj.username}@example.com')
    first_name = factory.Faker('first_name')
    last_name = factory.Faker('last_name')
    is_active = True
    is_staff = False
    is_superuser = False

    @factory.post_generation
    def password(self, create, extracted, **kwargs):
        """Set password if provided, otherwise use default."""
        if extracted:
            self.set_password(extracted)
        else:
            self.set_password('testpassword123')
        if create:
            self.save()


class UserProfileFactory(factory.django.DjangoModelFactory):
    """Factory for creating UserProfile instances."""

    class Meta:
        model = UserProfile

    user = factory.SubFactory(UserFactory)
    role = UserProfile.Role.CERTIFICATE_REQUESTER


class SuperAdminUserFactory(UserFactory):
    """Factory for creating Super Admin users."""

    username = factory.Sequence(lambda n: f'superadmin{n}')
    is_superuser = True

    @factory.post_generation
    def set_role(self, create, extracted, **kwargs):
        """Set Super Admin role after user creation."""
        if create and hasattr(self, 'profile'):
            self.profile.role = UserProfile.Role.SUPER_ADMIN
            self.profile.save()


class AdministratorUserFactory(UserFactory):
    """Factory for creating Administrator users."""

    username = factory.Sequence(lambda n: f'admin{n}')

    @factory.post_generation
    def set_role(self, create, extracted, **kwargs):
        """Set Administrator role after user creation."""
        if create and hasattr(self, 'profile'):
            self.profile.role = UserProfile.Role.ADMINISTRATOR
            self.profile.save()


class CertificateManagerUserFactory(UserFactory):
    """Factory for creating Certificate Manager users."""

    username = factory.Sequence(lambda n: f'manager{n}')

    @factory.post_generation
    def set_role(self, create, extracted, **kwargs):
        """Set Certificate Manager role after user creation."""
        if create and hasattr(self, 'profile'):
            self.profile.role = UserProfile.Role.CERTIFICATE_MANAGER
            self.profile.save()


class CertificateRequesterUserFactory(UserFactory):
    """Factory for creating Certificate Requester users."""

    username = factory.Sequence(lambda n: f'requester{n}')

    @factory.post_generation
    def set_role(self, create, extracted, **kwargs):
        """Set Certificate Requester role after user creation."""
        if create and hasattr(self, 'profile'):
            self.profile.role = UserProfile.Role.CERTIFICATE_REQUESTER
            self.profile.save()


class AuditorUserFactory(UserFactory):
    """Factory for creating Auditor users."""

    username = factory.Sequence(lambda n: f'auditor{n}')

    @factory.post_generation
    def set_role(self, create, extracted, **kwargs):
        """Set Auditor role after user creation."""
        if create and hasattr(self, 'profile'):
            self.profile.role = UserProfile.Role.AUDITOR
            self.profile.save()
