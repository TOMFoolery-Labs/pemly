"""
Regression tests: an unauthenticated request must be redirected to the login
page, never answered with 403.

Every role mixin reads request.user.profile, which AnonymousUser does not have.
When the role check ran before the authentication check, any anonymous request
to a role-gated page raised PermissionDenied instead of redirecting. The visible
symptom was changing your own password on the user edit page: set_password()
rotates the session auth hash, the redirect that follows arrives anonymous, and
the user was met with Forbidden instead of the login form.
"""

import pytest
from django.contrib.auth import update_session_auth_hash  # noqa: F401  (documents the fix)
from django.urls import reverse

from tests.factories import SuperAdminUserFactory


ROLE_GATED_URLS = [
    'accounts:user_list',
    'accounts:user_create',
    'core:dashboard',
    'core:ca_list',
    'core:certificate_list',
]


@pytest.mark.django_db
class TestAnonymousAccess:
    @pytest.mark.parametrize('url_name', ROLE_GATED_URLS)
    def test_anonymous_is_redirected_to_login(self, client, url_name):
        response = client.get(reverse(url_name))

        assert response.status_code == 302, (
            f"{url_name} answered {response.status_code}; anonymous users must be "
            "redirected to the login page, not refused"
        )
        assert reverse('accounts:login') in response['Location']

    @pytest.mark.parametrize('url_name', ROLE_GATED_URLS)
    def test_redirect_preserves_the_destination(self, client, url_name):
        """?next= means the user lands where they were going after logging in."""
        target = reverse(url_name)
        response = client.get(target)

        assert f'next={target}' in response['Location']

    def test_authenticated_user_without_permission_still_gets_403(self, client):
        """The fix must not weaken authorisation for users who ARE logged in."""
        from tests.factories import CertificateRequesterUserFactory

        client.force_login(CertificateRequesterUserFactory())
        response = client.get(reverse('accounts:user_list'))

        assert response.status_code == 403


@pytest.mark.django_db
class TestSelfPasswordChange:
    """Changing your own password must not log you out."""

    def test_session_survives_changing_own_password(self, client):
        user = SuperAdminUserFactory()
        client.force_login(user)

        response = client.post(
            reverse('accounts:user_edit', kwargs={'pk': user.pk}),
            {
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': 'super_admin',
                'is_active': 'on',
                'change_password': 'on',
                'new_password': 'a-Fresh-Passphrase-42',
                'new_password_confirm': 'a-Fresh-Passphrase-42',
            },
        )

        assert response.status_code == 302
        assert response['Location'] == reverse('accounts:user_list')

        # The redirect target must be reachable: previously the session had been
        # invalidated by the password change and this came back 403.
        followup = client.get(reverse('accounts:user_list'))
        assert followup.status_code == 200

    def test_password_was_actually_changed(self, client):
        user = SuperAdminUserFactory()
        client.force_login(user)

        client.post(
            reverse('accounts:user_edit', kwargs={'pk': user.pk}),
            {
                'username': user.username,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'role': 'super_admin',
                'is_active': 'on',
                'change_password': 'on',
                'new_password': 'a-Fresh-Passphrase-42',
                'new_password_confirm': 'a-Fresh-Passphrase-42',
            },
        )

        user.refresh_from_db()
        assert user.check_password('a-Fresh-Passphrase-42')

    def test_changing_another_users_password_does_not_touch_your_session(self, client):
        actor = SuperAdminUserFactory(username='actor')
        target = SuperAdminUserFactory(username='target')
        client.force_login(actor)

        client.post(
            reverse('accounts:user_edit', kwargs={'pk': target.pk}),
            {
                'username': target.username,
                'email': target.email,
                'first_name': target.first_name,
                'last_name': target.last_name,
                'role': 'super_admin',
                'is_active': 'on',
                'change_password': 'on',
                'new_password': 'another-Passphrase-42',
                'new_password_confirm': 'another-Passphrase-42',
            },
        )

        assert client.get(reverse('accounts:user_list')).status_code == 200
        target.refresh_from_db()
        assert target.check_password('another-Passphrase-42')
