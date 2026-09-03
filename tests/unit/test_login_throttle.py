"""
Tests for login throttling and failed-login auditing.

LoginView logged successes only and nothing rate-limited it, so password
guessing against a CA console was unlimited and left no trace. Failures are now
audit entries, and the throttle counts them.
"""

import pytest
from django.urls import reverse

from core.models import AuditLog


LOGIN_URL = reverse('accounts:login')


def failures():
    return AuditLog.objects.filter(action=AuditLog.Action.USER_LOGIN_FAILED)


def blocks():
    return AuditLog.objects.filter(action=AuditLog.Action.USER_LOGIN_BLOCKED)


@pytest.mark.django_db
class TestFailedLoginsAreRecorded:
    def test_a_bad_password_is_audited(self, client):
        client.post(LOGIN_URL, {'username': 'admin', 'password': 'wrong'})

        entry = failures().get()
        assert entry.resource_name == 'admin'
        assert entry.user is None

    def test_an_unknown_username_is_audited_too(self, client):
        client.post(LOGIN_URL, {'username': 'nobody', 'password': 'wrong'})

        assert failures().count() == 1

    def test_the_submitted_password_is_never_stored(self, client):
        client.post(LOGIN_URL, {'username': 'admin', 'password': 'sup3rs3cret'})

        entry = failures().get()
        assert 'sup3rs3cret' not in str(entry.details)
        assert 'sup3rs3cret' not in entry.resource_name

    def test_a_good_password_still_works(self, client, super_admin_user):
        super_admin_user.set_password('correct-horse')
        super_admin_user.save()

        response = client.post(
            LOGIN_URL, {'username': super_admin_user.username, 'password': 'correct-horse'}
        )

        assert response.status_code == 302
        assert failures().count() == 0
        assert AuditLog.objects.filter(action=AuditLog.Action.USER_LOGIN).count() == 1


@pytest.mark.django_db
class TestThrottle:
    @pytest.fixture(autouse=True)
    def limits(self, settings):
        settings.LOGIN_FAILURE_LIMIT = 3
        settings.LOGIN_FAILURE_LIMIT_PER_IP = 100
        settings.LOGIN_FAILURE_WINDOW_MINUTES = 15
    def test_attempts_are_refused_once_the_limit_is_reached(self, client):
        for _ in range(3):
            response = client.post(LOGIN_URL, {'username': 'admin', 'password': 'wrong'})
            assert response.status_code == 200

        response = client.post(LOGIN_URL, {'username': 'admin', 'password': 'wrong'})

        assert response.status_code == 429
        assert blocks().count() == 1

    def test_a_blocked_attempt_is_refused_even_with_the_right_password(
        self, client, super_admin_user
    ):
        """The check runs before the password does, so timing gives nothing away."""
        super_admin_user.set_password('correct-horse')
        super_admin_user.save()
        for _ in range(3):
            client.post(LOGIN_URL, {'username': super_admin_user.username, 'password': 'no'})

        response = client.post(
            LOGIN_URL, {'username': super_admin_user.username, 'password': 'correct-horse'}
        )

        assert response.status_code == 429
        assert AuditLog.objects.filter(action=AuditLog.Action.USER_LOGIN).count() == 0

    def test_one_username_being_locked_does_not_lock_another(self, client):
        for _ in range(4):
            client.post(LOGIN_URL, {'username': 'admin', 'password': 'wrong'})

        response = client.post(LOGIN_URL, {'username': 'auditor', 'password': 'wrong'})

        assert response.status_code == 200

    def test_a_success_clears_the_slate(self, client, super_admin_user):
        """Mistyping twice then getting it right must not leave you near a lockout."""
        super_admin_user.set_password('correct-horse')
        super_admin_user.save()
        for _ in range(2):
            client.post(LOGIN_URL, {'username': super_admin_user.username, 'password': 'no'})

        client.post(
            LOGIN_URL, {'username': super_admin_user.username, 'password': 'correct-horse'}
        )
        client.logout()

        # Two more failures would have tripped a limit of 3 without the reset.
        for _ in range(2):
            response = client.post(
                LOGIN_URL, {'username': super_admin_user.username, 'password': 'no'}
            )

        assert response.status_code == 200

    def test_spraying_many_usernames_from_one_address_is_throttled(self, client, settings):
        settings.LOGIN_FAILURE_LIMIT = 100
        settings.LOGIN_FAILURE_LIMIT_PER_IP = 3
        for n in range(3):
            client.post(LOGIN_URL, {'username': f'user{n}', 'password': 'wrong'})

        response = client.post(LOGIN_URL, {'username': 'user99', 'password': 'wrong'})

        assert response.status_code == 429

    def test_failures_outside_the_window_do_not_count(self, client, settings):
        settings.LOGIN_FAILURE_WINDOW_MINUTES = 0
        for _ in range(5):
            client.post(LOGIN_URL, {'username': 'admin', 'password': 'wrong'})

        response = client.post(LOGIN_URL, {'username': 'admin', 'password': 'wrong'})

        assert response.status_code == 200
