"""
Tests for login throttling and login auditing.

The lock is keyed on the (username, address) pair. The first version keyed on
the username alone, which let anyone who knew an operator's username keep them
locked out of the CA console from anywhere. Enforcement is in the auth backend
and recording in signals, so the admin login is covered as well as our own.
"""

import pytest
from django.urls import reverse

from core.models import AuditLog


LOGIN_URL = reverse('accounts:login')
ADMIN_LOGIN_URL = '/admin/login/'


def rows(action):
    return AuditLog.objects.filter(action=action)


def attempt(client, username, password, ip='10.0.0.1', url=LOGIN_URL):
    return client.post(url, {'username': username, 'password': password}, REMOTE_ADDR=ip)


@pytest.fixture
def limits(settings):
    settings.LOGIN_FAILURE_LIMIT = 3
    settings.LOGIN_FAILURE_LIMIT_PER_IP = 100
    settings.LOGIN_FAILURE_WINDOW_MINUTES = 15
    settings.TRUST_X_FORWARDED_FOR = False
    return settings


@pytest.fixture
def admin(super_admin_user):
    super_admin_user.set_password('correct-horse')
    super_admin_user.is_staff = True  # the admin site turns away non-staff after auth
    super_admin_user.save()
    return super_admin_user


@pytest.mark.django_db
class TestLoginsAreRecorded:
    def test_a_bad_password_is_audited(self, client, limits):
        attempt(client, 'admin', 'wrong')

        entry = rows(AuditLog.Action.USER_LOGIN_FAILED).get()
        assert entry.resource_name == 'admin'
        assert entry.ip_address == '10.0.0.1'
        assert entry.user is None

    def test_the_submitted_password_is_never_stored(self, client, limits):
        attempt(client, 'admin', 'sup3rs3cret')

        entry = rows(AuditLog.Action.USER_LOGIN_FAILED).get()
        assert 'sup3rs3cret' not in str(entry.details)

    def test_a_good_password_is_audited_once(self, client, limits, admin):
        response = attempt(client, admin.username, 'correct-horse')

        assert response.status_code == 302
        assert rows(AuditLog.Action.USER_LOGIN).count() == 1
        assert rows(AuditLog.Action.USER_LOGIN_FAILED).count() == 0

    def test_logout_is_audited(self, client, limits, admin):
        attempt(client, admin.username, 'correct-horse')
        client.post(reverse('accounts:logout'))

        assert rows(AuditLog.Action.USER_LOGOUT).get().user == admin

    def test_the_admin_site_login_is_audited_too(self, client, limits, admin):
        """Django admin was an unaudited way in until recording moved to signals."""
        attempt(client, admin.username, 'wrong', url=ADMIN_LOGIN_URL)
        attempt(client, admin.username, 'correct-horse', url=ADMIN_LOGIN_URL)

        assert rows(AuditLog.Action.USER_LOGIN_FAILED).count() == 1
        assert rows(AuditLog.Action.USER_LOGIN).count() == 1


@pytest.mark.django_db
class TestThrottle:
    def test_attempts_are_refused_once_the_limit_is_reached(self, client, limits):
        for _ in range(3):
            assert attempt(client, 'admin', 'wrong').status_code == 200

        response = attempt(client, 'admin', 'wrong')

        assert response.status_code == 429
        assert rows(AuditLog.Action.USER_LOGIN_BLOCKED).count() == 1

    def test_the_refusal_is_explained_on_the_page(self, client, limits):
        """The first version queued a message the login page never rendered."""
        for _ in range(3):
            attempt(client, 'admin', 'wrong')

        body = attempt(client, 'admin', 'wrong').content.decode()

        assert 'Too many failed sign-in attempts' in body

    def test_the_refusal_does_not_leak_onto_the_next_session(self, client, limits, admin):
        for _ in range(4):
            attempt(client, 'admin', 'wrong')

        attempt(client, admin.username, 'correct-horse', ip='10.0.0.2')
        dashboard = client.get(reverse('core:dashboard')).content.decode()

        assert 'Too many failed sign-in attempts' not in dashboard

    def test_an_attacker_locks_out_only_their_own_address(self, client, limits, admin):
        """The regression: a username-only lock was a denial of service on the operator."""
        for _ in range(4):
            attempt(client, admin.username, 'wrong', ip='198.51.100.9')

        response = attempt(client, admin.username, 'correct-horse', ip='10.0.0.1')

        assert response.status_code == 302, "the real operator must still get in from elsewhere"

    def test_the_same_pair_is_refused_even_with_the_right_password(self, client, limits, admin):
        for _ in range(3):
            attempt(client, admin.username, 'wrong')

        response = attempt(client, admin.username, 'correct-horse')

        assert response.status_code == 429
        assert rows(AuditLog.Action.USER_LOGIN).count() == 0

    def test_the_admin_site_login_is_throttled_too(self, client, limits, admin):
        """An attacker locked out of /accounts/login/ could just move to /admin/login/."""
        for _ in range(3):
            attempt(client, admin.username, 'wrong')

        response = attempt(client, admin.username, 'correct-horse', url=ADMIN_LOGIN_URL)

        assert response.status_code == 200, "admin must not have logged in"
        assert rows(AuditLog.Action.USER_LOGIN).count() == 0
        assert rows(AuditLog.Action.USER_LOGIN_BLOCKED).count() == 1

    def test_one_username_being_locked_does_not_lock_another(self, client, limits):
        for _ in range(4):
            attempt(client, 'admin', 'wrong')

        assert attempt(client, 'auditor', 'wrong').status_code == 200

    def test_a_success_clears_the_slate(self, client, limits, admin):
        for _ in range(2):
            attempt(client, admin.username, 'no')
        attempt(client, admin.username, 'correct-horse')
        client.logout()

        # Two more would have tripped a limit of 3 without the reset.
        for _ in range(2):
            response = attempt(client, admin.username, 'no')

        assert response.status_code == 200

    def test_spraying_many_usernames_from_one_address_is_throttled(self, client, limits):
        limits.LOGIN_FAILURE_LIMIT = 100
        limits.LOGIN_FAILURE_LIMIT_PER_IP = 3
        for n in range(3):
            attempt(client, f'user{n}', 'wrong')

        assert attempt(client, 'user99', 'wrong').status_code == 429

    def test_refused_attempts_do_not_write_a_row_each(self, client, limits):
        """A locked-out attacker must not be able to fill the audit table."""
        for _ in range(3):
            attempt(client, 'admin', 'wrong')
        for _ in range(50):
            attempt(client, 'admin', 'wrong')

        assert rows(AuditLog.Action.USER_LOGIN_FAILED).count() == 3
        assert rows(AuditLog.Action.USER_LOGIN_BLOCKED).count() == 1

    def test_a_failed_audit_write_does_not_break_the_refusal(self, client, limits, monkeypatch):
        from accounts import throttling

        def boom(*args, **kwargs):
            raise RuntimeError("database is away")

        monkeypatch.setattr(throttling.AuditLog, 'log', boom)

        response = attempt(client, 'admin', 'wrong')

        assert response.status_code == 200
        assert not response.wsgi_request.user.is_authenticated
