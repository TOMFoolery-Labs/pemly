"""
Authentication backend that enforces the login throttle.

authenticate() is the one point every login path passes through - the app's own
LoginView, Django admin's login, and DRF session authentication - so refusing
here covers entry points that instrumenting a single view never could. The
admin login was an unlimited, unaudited way in until this existed.
"""

from django.contrib.auth.backends import ModelBackend

from accounts.throttling import is_throttled
from core.utils import get_client_ip


class ThrottledModelBackend(ModelBackend):
    def authenticate(self, request, username=None, password=None, **kwargs):
        # No request means a programmatic call (management commands, the test
        # client's login()); there is no address to key on and nothing to protect.
        if request is not None and username and is_throttled(username, get_client_ip(request)):
            return None
        return super().authenticate(request, username=username, password=password, **kwargs)
