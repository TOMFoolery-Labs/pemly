"""
Regression tests: the public trust portal must render its content.

base.html renders either the authenticated layout, which ends in
{% block content %}, or the anonymous one, which ends in
{% block auth_content %}. portal.html filled auth_content only, so a logged-in
operator following the "Trust Portal" link from the CA detail page was served
the admin sidebar wrapped around an empty <main> - a 200 with nothing in it.
The portal now extends base_public.html and renders identically for everyone.
"""

import pytest
from django.urls import reverse

from core.models import CAStatus


def portal_url(ca):
    return reverse('core:trust_portal', kwargs={'pk': ca.pk})


@pytest.mark.django_db
class TestTrustPortalRenders:
    def test_anonymous_visitor_sees_the_certificate(self, client, root_ca):
        response = client.get(portal_url(root_ca))

        assert response.status_code == 200
        body = response.content.decode()
        assert 'Certificate Details' in body
        assert root_ca.name in body

    def test_logged_in_operator_sees_the_same_page(self, client, root_ca, super_admin_user):
        """The regression: authentication decided which block base.html rendered."""
        client.force_login(super_admin_user)
        response = client.get(portal_url(root_ca))

        assert response.status_code == 200
        body = response.content.decode()
        assert 'Certificate Details' in body, (
            "the portal rendered empty chrome for an authenticated visitor"
        )
        assert root_ca.name in body

    def test_the_page_carries_no_admin_chrome(self, client, root_ca, super_admin_user):
        """A public page must not leak the operator's navigation to end users."""
        client.force_login(super_admin_user)
        body = client.get(portal_url(root_ca)).content.decode()

        assert 'Certificate Authorities' not in body, "sidebar navigation leaked"
        assert reverse('accounts:logout') not in body

    def test_download_links_are_present(self, client, root_ca):
        body = client.get(portal_url(root_ca)).content.decode()

        assert reverse('core:trust_download', kwargs={'pk': root_ca.pk, 'format': 'der'}) in body
        assert reverse('core:trust_download', kwargs={'pk': root_ca.pk, 'format': 'pem'}) in body

    @pytest.mark.parametrize('status', [CAStatus.PENDING, CAStatus.REVOKED, CAStatus.EXPIRED])
    def test_a_ca_that_is_not_active_is_not_published(self, client, root_ca, status):
        """Only active and air-gapped CAs are distributable."""
        root_ca.status = status
        root_ca.save()

        assert client.get(portal_url(root_ca)).status_code == 404
