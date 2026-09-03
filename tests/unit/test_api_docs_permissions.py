"""
Regression test: the OpenAPI schema and Swagger UI must not be public.

drf-spectacular serves both with AllowAny by default and ignores
DEFAULT_PERMISSION_CLASSES, so an anonymous visitor to an internet-reachable
Pemly could read the complete API surface of a certificate authority.
"""

import pytest
from django.urls import reverse


DOC_URLS = ['schema', 'api-docs']


@pytest.mark.django_db
@pytest.mark.parametrize('url_name', DOC_URLS)
def test_anonymous_cannot_read_the_api_docs(client, url_name):
    response = client.get(reverse(url_name))

    assert response.status_code in (401, 403), (
        f"{url_name} answered {response.status_code}; the API surface must not be public"
    )


@pytest.mark.django_db
@pytest.mark.parametrize('url_name', DOC_URLS)
def test_an_authenticated_user_still_gets_them(client, url_name, super_admin_user):
    client.force_login(super_admin_user)
    response = client.get(reverse(url_name))

    assert response.status_code == 200
