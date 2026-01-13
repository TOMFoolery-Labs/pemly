"""
Context processors for making data available to all templates.
"""

from django.conf import settings


def app_settings(request):
    """
    Make application settings available to all templates.
    """
    return {
        'settings': settings,
    }
