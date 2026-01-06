"""
Data migration to create built-in certificate profiles.
"""

from django.db import migrations


def create_builtin_profiles(apps, schema_editor):
    """Create the default built-in certificate profiles."""
    CertificateProfile = apps.get_model('core', 'CertificateProfile')

    profiles = [
        {
            'name': 'Web Server',
            'description': 'Standard TLS certificate for public-facing web servers. 1-year validity with RSA 2048-bit key.',
            'is_builtin': True,
            'certificate_type': 'server_tls',
            'validity_days': 365,
            'key_algorithm': 'rsa',
            'key_size': 2048,
        },
        {
            'name': 'Internal Service',
            'description': 'TLS certificate for internal APIs and microservices. 2-year validity for reduced rotation overhead.',
            'is_builtin': True,
            'certificate_type': 'server_tls',
            'validity_days': 730,
            'key_algorithm': 'rsa',
            'key_size': 2048,
        },
        {
            'name': 'Client Authentication',
            'description': 'Certificate for user or device authentication. 1-year validity.',
            'is_builtin': True,
            'certificate_type': 'client_auth',
            'validity_days': 365,
            'key_algorithm': 'rsa',
            'key_size': 2048,
        },
        {
            'name': 'Short-lived',
            'description': 'Short-lived certificate for automated rotation environments. 30-day validity with modern ECDSA key.',
            'is_builtin': True,
            'certificate_type': 'server_tls',
            'validity_days': 30,
            'key_algorithm': 'ecdsa',
            'key_size': 256,
        },
    ]

    for profile_data in profiles:
        CertificateProfile.objects.create(**profile_data)


def remove_builtin_profiles(apps, schema_editor):
    """Remove the built-in profiles (for reverse migration)."""
    CertificateProfile = apps.get_model('core', 'CertificateProfile')
    CertificateProfile.objects.filter(is_builtin=True).delete()


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0005_add_certificate_profiles'),
    ]

    operations = [
        migrations.RunPython(create_builtin_profiles, remove_builtin_profiles),
    ]
