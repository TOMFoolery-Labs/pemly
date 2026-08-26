"""
Issue the TLS certificate for Pemly's own web interface from Pemly's own CA.

This is the answer for sites with no outbound internet at all, where neither ACME
DNS-01 nor a commercial CA is reachable: the appliance already is a CA, so it can
sign its own web certificate. Clients that already trust the CA (via the trust
portal) then trust the web UI with no extra step.

Writes into the certs volume that the Traefik container mounts read-only. Traefik
must then be restarted to pick it up; `bootstrap.sh issue-cert` does both steps.
"""

import os
from datetime import timedelta
from pathlib import Path

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from core.models import (
    AuditLog,
    CAStatus,
    Certificate,
    CertificateAuthority,
    CertificateStatus,
    CertificateType,
    KeyAlgorithm,
)
from core.services import CFSSLClient, CFSSLError
from core.services.cfssl import CertificateRequest

DEFAULT_CERT_DIR = '/certs'


class Command(BaseCommand):
    help = "Issue the web UI's TLS certificate from a Pemly CA and hand it to the proxy."

    def add_arguments(self, parser):
        parser.add_argument(
            '--domain',
            help="Certificate common name. Defaults to PEMLY_DOMAIN from the environment.",
        )
        parser.add_argument(
            '--ca',
            help="Name or UUID of the signing CA. Optional when exactly one CA can sign.",
        )
        parser.add_argument(
            '--alt-name',
            action='append',
            default=[],
            dest='alt_names',
            help="Additional DNS SAN. Repeatable.",
        )
        parser.add_argument(
            '--ip',
            action='append',
            default=[],
            dest='ip_addresses',
            help="Additional IP SAN. Repeatable.",
        )
        parser.add_argument('--validity-days', type=int, default=397)
        parser.add_argument('--key-size', type=int, default=2048)
        parser.add_argument(
            '--cert-dir',
            default=os.environ.get('PEMLY_CERT_DIR', DEFAULT_CERT_DIR),
            help=f"Directory to write tls.crt/tls.key into (default {DEFAULT_CERT_DIR}).",
        )

    # -- helpers ---------------------------------------------------------------

    def _resolve_domain(self, options) -> str:
        domain = options['domain'] or os.environ.get('PEMLY_DOMAIN', '')
        if not domain:
            raise CommandError(
                "No domain given. Pass --domain, or set PEMLY_DOMAIN in .env."
            )
        return domain.strip()

    def _resolve_ca(self, options) -> CertificateAuthority:
        candidates = CertificateAuthority.objects.filter(
            status=CAStatus.ACTIVE,
        ).exclude(private_key_pem_encrypted='')

        selector = options['ca']
        if selector:
            ca = candidates.filter(name=selector).first()
            if ca is None:
                # UUID lookups raise ValidationError on a malformed value, and a bad
                # --ca is a user error rather than a crash.
                try:
                    ca = candidates.filter(pk=selector).first()
                except Exception:
                    ca = None
            if ca is None:
                raise CommandError(f"No active signing CA matches '{selector}'.")
            return ca

        count = candidates.count()
        if count == 0:
            raise CommandError(
                "No active CA with a private key. Set up a Certificate Authority in "
                "the web UI first, then re-run this command."
            )
        if count > 1:
            names = ', '.join(candidates.values_list('name', flat=True))
            raise CommandError(f"Multiple signing CAs available; pass --ca. Options: {names}")
        return candidates.first()

    def _resolve_author(self) -> User:
        # created_by is PROTECT/non-null on Certificate, so the record needs an owner.
        user = User.objects.filter(is_superuser=True).order_by('pk').first()
        if user is None:
            raise CommandError("No superuser exists to attribute this certificate to.")
        return user

    def _write(self, cert_dir: Path, name: str, content: str, mode: int) -> Path:
        path = cert_dir / name
        # Create with the right mode from the start rather than chmod-ing afterwards,
        # which would leave the private key briefly world-readable.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, 'w') as handle:
            handle.write(content)
        os.chmod(path, mode)
        return path

    # -- entrypoint ------------------------------------------------------------

    def handle(self, *args, **options):
        domain = self._resolve_domain(options)
        ca = self._resolve_ca(options)
        author = self._resolve_author()

        cert_dir = Path(options['cert_dir'])
        if not cert_dir.is_dir():
            raise CommandError(f"Certificate directory {cert_dir} does not exist.")
        if not os.access(cert_dir, os.W_OK):
            raise CommandError(f"Certificate directory {cert_dir} is not writable.")

        dns_names = [domain] + [n for n in options['alt_names'] if n != domain]
        ip_addresses = list(options['ip_addresses'])
        hosts = dns_names + ip_addresses
        validity_days = options['validity_days']

        self.stdout.write(f"Issuing '{domain}' from CA '{ca.name}'...")

        client = CFSSLClient()
        try:
            key_result = client.generate_key(CertificateRequest(
                common_name=domain,
                organization=ca.organization,
                hosts=hosts,
                key_algorithm=KeyAlgorithm.RSA,
                key_size=options['key_size'],
            ))
            sign_result = client.sign(
                csr=key_result['csr'],
                ca_cert=ca.certificate_pem,
                ca_key=ca.get_private_key(),
                profile='server_tls',
                hosts=hosts,
                expiry=f"{validity_days * 24}h",
                ocsp_url=ca.ocsp_responder_url or None,
            )
        except CFSSLError as exc:
            raise CommandError(f"CFSSL error: {exc}")

        certificate_pem = sign_result['certificate']
        private_key_pem = key_result['private_key']

        # Record it like any other issued certificate so it is visible, auditable,
        # renewable and revocable through the normal UI.
        certificate = Certificate(
            ca=ca,
            type=CertificateType.SERVER_TLS,
            common_name=domain,
            organization=ca.organization,
            san_dns_names=dns_names,
            san_ip_addresses=ip_addresses,
            key_algorithm=KeyAlgorithm.RSA,
            key_size=options['key_size'],
            validity_days=validity_days,
            certificate_pem=certificate_pem,
            status=CertificateStatus.ACTIVE,
            not_before=timezone.now(),
            not_after=timezone.now() + timedelta(days=validity_days),
            created_by=author,
        )
        certificate.set_private_key(private_key_pem)

        try:
            from cryptography import x509
            parsed = x509.load_pem_x509_certificate(certificate_pem.encode())
            certificate.serial_number = format(parsed.serial_number, 'x')
            certificate.not_before = parsed.not_valid_before_utc
            certificate.not_after = parsed.not_valid_after_utc
        except Exception:
            pass

        certificate.save()

        AuditLog.log(
            action=AuditLog.Action.CERT_ISSUED,
            resource_type='certificate',
            resource_id=certificate.id,
            resource_name=certificate.common_name,
            user=author,
            details={
                'type': certificate.type,
                'generation_method': 'issue_web_cert',
                'purpose': 'pemly web interface',
                'validity_days': validity_days,
                'san_dns_names': dns_names,
                'san_ip_addresses': ip_addresses,
                'signing_ca': ca.name,
                'signing_ca_id': str(ca.id),
            },
        )

        # Serve the full chain so clients that trust only the root still validate a
        # certificate issued by an intermediate.
        chain = certificate_pem.strip() + '\n'
        if ca.certificate_pem and ca.certificate_pem.strip() not in chain:
            chain += ca.certificate_pem.strip() + '\n'

        crt_path = self._write(cert_dir, 'tls.crt', chain, 0o644)
        key_path = self._write(cert_dir, 'tls.key', private_key_pem.strip() + '\n', 0o600)

        self.stdout.write(self.style.SUCCESS(
            f"Issued {domain} (serial {certificate.serial_number or 'unknown'}), "
            f"valid until {certificate.not_after:%Y-%m-%d}."
        ))
        self.stdout.write(f"  wrote {crt_path}")
        self.stdout.write(f"  wrote {key_path}")
        self.stdout.write(self.style.WARNING(
            "Reload the proxy to start serving it:  docker compose restart traefik"
        ))
        self.stdout.write(
            "(Traefik's file provider watches the config directory, not the "
            "certificate files it references, so a reload is required.)"
        )
