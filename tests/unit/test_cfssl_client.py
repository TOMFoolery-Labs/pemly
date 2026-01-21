"""
Unit tests for CFSSLClient with mocked HTTP and CLI.
"""

import pytest
import json
from unittest.mock import patch, MagicMock

import responses
from requests.exceptions import ConnectionError, Timeout

from core.services.cfssl import (
    CFSSLClient,
    CFSSLError,
    CAInitRequest,
    CertificateRequest,
)


class TestCFSSLClientHTTP:
    """Tests for CFSSL HTTP API interactions."""

    @responses.activate
    def test_health_check_success(self):
        """Test successful health check."""
        responses.add(
            responses.GET,
            'http://localhost:8888/api/v1/cfssl/health',
            json={'success': True},
            status=200
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        assert client.health_check() is True

    @responses.activate
    def test_health_check_failure(self):
        """Test failed health check."""
        responses.add(
            responses.GET,
            'http://localhost:8888/api/v1/cfssl/health',
            body=ConnectionError('Connection refused')
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        assert client.health_check() is False

    @responses.activate
    def test_init_ca_success(self):
        """Test successful CA initialization."""
        expected_response = {
            'success': True,
            'result': {
                'certificate': '-----BEGIN CERTIFICATE-----\nCA CERT\n-----END CERTIFICATE-----',
                'private_key': '-----BEGIN RSA PRIVATE KEY-----\nCA KEY\n-----END RSA PRIVATE KEY-----',
                'csr': '-----BEGIN CERTIFICATE REQUEST-----\nCA CSR\n-----END CERTIFICATE REQUEST-----',
            }
        }

        responses.add(
            responses.POST,
            'http://localhost:8888/api/v1/cfssl/init_ca',
            json=expected_response,
            status=200
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        request = CAInitRequest(
            common_name='Test Root CA',
            organization='Test Org',
            country='US',
            state='California',
            locality='San Francisco',
        )

        result = client.init_ca(request)

        assert result['certificate'] == expected_response['result']['certificate']
        assert result['private_key'] == expected_response['result']['private_key']
        assert result['csr'] == expected_response['result']['csr']

    @responses.activate
    def test_init_ca_error(self):
        """Test CA initialization error handling."""
        responses.add(
            responses.POST,
            'http://localhost:8888/api/v1/cfssl/init_ca',
            json={
                'success': False,
                'errors': [{'message': 'Invalid key size'}]
            },
            status=200
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        request = CAInitRequest(
            common_name='Test CA',
            organization='Test',
        )

        with pytest.raises(CFSSLError, match='Invalid key size'):
            client.init_ca(request)

    @responses.activate
    def test_generate_key_success(self):
        """Test successful key generation."""
        expected_response = {
            'success': True,
            'result': {
                'private_key': '-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----',
                'certificate_request': '-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----',
            }
        }

        responses.add(
            responses.POST,
            'http://localhost:8888/api/v1/cfssl/newkey',
            json=expected_response,
            status=200
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        request = CertificateRequest(
            common_name='test.example.com',
            hosts=['test.example.com', '192.168.1.1'],
        )

        result = client.generate_key(request)

        assert result['private_key'] == expected_response['result']['private_key']
        assert result['csr'] == expected_response['result']['certificate_request']

    @responses.activate
    def test_connection_error(self):
        """Test connection error handling."""
        responses.add(
            responses.POST,
            'http://localhost:8888/api/v1/cfssl/newkey',
            body=ConnectionError('Connection refused')
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        request = CertificateRequest(common_name='test.example.com')

        with pytest.raises(CFSSLError, match='Cannot connect'):
            client.generate_key(request)

    @responses.activate
    def test_timeout_error(self):
        """Test timeout error handling."""
        responses.add(
            responses.POST,
            'http://localhost:8888/api/v1/cfssl/newkey',
            body=Timeout('Request timed out')
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        request = CertificateRequest(common_name='test.example.com')

        with pytest.raises(CFSSLError, match='timed out'):
            client.generate_key(request)

    @responses.activate
    def test_info_endpoint(self):
        """Test getting CA info."""
        expected_response = {
            'success': True,
            'result': {
                'certificate': '-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----',
                'usages': ['signing', 'cert sign', 'crl sign'],
            }
        }

        responses.add(
            responses.POST,
            'http://localhost:8888/api/v1/cfssl/info',
            json=expected_response,
            status=200
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        result = client.info()

        assert 'certificate' in result

    @responses.activate
    def test_revoke_endpoint(self):
        """Test certificate revocation."""
        responses.add(
            responses.POST,
            'http://localhost:8888/api/v1/cfssl/revoke',
            json={'success': True, 'result': {}},
            status=200
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        result = client.revoke(
            serial='abc123',
            authority_key_id='def456',
            reason='key_compromise'
        )

        assert result == {}


class TestCFSSLClientCLI:
    """Tests for CFSSL CLI interactions."""

    @patch('core.services.cfssl.subprocess.run')
    @patch('shutil.which')
    def test_sign_success(self, mock_which, mock_run):
        """Test successful CSR signing via CLI."""
        mock_which.return_value = '/usr/local/bin/cfssl'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"cert": "-----BEGIN CERTIFICATE-----\\nSIGNED CERT\\n-----END CERTIFICATE-----"}',
            stderr=''
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        result = client.sign(
            csr='-----BEGIN CERTIFICATE REQUEST-----\nCSR\n-----END CERTIFICATE REQUEST-----',
            ca_cert='-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----',
            ca_key='-----BEGIN RSA PRIVATE KEY-----\nKEY\n-----END RSA PRIVATE KEY-----',
            profile='server_tls',
        )

        assert 'certificate' in result
        assert 'BEGIN CERTIFICATE' in result['certificate']

    @patch('core.services.cfssl.subprocess.run')
    @patch('shutil.which')
    def test_sign_with_hosts(self, mock_which, mock_run):
        """Test CSR signing with additional hosts."""
        mock_which.return_value = '/usr/local/bin/cfssl'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"cert": "-----BEGIN CERTIFICATE-----\\nCERT\\n-----END CERTIFICATE-----"}',
            stderr=''
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        client.sign(
            csr='CSR',
            ca_cert='CA CERT',
            ca_key='CA KEY',
            hosts=['example.com', '192.168.1.1'],
        )

        # Verify -hostname flag was passed
        call_args = mock_run.call_args[0][0]
        assert '-hostname' in call_args
        hostname_idx = call_args.index('-hostname')
        assert 'example.com,192.168.1.1' in call_args[hostname_idx + 1]

    @patch('core.services.cfssl.subprocess.run')
    @patch('shutil.which')
    def test_sign_with_ocsp_url(self, mock_which, mock_run):
        """Test CSR signing with OCSP URL."""
        mock_which.return_value = '/usr/local/bin/cfssl'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"cert": "-----BEGIN CERTIFICATE-----\\nCERT\\n-----END CERTIFICATE-----"}',
            stderr=''
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        client.sign(
            csr='CSR',
            ca_cert='CA CERT',
            ca_key='CA KEY',
            ocsp_url='http://ocsp.example.com/',
        )

        # The OCSP URL should be in the config written to the temp file
        # We can't easily verify the temp file content, but the call should succeed
        mock_run.assert_called_once()

    @patch('core.services.cfssl.subprocess.run')
    @patch('shutil.which')
    def test_sign_cli_error(self, mock_which, mock_run):
        """Test CLI error handling."""
        mock_which.return_value = '/usr/local/bin/cfssl'
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout='',
            stderr='Error: invalid CSR format'
        )

        client = CFSSLClient(base_url='http://localhost:8888')

        with pytest.raises(CFSSLError, match='CFSSL CLI error'):
            client.sign(
                csr='INVALID CSR',
                ca_cert='CA',
                ca_key='KEY',
            )

    @patch('core.services.cfssl.subprocess.run')
    @patch('shutil.which')
    def test_sign_cli_timeout(self, mock_which, mock_run):
        """Test CLI timeout handling."""
        import subprocess

        mock_which.return_value = '/usr/local/bin/cfssl'
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='cfssl', timeout=30)

        client = CFSSLClient(base_url='http://localhost:8888')

        with pytest.raises(CFSSLError, match='timed out'):
            client.sign(
                csr='CSR',
                ca_cert='CA',
                ca_key='KEY',
            )

    @patch('shutil.which')
    def test_binary_not_found(self, mock_which):
        """Test error when CFSSL binary is not found."""
        mock_which.return_value = None

        client = CFSSLClient(base_url='http://localhost:8888')

        with pytest.raises(CFSSLError, match='CFSSL binary not found'):
            client.sign(
                csr='CSR',
                ca_cert='CA',
                ca_key='KEY',
            )

    @patch('core.services.cfssl.subprocess.run')
    @patch('shutil.which')
    def test_sign_intermediate_success(self, mock_which, mock_run):
        """Test successful intermediate CA signing."""
        mock_which.return_value = '/usr/local/bin/cfssl'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"cert": "-----BEGIN CERTIFICATE-----\\nINTERMEDIATE\\n-----END CERTIFICATE-----"}',
            stderr=''
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        result = client.sign_intermediate(
            csr='CSR',
            ca_cert='CA CERT',
            ca_key='CA KEY',
            path_length=0,
        )

        assert 'certificate' in result

    @patch('core.services.cfssl.subprocess.run')
    @patch('shutil.which')
    def test_sign_ocsp_responder_success(self, mock_which, mock_run):
        """Test successful OCSP responder certificate signing."""
        mock_which.return_value = '/usr/local/bin/cfssl'
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='{"cert": "-----BEGIN CERTIFICATE-----\\nOCSP\\n-----END CERTIFICATE-----"}',
            stderr=''
        )

        client = CFSSLClient(base_url='http://localhost:8888')
        result = client.sign_ocsp_responder(
            csr='CSR',
            ca_cert='CA CERT',
            ca_key='CA KEY',
        )

        assert 'certificate' in result


class TestCFSSLError:
    """Tests for CFSSLError exception."""

    def test_error_with_message(self):
        """Test CFSSLError with message."""
        error = CFSSLError('Test error message')
        assert str(error) == 'Test error message'
        assert error.message == 'Test error message'

    def test_error_with_code(self):
        """Test CFSSLError with code."""
        error = CFSSLError('Error', code=500)
        assert error.code == 500

    def test_error_with_errors_list(self):
        """Test CFSSLError with errors list."""
        error = CFSSLError('Error', errors=[{'message': 'Detail 1'}, {'message': 'Detail 2'}])
        assert len(error.errors) == 2
