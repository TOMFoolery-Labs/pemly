"""
Root pytest configuration for PEMLY tests.

This file is automatically loaded by pytest and provides:
- Django configuration
- Common fixtures
"""

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def encryption_key():
    """Generate a valid Fernet encryption key for tests."""
    return Fernet.generate_key().decode()
