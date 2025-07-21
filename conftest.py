"""
Pytest configuration and fixtures for the AWS IAM Policy Description Tool.
"""

import pytest
import os
import tempfile
import json
from unittest.mock import Mock


@pytest.fixture(scope="module")
def sample_processed_permissions():
    """Load sample processed permissions from JSON file."""
    with open('tests/fixtures/sample_processed_permissions.json', 'r') as f:
        return json.load(f)


@pytest.fixture(scope="module")
def sample_policy_document():
    """Load sample IAM policy document from JSON file."""
    with open('tests/fixtures/sample_policy_document.json', 'r') as f:
        return json.load(f)


@pytest.fixture(scope="module")
def sample_trust_policy():
    """Load sample trust policy for role testing."""
    with open('tests/fixtures/sample_trust_policy.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_iam_definitions():
    """Load sample IAM definitions for testing."""
    with open('tests/fixtures/sample_iam_definitions.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_get_policy_response():
    """Load sample AWS API responses for mocking."""
    with open('tests/fixtures/sample_get_policy_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_get_policy_version_response():
    """Load sample get policy version response."""
    with open('tests/fixtures/sample_get_policy_version_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_get_role_response():
    """Load sample get role response."""
    with open('tests/fixtures/sample_get_role_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_list_attached_role_policies_response():
    """Load sample list attached role policies response."""
    with open('tests/fixtures/sample_list_attached_role_policies_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_list_role_policies_response():
    """Load sample list role policies response."""
    with open('tests/fixtures/sample_list_role_policies_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_get_role_policy_response():
    """Load sample get role policy response."""
    with open('tests/fixtures/sample_get_role_policy_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_get_user_response():
    """Load sample get user response."""
    with open('tests/fixtures/sample_get_user_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_list_attached_user_policies_response():
    """Load sample list attached user policies response."""
    with open('tests/fixtures/sample_list_attached_user_policies_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_list_user_policies_response():
    """Load sample list user policies response."""
    with open('tests/fixtures/sample_list_user_policies_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_get_user_policy_response():
    """Load sample get user policy response."""
    with open('tests/fixtures/sample_get_user_policy_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def sample_get_caller_identity_response():
    """Load sample get caller identity response."""
    with open('tests/fixtures/sample_get_caller_identity_response.json', 'r') as f:
        return json.load(f)


@pytest.fixture
def temp_policy_file():
    """Fixture providing a temporary policy file."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_policy_document, f)
        f.flush()
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_invalid_json_file():
    """Fixture providing a temporary file with invalid JSON."""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("invalid json content")
        f.flush()
        yield f.name
    os.unlink(f.name)


@pytest.fixture
def temp_cache_dir():
    """Fixture providing a temporary cache directory."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


@pytest.fixture
def mock_boto3_client():
    """Fixture providing a mock boto3 client."""
    mock_client = Mock()
    return mock_client


@pytest.fixture
def mock_requests_response():
    """Fixture providing a mock requests response."""
    mock_response = Mock()
    mock_response.raise_for_status.return_value = None
    mock_response.text = json.dumps(sample_iam_definitions)
    return mock_response


@pytest.fixture(autouse=True)
def isolate_tests():
    """Fixture to isolate tests by clearing any cached modules."""
    # Clear any cached imports or state that might interfere between tests
    import sys
    modules_to_clear = [name for name in sys.modules.keys() if name.startswith('policy_')]
    for module in modules_to_clear:
        if module in sys.modules:
            del sys.modules[module]
    yield


def pytest_configure(config):
    """Configure pytest with custom settings."""
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as integration test"
    )
    config.addinivalue_line(
        "markers", "unit: mark test as unit test"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers automatically."""
    for item in items:
        # Add unit test marker to all tests by default
        if not any(marker.name in ['integration', 'slow'] for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)

        # Add integration marker to main tests
        if 'test_main' in item.nodeid:
            item.add_marker(pytest.mark.integration)

        # Add slow marker to tests that might be slow
        if any(keyword in item.name.lower() for keyword in ['fetch', 'request', 'aws']):
            item.add_marker(pytest.mark.slow)
