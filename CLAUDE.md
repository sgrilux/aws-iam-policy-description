# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Running the application
```bash
# Basic usage - analyze local policy files
python main.py --file examples/s3_read_only.json
python main.py --file examples/wildcard_actions.json

# AWS managed policies
python main.py --name ReadOnlyAccess
python main.py --name PowerUserAccess --verbose

# IAM Role analysis (fetches all attached policies)
python main.py --role MyRole --verbose
python main.py --role MyRole --output json --output-file role_analysis.json

# IAM User analysis (fetches all attached policies)
python main.py --user MyUser --verbose
python main.py --user MyUser --output csv --output-file user_permissions.csv

# Policy ARN support
python main.py --policy-arn arn:aws:iam::123456789012:policy/MyCustomPolicy
python main.py --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess

# Different output formats
python main.py --file examples/developer_policy.json --output json
python main.py --file examples/wildcard_actions.json --output csv --output-file results.csv
python main.py --file examples/permission_boundary.json --output html --output-file report.html

# Advanced options
python main.py --file examples/deny_policy.json --verbose
python main.py --name PowerUserAccess --no-cache
python main.py --file examples/ec2_trust_policy.json --ssl-verify
```

### Testing
```bash
# Run all tests
python -m pytest tests/ -v

# Run tests with coverage
python -m pytest tests/ --cov=. --cov-report=html

# Run specific test modules
python -m pytest tests/test_main.py -v
python -m pytest tests/test_policy_fetcher.py -v
python -m pytest tests/test_policy_analyzer.py -v
python -m pytest tests/test_output_formatter.py -v
python -m pytest tests/test_utils.py -v
```

### Installation
```bash
pip install -r requirements.txt
```

## Architecture

This is a Python CLI tool that analyzes AWS IAM policies and provides human-readable descriptions of permissions. The tool accepts IAM policies from multiple sources:
- Local JSON files
- AWS managed policies (by name or ARN)
- Customer managed policies (by name or ARN)
- All policies attached to IAM roles (managed, inline, and trust policies)
- All policies attached to IAM users (managed and inline)

It supports multiple output formats (table, JSON, CSV, HTML) and includes caching for improved performance.

### Module Structure

The application is organized into focused modules for better maintainability:

- **main.py**: Entry point and command-line interface
- **policy_fetcher.py**: AWS policy retrieval functions
- **policy_analyzer.py**: Policy analysis and IAM definitions processing
- **output_formatter.py**: Output formatting for different formats
- **utils.py**: Common utility functions

### Core Components

#### main.py
- Command-line argument parsing
- Orchestrates the workflow between modules
- Error handling and logging setup

#### policy_fetcher.py
- **get_policy_from_file()**: Loads and validates IAM policy from JSON file
- **get_policy_from_aws()**: Fetches IAM managed policies from AWS (supports names and ARNs)
- **get_policies_from_role()**: Fetches all policies attached to an IAM role
- **get_policies_from_user()**: Fetches all policies attached to an IAM user

#### policy_analyzer.py
- **validate_policy_document()**: Validates IAM policy structure and format
- **fetch_iam_definitions()**: Fetches IAM definitions with caching support
- **get_action_descriptions()**: Maps IAM actions to human-readable descriptions
- **process_multiple_policies()**: Processes multiple policies from roles/users
- **setup_logging()**: Configures logging with Rich formatting

#### output_formatter.py
- **format_output_table()**: Rich table formatting for terminal display
- **format_output_json()**: JSON output formatting
- **format_output_csv()**: CSV output formatting
- **format_output_html()**: HTML output formatting
- **output_results()**: Main output orchestrator

#### utils.py
- **get_default_cache_dir()**: Default cache directory location
- **normalize_to_list()**: Utility for normalizing values to lists

### Data Flow

1. **Input Processing** (main.py): Command-line arguments parsed and validated
2. **Policy Retrieval** (policy_fetcher.py): Policies fetched from various sources
3. **Policy Validation** (policy_analyzer.py): Policy document structure validated
4. **IAM Definitions** (policy_analyzer.py): IAM action definitions fetched with caching
5. **Action Analysis** (policy_analyzer.py): IAM actions mapped to descriptions
6. **Multiple Policy Processing** (policy_analyzer.py): Combined results for roles/users
7. **Output Formatting** (output_formatter.py): Results formatted in chosen format
8. **Output Delivery** (output_formatter.py): Results displayed or written to file

### Dependencies

- **boto3**: AWS SDK for fetching policies from IAM
- **rich**: Terminal formatting and table rendering
- **requests**: HTTP client for fetching IAM action definitions

The tool fetches IAM action definitions from `https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/iam_definition.json` to provide descriptions for each permission.

### Wildcard Action Support

The tool now supports wildcard actions and will automatically expand them to show all matching permissions:

- **Full service wildcards**: `s3:*` expands to all S3 actions
- **Prefix wildcards**: `s3:Get*` expands to all S3 actions starting with "Get" (e.g., GetObject, GetBucketPolicy)
- **Describe wildcards**: `ec2:Describe*` expands to all EC2 Describe actions
- **List wildcards**: `iam:List*` expands to all IAM List actions

When analyzing policies with wildcard actions, the tool will:
1. Show a summary of the wildcard (e.g., "All s3 actions starting with 'Get' (59 actions)")
2. List each individual action that matches the wildcard pattern
3. Provide descriptions for all expanded actions

This feature helps security teams understand the full scope of permissions granted by wildcard actions.

## Testing Guidelines

### Test Organization

The test suite is organized into modules that mirror the application structure:
- **tests/test_main.py**: Integration tests for command-line interface and main workflow
- **tests/test_policy_fetcher.py**: Unit tests for AWS policy fetching functionality
- **tests/test_policy_analyzer.py**: Unit tests for policy analysis and IAM definitions processing
- **tests/test_output_formatter.py**: Unit tests for output formatting in various formats
- **tests/test_utils.py**: Unit tests for utility functions

### Critical Testing Considerations

#### AWS Service Mocking

When testing functions that interact with AWS services (boto3), **ALWAYS** use proper mocking to avoid hitting real AWS APIs:

**✅ CORRECT - Use `@patch('boto3.client')` for proper mocking:**
```python
@patch('boto3.client')
def test_get_policy_from_aws(self, mock_boto3_client):
    mock_iam = Mock()
    mock_sts = Mock()
    
    # Set up IAM client exceptions (use specific exception classes)
    class NoSuchEntityException(ClientError):
        pass
    
    mock_iam.exceptions = Mock()
    mock_iam.exceptions.NoSuchEntityException = NoSuchEntityException
    
    # Set up STS client mock (always mock get_caller_identity)
    mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
    
    # Configure client side_effect for service selection
    mock_boto3_client.side_effect = lambda service: mock_iam if service == 'iam' else mock_sts
    
    # Set up specific method responses with proper structure
    mock_iam.get_policy.return_value = sample_get_policy_response
    mock_iam.get_policy_version.return_value = sample_get_policy_version_response
```

**❌ INCORRECT - Don't use module-level patching:**
```python
@patch('policy_fetcher.boto3')  # This doesn't work reliably in pytest
def test_get_policy_from_aws(self, mock_boto3):
    # This approach can hit real AWS APIs
```

#### Exception Handling Testing

For AWS exception testing, create specific exception classes that inherit from the correct base:
```python
# Create specific exception classes for proper type checking
class NoSuchEntityException(ClientError):
    pass

mock_iam.exceptions.NoSuchEntityException = NoSuchEntityException

# Use different exception types for different test scenarios
mock_iam.get_policy.side_effect = ClientError(
    {'Error': {'Code': 'AccessDenied'}}, 'GetPolicy'  # Not NoSuchEntity
)
```

#### Fixture Data Structure

Ensure test fixtures match AWS API response structures exactly:

**✅ CORRECT - list_attached_user_policies response:**
```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "TestPolicy",
            "PolicyArn": "arn:aws:iam::123456789012:policy/TestPolicy"
        }
    ]
}
```

**❌ INCORRECT - Don't confuse with inline policy response:**
```json
{
    "PolicyNames": ["InlineUserPolicy"]  // This is for list_user_policies, not list_attached_user_policies
}
```

#### Multi-Service Mocking

When functions call multiple AWS services (IAM + STS), mock both services:
```python
mock_boto3_client.side_effect = lambda service: mock_iam if service == 'iam' else mock_sts
mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
```

#### Function-Level Patching

For tests that need to mock both boto3 clients AND specific functions, add both patches and set up fallback mocking:
```python
@patch('boto3.client')
@patch('policy_fetcher.get_policy_from_aws')  # Function-level patch
def test_role_success(self, mock_get_policy, mock_boto3_client, ...):
    # Set up both the function mock AND the underlying client mock
    mock_get_policy.return_value = sample_policy_document
    
    # Also set up client mocks as fallback
    mock_iam.get_policy.return_value = sample_get_policy_response
    mock_iam.get_policy_version.return_value = sample_get_policy_version_response
```

### Test Fixtures

Test fixtures are located in `tests/fixtures/` and loaded via `conftest.py`. When modifying or adding fixtures:

1. **Verify Structure**: Ensure fixture data matches actual AWS API responses
2. **Update Related Tests**: Check if changes affect multiple test files
3. **Validate JSON**: Ensure all fixture JSON files are valid
4. **Document Changes**: Update test documentation when adding new fixtures

### Common Testing Pitfalls

1. **Missing STS Mock**: Always mock `get_caller_identity()` when functions use account IDs
2. **Wrong Exception Classes**: Use specific exception classes, not generic `ClientError`
3. **Incorrect Fixture Structure**: Match AWS API response structure exactly
4. **Module vs Function Patching**: Use `@patch('boto3.client')` for reliable mocking
5. **Missing Context**: Provide enough context in mocks for complex workflows

### Before Committing Tests

1. Run the full test suite: `python -m pytest tests/ -v`
2. Verify no tests are hitting real AWS APIs (should complete quickly)
3. Check for any skipped tests that need to be addressed
4. Ensure test coverage remains high for critical functions