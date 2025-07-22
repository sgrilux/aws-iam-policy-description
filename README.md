# AWS IAM Policy Description Tool

A Python CLI tool that analyzes AWS IAM policies and provides human-readable descriptions of permissions using both detailed action breakdowns and AI-powered summaries via Amazon Bedrock.

## Features

- 🔍 **Multiple Analysis Modes**:
  - Detailed action breakdown with descriptions
  - AI-powered policy summaries via Amazon Bedrock
  - Combined analysis (both detailed and AI summary)

- 📋 **Multiple Policy Sources**:
  - Local JSON files
  - AWS managed policies (by name or ARN)
  - IAM roles (all attached policies)
  - IAM users (all attached policies)

- 🎯 **Wildcard Support**: Automatically expands wildcard actions (e.g., `s3:Get*`, `ec2:Describe*`)

- 📊 **Multiple Output Formats**: Table, JSON, CSV, and HTML

- 🚀 **Performance**: Built-in caching for IAM definitions

## Quick Start

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd aws-iam-policy-description

# Create a virtual environment
python -m venv .venv

# Install dependencies
pip install -r requirements.txt

# For development
pip install -r requirements-dev.txt
```

### Basic Usage

```bash
# Analyze a local policy file
python main.py --file examples/s3_read_only.json

# Get AI-powered summary
python main.py --file examples/s3_read_only.json --analysis-mode description

# Analyze AWS managed policy
python main.py --name ReadOnlyAccess

# Analyze all policies for an IAM role
python main.py --role MyDeveloperRole --analysis-mode both

# Export to different formats
python main.py --file policy.json --output json --output-file analysis.json
```

## Analysis Modes

- `--analysis-mode actions` (default): Detailed IAM action breakdown
- `--analysis-mode description`: AI-generated summary via Amazon Bedrock  
- `--analysis-mode full`: Combined detailed actions + AI summary

## Output Formats

- **Table** (default): Rich formatted tables for terminal viewing
- **JSON**: Structured data for programmatic processing
- **CSV**: Spreadsheet-compatible format
- **HTML**: Web-friendly reports with styling

## Development

### Setup Development Environment

```bash
# Install development dependencies
make install-dev

# Install pre-commit hooks
make pre-commit-install
```

### Code Quality

This project uses comprehensive code quality tools:

```bash
# Run all quality checks
make all-checks

# Individual checks
make lint          # Flake8 linting
make format        # Black + isort formatting
make type-check    # MyPy type checking  
make docs-check    # Documentation coverage
make test          # Run test suite
make test-coverage # Tests with coverage report
```

### Pre-commit Hooks

Pre-commit hooks run automatically on every commit and include:

- **Code Formatting**: Black (120 char lines) + isort
- **Linting**: Flake8 with docstring/import checks
- **Type Checking**: MyPy with boto3 stubs
- **Testing**: Pytest automated test suite
- **Documentation**: 80% docstring coverage requirement

Run hooks manually:
```bash
make pre-commit-run
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
make test-coverage

# Run specific test categories
make test-unit
make test-integration
```

## Architecture

The tool is organized into focused modules:

- **main.py**: CLI interface and workflow orchestration
- **policy_fetcher.py**: AWS policy retrieval from various sources
- **policy_analyzer.py**: Policy analysis and action description mapping
- **bedrock_analyzer.py**: AI-powered analysis via Amazon Bedrock
- **output_formatter.py**: Multi-format output rendering
- **utils.py**: Common utilities and configuration

## Examples

The `examples/` directory contains sample policies demonstrating various features:

- `s3_read_only.json`: Basic S3 permissions
- `wildcard_actions.json`: Wildcard expansion examples
- `bedrock_analysis_policy.json`: Bedrock service permissions
- `data_scientist_policy.json`: Multi-service ML workflow policy
- `developer_policy.json`: Complex development environment policy
- `deny_policy.json`: Deny statement examples

See `examples/README.md` for detailed usage examples.

## Requirements

- Python 3.9+
- AWS credentials configured (for Bedrock and AWS managed policy analysis)
- Internet access (for IAM action definitions and Bedrock API)

### IAM Permissions for AI Analysis

When using `--analysis-mode description` or `--analysis-mode full`, the tool requires access to Amazon Bedrock. Your AWS credentials must have the following permissions:

#### Required IAM Policy for Bedrock Analysis

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "BedrockModelAccess",
            "Effect": "Allow",
            "Action": [
                "bedrock:InvokeModel"
            ],
            "Resource": [
                "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
            ]
        },
        {
            "Sid": "BedrockModelListing",
            "Effect": "Allow",
            "Action": [
                "bedrock:ListFoundationModels"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Additional IAM Permissions for AWS Policy Analysis

If you plan to analyze AWS managed policies, IAM roles, or users (using `--name`, `--role`, or `--user` options), you also need:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "IAMReadAccess",
            "Effect": "Allow",
            "Action": [
                "iam:GetPolicy",
                "iam:GetPolicyVersion",
                "iam:GetRole",
                "iam:GetUser",
                "iam:ListAttachedRolePolicies",
                "iam:ListAttachedUserPolicies",
                "iam:ListRolePolicies",
                "iam:ListUserPolicies",
                "iam:GetRolePolicy",
                "iam:GetUserPolicy"
            ],
            "Resource": "*"
        },
        {
            "Sid": "STSCallerIdentity",
            "Effect": "Allow",
            "Action": [
                "sts:GetCallerIdentity"
            ],
            "Resource": "*"
        }
    ]
}
```

#### Minimal Permissions for Local File Analysis

For analyzing local policy files only (no `--analysis-mode description`), no AWS permissions are required. The tool will fetch IAM action definitions from a public GitHub repository.

#### Bedrock Model Regions

The tool defaults to `eu-central-1` for Bedrock access. Ensure Bedrock is available and you have model access in your chosen region. You can specify a different region in the tool's configuration if needed.

**Note**: Amazon Bedrock model access may require additional setup in the AWS console to enable specific foundation models in your account.

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Install development dependencies: `make install-dev`
4. Install pre-commit hooks: `make pre-commit-install`
5. Make your changes
6. Run quality checks: `make all-checks`
7. Commit your changes (pre-commit hooks will run)
8. Push and create a pull request
