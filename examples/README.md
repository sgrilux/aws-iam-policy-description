# AWS IAM Policy Examples

This directory contains example IAM policies demonstrating various use cases and features of the policy analysis tool.

## Example Policies

### 1. Basic S3 Read-Only Policy (`s3_read_only.json`)
A simple policy granting read-only access to S3 buckets and objects.

```bash
python main.py --file examples/s3_read_only.json
```

**Features demonstrated:**
- Basic Allow statements
- Multiple actions in a single statement
- S3 resource specifications

---

### 2. Deny Policy Example (`deny_policy.json`)
Shows how Deny statements work to explicitly prevent certain actions.

```bash
python main.py --file examples/deny_policy.json --verbose
```

**Features demonstrated:**
- Deny effect statements
- Policy precedence (Deny overrides Allow)
- Resource-specific restrictions

---

### 3. Wildcard Actions (`wildcard_actions.json`)
Demonstrates the tool's wildcard expansion capabilities with various wildcard patterns.

```bash
python main.py --file examples/wildcard_actions.json
```

**Features demonstrated:**
- Prefix wildcards (`s3:Get*`, `ec2:Describe*`)
- Wildcard expansion showing all matching actions
- Mixed wildcard and specific actions
- Both Allow and Deny with wildcards

**Try different output formats:**
```bash
# JSON output to see detailed structure
python main.py --file examples/wildcard_actions.json --output json

# CSV output for spreadsheet analysis
python main.py --file examples/wildcard_actions.json --output csv --output-file wildcard_analysis.csv

# HTML output for reports
python main.py --file examples/wildcard_actions.json --output html --output-file wildcard_report.html
```

---

### 4. Complex Developer Policy (`developer_policy.json`)
A comprehensive policy for a developer role with multiple services and conditions.

```bash
python main.py --file examples/developer_policy.json --verbose
```

**Features demonstrated:**
- Multi-service permissions
- Complex resource patterns
- Conditional statements
- Real-world policy structure

---

### 5. EC2 Trust Policy (`ec2_trust_policy.json`)
An assume role policy document (trust policy) for EC2 instances.

```bash
python main.py --file examples/ec2_trust_policy.json
```

**Features demonstrated:**
- Trust relationships
- Principal specifications
- Service-to-service permissions

---

### 6. Permission Boundary (`permission_boundary.json`)
A permission boundary policy that limits maximum permissions.

```bash
python main.py --file examples/permission_boundary.json
```

**Features demonstrated:**
- Permission boundary concepts
- Maximum permission limits
- Security guardrails

---

### 7. Bedrock Analysis Policy (`bedrock_analysis_policy.json`)
A policy for applications that use Amazon Bedrock for AI model invocation.

```bash
python main.py --file examples/bedrock_analysis_policy.json --analysis-mode both
```

**Features demonstrated:**
- Bedrock model invocation permissions
- AI-generated policy summaries
- Combined analysis modes

---

### 8. Data Scientist Policy (`data_scientist_policy.json`)
A comprehensive policy for data scientists using multiple AWS AI/ML services.

```bash
python main.py --file examples/data_scientist_policy.json --analysis-mode description
```

**Features demonstrated:**
- Multi-service AI/ML permissions  
- Complex Deny conditions
- AI-powered policy analysis

## Advanced Usage Examples

### AI-Powered Policy Analysis with Bedrock

The tool now supports AI-powered policy analysis using Amazon Bedrock. This provides natural language descriptions of what policies do, their security implications, and potential risks.

```bash
# Get only AI description (no detailed action breakdown)
python main.py --file examples/data_scientist_policy.json --analysis-mode description

# Get both AI description and detailed actions
python main.py --file examples/bedrock_analysis_policy.json --analysis-mode both

# Use different Bedrock models
python main.py --file examples/developer_policy.json --analysis-mode description --bedrock-model anthropic.claude-3-haiku-20240307-v1:0

# Specify Bedrock region
python main.py --file examples/wildcard_actions.json --analysis-mode both --bedrock-region us-west-2
```

**Analysis Mode Options:**
- `--analysis-mode actions` (default) - Detailed action breakdown only
- `--analysis-mode description` - AI-generated summary only  
- `--analysis-mode both` - Both AI summary and detailed actions

**Note:** Bedrock analysis requires appropriate AWS permissions for the `bedrock:InvokeModel` action.

### Analyze AWS Managed Policies
```bash
# Analyze AWS managed ReadOnlyAccess policy
python main.py --name ReadOnlyAccess

# Analyze PowerUserAccess policy with AI description
python main.py --name PowerUserAccess --analysis-mode description --verbose

# Export SecurityAudit policy with both analyses to JSON
python main.py --name SecurityAudit --analysis-mode both --output json --output-file security_audit.json
```

### Analyze IAM Roles and Users
```bash
# Analyze all policies attached to an IAM role
python main.py --role MyDeveloperRole --verbose

# Analyze all policies attached to an IAM user
python main.py --user john.doe --output csv --output-file user_permissions.csv

# Analyze role with custom cache directory
python main.py --role MyRole --cache-dir /tmp/iam-cache
```

### Working with Customer Managed Policies
```bash
# Analyze by policy ARN
python main.py --policy-arn arn:aws:iam::123456789012:policy/MyCustomPolicy

# Analyze with SSL verification disabled (for corporate networks)
python main.py --name MyPolicy --ssl-verify
```

### Cache Management
```bash
# Disable caching for fresh data
python main.py --file examples/developer_policy.json --no-cache

# Use custom cache directory
python main.py --file examples/wildcard_actions.json --cache-dir /custom/cache/path
```

## Output Formats

The tool supports multiple output formats for different use cases:

### Table Format (Default)
Best for terminal viewing and quick analysis:
```bash
python main.py --file examples/s3_read_only.json
```

### JSON Format
Best for programmatic processing and detailed analysis:
```bash
python main.py --file examples/wildcard_actions.json --output json
```

### CSV Format
Best for spreadsheet analysis and reporting:
```bash
python main.py --file examples/developer_policy.json --output csv --output-file analysis.csv
```

### HTML Format
Best for reports and documentation:
```bash
python main.py --file examples/wildcard_actions.json --output html --output-file report.html
```

## Understanding Wildcard Expansion

The tool now automatically expands wildcard actions to show all matching permissions:

**Example with `s3:Get*`:**
- Shows summary: "All s3 actions starting with 'Get' (59 actions)"
- Lists all individual actions: `s3:GetObject`, `s3:GetBucketPolicy`, etc.
- Provides descriptions for each expanded action

**Common wildcard patterns:**
- `s3:*` - All S3 actions
- `s3:Get*` - All S3 Get actions (GetObject, GetBucketPolicy, etc.)
- `ec2:Describe*` - All EC2 Describe actions (DescribeInstances, DescribeImages, etc.)
- `iam:List*` - All IAM List actions (ListUsers, ListRoles, etc.)

## Tips for Analysis

1. **Start with verbose mode** (`--verbose`) to see detailed logging
2. **Use JSON output** for complex policies to see full structure
3. **Analyze wildcards carefully** - they often grant more permissions than expected
4. **Check both Allow and Deny statements** - Deny always overrides Allow
5. **Use role/user analysis** to see combined effect of multiple policies
6. **Export results** to files for documentation and compliance

## Security Considerations

When analyzing policies, pay attention to:

- **Overly broad wildcards** (`*:*`, `s3:*` on all resources)
- **Dangerous actions** (IAM management, security configuration changes)
- **Resource scope** (policies affecting all resources with `*`)
- **Cross-account access** (principals from other accounts)
- **Privilege escalation paths** (ability to modify IAM policies/roles)

## Getting Help

For command-line help:
```bash
python main.py --help
```

For more information about specific features, check the main project documentation.
