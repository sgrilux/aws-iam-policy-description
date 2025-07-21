"""
Unit tests for output_formatter module.
"""

import json
import pytest
from unittest.mock import Mock, patch

from output_formatter import (
    format_output_table,
    format_output_json,
    format_output_csv,
    format_output_html,
    output_results
)


class TestFormatOutputTable:
    """Test cases for format_output_table function."""

    @patch('output_formatter.Console')
    def test_format_output_table_basic(self, mock_console_class, sample_processed_permissions):
        """Test basic table formatting."""
        mock_console = Mock()
        mock_console_class.return_value = mock_console

        format_output_table(sample_processed_permissions)

        # Verify console was created and print was called
        mock_console_class.assert_called_once()
        mock_console.print.assert_called_once()

    @patch('output_formatter.Console')
    def test_format_output_table_with_principals(self, mock_console_class):
        """Test table formatting with principal information."""
        mock_console = Mock()
        mock_console_class.return_value = mock_console

        # Create test data with principals
        permissions_with_principals = [
            {
                "Sid": "TestStatement",
                "Effect": "Allow",
                "Resource": ["*"],
                "Condition": {},
                "Principal": {
                    "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
                },
                "PolicyMetadata": {
                    "PolicyName": "TestPolicy",
                    "PolicyType": "Trust"
                },
                "actions": {
                    "sts:AssumeRole": "Grants permission to assume a role"
                }
            }
        ]

        format_output_table(permissions_with_principals)

        mock_console_class.assert_called_once()
        mock_console.print.assert_called_once()

    @patch('output_formatter.Console')
    def test_format_output_table_empty_permissions(self, mock_console_class):
        """Test table formatting with empty permissions."""
        mock_console = Mock()
        mock_console_class.return_value = mock_console

        format_output_table([])

        mock_console_class.assert_called_once()
        mock_console.print.assert_called_once()


class TestFormatOutputJson:
    """Test cases for format_output_json function."""

    def test_format_output_json_basic(self, sample_processed_permissions):
        """Test basic JSON formatting."""
        result = format_output_json(sample_processed_permissions)

        # Parse the result to verify it's valid JSON
        parsed = json.loads(result)
        assert parsed == sample_processed_permissions

        # Verify it's properly formatted (indented)
        assert '\n' in result
        assert '  ' in result  # Indentation

    def test_format_output_json_empty(self):
        """Test JSON formatting with empty data."""
        result = format_output_json([])
        assert result == "[]"

    def test_format_output_json_special_characters(self):
        """Test JSON formatting with special characters."""
        test_data = [{
            "test": "value with \"quotes\" and \\ backslashes",
            "unicode": "🔐 test"
        }]

        result = format_output_json(test_data)
        parsed = json.loads(result)
        assert parsed == test_data


class TestFormatOutputCsv:
    """Test cases for format_output_csv function."""

    def test_format_output_csv_basic(self, sample_processed_permissions):
        """Test basic CSV formatting."""
        result = format_output_csv(sample_processed_permissions)

        # Verify header is present
        assert result.startswith('Statement,PolicyName,PolicyType,Sid,Action,Description,Effect,Resource,Principal,Condition')

        # Verify data rows are present
        assert 'TestPolicy' in result
        assert 'Managed' in result
        assert 's3:GetObject' in result
        assert 's3:ListBucket' in result
        assert 's3:DeleteObject' in result

    def test_format_output_csv_with_principals(self):
        """Test CSV formatting with principal information."""
        permissions_with_principals = [
            {
                "Sid": "TestStatement",
                "Effect": "Allow",
                "Resource": ["*"],
                "Condition": {},
                "Principal": {
                    "Service": ["ec2.amazonaws.com"],
                    "AWS": "arn:aws:iam::123456789012:user/testuser"
                },
                "PolicyMetadata": {
                    "PolicyName": "TestPolicy",
                    "PolicyType": "Trust"
                },
                "actions": {
                    "sts:AssumeRole": "Grants permission to assume a role"
                }
            }
        ]

        result = format_output_csv(permissions_with_principals)

        # Verify principal information is included
        assert 'Service: ec2.amazonaws.com' in result
        assert 'AWS: arn:aws:iam::123456789012:user/testuser' in result

    def test_format_output_csv_empty(self):
        """Test CSV formatting with empty data."""
        result = format_output_csv([])

        # Should still have header
        assert result.startswith('Statement,PolicyName,PolicyType,Sid,Action,Description,Effect,Resource,Principal,Condition')
        # But no data rows
        assert result.count('\n') == 1

    def test_format_output_csv_special_characters(self):
        """Test CSV formatting with special characters."""
        special_permissions = [
            {
                "Sid": "Test,With,Commas",
                "Effect": "Allow",
                "Resource": ['arn:aws:s3:::bucket"with"quotes'],
                "Condition": {},
                "Principal": {},
                "PolicyMetadata": {
                    "PolicyName": "Test\nPolicy",
                    "PolicyType": "Managed"
                },
                "actions": {
                    "s3:GetObject": "Description with, commas and \"quotes\""
                }
            }
        ]

        result = format_output_csv(special_permissions)

        # Should be properly escaped/quoted
        assert 'Test,With,Commas' in result or '"Test,With,Commas"' in result


class TestFormatOutputHtml:
    """Test cases for format_output_html function."""

    def test_format_output_html_basic(self, sample_processed_permissions):
        """Test basic HTML formatting."""
        result = format_output_html(sample_processed_permissions)

        # Verify basic HTML structure
        assert result.startswith('<!DOCTYPE html>')
        assert '<html>' in result
        assert '<head>' in result
        assert '<title>IAM Policy Description</title>' in result
        assert '<body>' in result
        assert '</html>' in result

        # Verify content is present
        assert 'TestPolicy' in result
        assert 's3:GetObject' in result
        assert 's3:ListBucket' in result
        assert 's3:DeleteObject' in result

    def test_format_output_html_with_principals(self):
        """Test HTML formatting with principal information."""
        permissions_with_principals = [
            {
                "Sid": "TestStatement",
                "Effect": "Allow",
                "Resource": ["*"],
                "Condition": {},
                "Principal": {
                    "Service": ["ec2.amazonaws.com"],
                    "AWS": "arn:aws:iam::123456789012:user/testuser"
                },
                "PolicyMetadata": {
                    "PolicyName": "TestPolicy",
                    "PolicyType": "Trust"
                },
                "actions": {
                    "sts:AssumeRole": "Grants permission to assume a role"
                }
            }
        ]

        result = format_output_html(permissions_with_principals)

        # Verify principal column is added
        assert '<th>Principal</th>' in result
        assert 'Service: ec2.amazonaws.com' in result
        assert 'AWS: arn:aws:iam::123456789012:user/testuser' in result

    def test_format_output_html_empty(self):
        """Test HTML formatting with empty data."""
        result = format_output_html([])

        # Should still have basic HTML structure
        assert result.startswith('<!DOCTYPE html>')
        assert '<title>IAM Policy Description</title>' in result
        assert '</html>' in result

    def test_format_output_html_special_characters(self):
        """Test HTML formatting with special characters that need escaping."""
        special_permissions = [
            {
                "Sid": "Test<Script>",
                "Effect": "Allow",
                "Resource": ["arn:aws:s3:::bucket&test"],
                "Condition": {},
                "Principal": {},
                "PolicyMetadata": {
                    "PolicyName": "Test&Policy",
                    "PolicyType": "Managed"
                },
                "actions": {
                    "s3:GetObject": "Description with <tags> & ampersands"
                }
            }
        ]

        result = format_output_html(special_permissions)

        # HTML should be properly formed (basic check)
        assert '<html>' in result
        assert '</html>' in result


class TestOutputResults:
    """Test cases for output_results function."""

    @patch('output_formatter.format_output_table')
    def test_output_results_table_format(self, mock_format_table, sample_processed_permissions):
        """Test output results with table format."""
        output_results(sample_processed_permissions, 'table')
        mock_format_table.assert_called_once_with(sample_processed_permissions)

    @patch('builtins.print')
    def test_output_results_json_format_stdout(self, mock_print, sample_processed_permissions):
        """Test output results with JSON format to stdout."""
        output_results(sample_processed_permissions, 'json')
        mock_print.assert_called_once()

        # Verify the printed content is valid JSON
        printed_content = mock_print.call_args[0][0]
        parsed = json.loads(printed_content)
        assert parsed == sample_processed_permissions

    @patch('builtins.open', create=True)
    def test_output_results_json_format_file(self, mock_open, sample_processed_permissions):
        """Test output results with JSON format to file."""
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        output_results(sample_processed_permissions, 'json', 'output.json')

        mock_open.assert_called_once_with('output.json', 'w')
        mock_file.write.assert_called_once()

        # Verify written content is valid JSON
        written_content = mock_file.write.call_args[0][0]
        parsed = json.loads(written_content)
        assert parsed == sample_processed_permissions

    @patch('builtins.print')
    def test_output_results_csv_format_stdout(self, mock_print, sample_processed_permissions):
        """Test output results with CSV format to stdout."""
        output_results(sample_processed_permissions, 'csv')
        mock_print.assert_called_once()

        # Verify the printed content has CSV header
        printed_content = mock_print.call_args[0][0]
        assert printed_content.startswith('Statement,PolicyName,PolicyType')

    @patch('builtins.open', create=True)
    def test_output_results_csv_format_file(self, mock_open, sample_processed_permissions):
        """Test output results with CSV format to file."""
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        output_results(sample_processed_permissions, 'csv', 'output.csv')

        mock_open.assert_called_once_with('output.csv', 'w')
        mock_file.write.assert_called_once()

        # Verify written content has CSV header
        written_content = mock_file.write.call_args[0][0]
        assert written_content.startswith('Statement,PolicyName,PolicyType')

    @patch('builtins.print')
    def test_output_results_html_format_stdout(self, mock_print, sample_processed_permissions):
        """Test output results with HTML format to stdout."""
        output_results(sample_processed_permissions, 'html')
        mock_print.assert_called_once()

        # Verify the printed content is HTML
        printed_content = mock_print.call_args[0][0]
        assert printed_content.startswith('<!DOCTYPE html>')

    @patch('builtins.open', create=True)
    def test_output_results_html_format_file(self, mock_open, sample_processed_permissions):
        """Test output results with HTML format to file."""
        mock_file = Mock()
        mock_open.return_value.__enter__.return_value = mock_file

        output_results(sample_processed_permissions, 'html', 'output.html')

        mock_open.assert_called_once_with('output.html', 'w')
        mock_file.write.assert_called_once()

        # Verify written content is HTML
        written_content = mock_file.write.call_args[0][0]
        assert written_content.startswith('<!DOCTYPE html>')

    def test_output_results_unsupported_format(self, sample_processed_permissions):
        """Test output results with unsupported format."""
        with pytest.raises(ValueError) as exc_info:
            output_results(sample_processed_permissions, 'unsupported')
        assert "Unsupported output format" in str(exc_info.value)
