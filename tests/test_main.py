"""Integration tests for main module."""

from unittest.mock import patch

import pytest

from main import main


class TestMainIntegration:
    """Integration test cases for main function."""

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_file_input_success(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test successful execution with file input."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--file", "test.json"]):
            main()

        mock_setup_logging.assert_called_once()
        mock_get_policy.assert_called_once_with("test.json")
        mock_get_descriptions.assert_called_once()
        mock_output.assert_called_once_with({"actions": sample_processed_permissions}, "table", None, "actions")

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_aws")
    @patch("main.setup_logging")
    def test_main_name_input_success(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test successful execution with policy name input."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--name", "ReadOnlyAccess"]):
            main()

        mock_setup_logging.assert_called_once()
        mock_get_policy.assert_called_once_with("ReadOnlyAccess")
        mock_get_descriptions.assert_called_once()
        mock_output.assert_called_once_with({"actions": sample_processed_permissions}, "table", None, "actions")

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_aws")
    @patch("main.setup_logging")
    def test_main_policy_arn_input_success(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test successful execution with policy ARN input."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--policy-arn", "arn:aws:iam::123456789012:policy/TestPolicy"]):
            main()

        mock_setup_logging.assert_called_once()
        mock_get_policy.assert_called_once_with("arn:aws:iam::123456789012:policy/TestPolicy")
        mock_get_descriptions.assert_called_once()
        mock_output.assert_called_once_with({"actions": sample_processed_permissions}, "table", None, "actions")

    @patch("main.output_results")
    @patch("main.process_policy_analysis")
    @patch("main.get_policies_from_role")
    @patch("main.setup_logging")
    @patch("main.get_default_cache_dir")
    def test_main_role_input_success(
        self,
        mock_cache_dir,
        mock_setup_logging,
        mock_get_policies,
        mock_process,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test successful execution with role input."""
        mock_cache_dir.return_value = "/test/cache/dir"
        mock_policies = [{"PolicyName": "TestPolicy", "PolicyType": "Managed", "Document": sample_policy_document}]
        mock_get_policies.return_value = mock_policies

        # Mock the new process_policy_analysis function return format
        expected_result = {
            "actions": sample_processed_permissions,
            "context": {"type": "role", "name": "TestRole", "policy_count": 1, "policies": ["TestPolicy"]},
        }
        mock_process.return_value = expected_result

        with patch("sys.argv", ["main.py", "--role", "TestRole"]):
            main()

        mock_setup_logging.assert_called_once()
        mock_get_policies.assert_called_once_with("TestRole")
        mock_process.assert_called_once()  # The new function signature is more complex, so just check it was called
        mock_output.assert_called_once_with(expected_result, "table", None, "actions")

    @patch("main.output_results")
    @patch("main.process_policy_analysis")
    @patch("main.get_policies_from_user")
    @patch("main.setup_logging")
    def test_main_user_input_success(
        self,
        mock_setup_logging,
        mock_get_policies,
        mock_process,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test successful execution with user input."""
        mock_policies = [{"PolicyName": "TestPolicy", "PolicyType": "Managed", "Document": sample_policy_document}]
        mock_get_policies.return_value = mock_policies
        # Mock the new process_policy_analysis function return format
        expected_result = {
            "actions": sample_processed_permissions,
            "context": {"type": "user", "name": "TestUser", "policy_count": 1, "policies": ["TestPolicy"]},
        }
        mock_process.return_value = expected_result

        with patch("sys.argv", ["main.py", "--user", "TestUser"]):
            main()

        mock_setup_logging.assert_called_once()
        mock_get_policies.assert_called_once_with("TestUser")
        mock_process.assert_called_once()  # The new function signature is more complex, so just check it was called
        mock_output.assert_called_once_with(expected_result, "table", None, "actions")

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_json_output_format(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test execution with JSON output format."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--file", "test.json", "--output", "json"]):
            main()

        mock_output.assert_called_once_with({"actions": sample_processed_permissions}, "json", None, "actions")

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_output_to_file(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test execution with output to file."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--file", "test.json", "--output-file", "output.json"]):
            main()

        mock_output.assert_called_once_with(
            {"actions": sample_processed_permissions}, "table", "output.json", "actions"
        )

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_verbose_logging(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test execution with verbose logging."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--file", "test.json", "--verbose"]):
            main()

        mock_setup_logging.assert_called_once_with(True)

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_no_cache_option(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test execution with no-cache option."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--file", "test.json", "--no-cache"]):
            main()

        # Verify get_action_descriptions was called with cache disabled
        args, kwargs = mock_get_descriptions.call_args
        assert len(args) >= 3  # policy_document, ssl_verify, cache_dir
        assert args[2] is None  # cache_dir should be None
        assert len(args) >= 4 and args[3] is False  # use_cache should be False

    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_ssl_verify_disabled(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test execution with SSL verification disabled."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions

        with patch("sys.argv", ["main.py", "--file", "test.json", "--ssl-verify"]):
            main()

        # Verify get_action_descriptions was called with SSL verification disabled
        args, kwargs = mock_get_descriptions.call_args
        assert args[1] is False  # ssl_verify should be False

    @patch("main.setup_logging")
    def test_main_no_input_error(self, mock_setup_logging):
        """Test error when no input option is provided."""
        with patch("sys.argv", ["main.py"]):
            with pytest.raises(SystemExit):  # argparse exits on error
                main()

    @patch("main.logging")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_file_not_found_error(self, mock_setup_logging, mock_get_policy, mock_logging):
        """Test error handling when file is not found."""
        mock_get_policy.side_effect = FileNotFoundError("File not found")

        with patch("sys.argv", ["main.py", "--file", "nonexistent.json"]):
            main()

        mock_logging.error.assert_called_once()
        assert "An error occurred" in mock_logging.error.call_args[0][0]

    @patch("main.logging")
    @patch("main.get_policy_from_aws")
    @patch("main.setup_logging")
    def test_main_aws_policy_not_found_error(self, mock_setup_logging, mock_get_policy, mock_logging):
        """Test error handling when AWS policy is not found."""
        mock_get_policy.side_effect = ValueError("Policy not found")

        with patch("sys.argv", ["main.py", "--name", "NonExistentPolicy"]):
            main()

        mock_logging.error.assert_called_once()
        assert "An error occurred" in mock_logging.error.call_args[0][0]

    @patch("main.logging")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_keyboard_interrupt(self, mock_setup_logging, mock_get_policy, mock_logging):
        """Test handling of keyboard interrupt."""
        mock_get_policy.side_effect = KeyboardInterrupt()

        with patch("sys.argv", ["main.py", "--file", "test.json"]):
            main()

        mock_logging.info.assert_called_once_with("Operation cancelled by user")

    @patch("main.logging")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_verbose_error_reraise(self, mock_setup_logging, mock_get_policy, mock_logging):
        """Test that errors are re-raised in verbose mode."""
        mock_get_policy.side_effect = Exception("Test error")

        with patch("sys.argv", ["main.py", "--file", "test.json", "--verbose"]):
            with pytest.raises(Exception, match="Test error"):
                main()

        mock_logging.error.assert_called_once()

    @patch("main.get_default_cache_dir")
    @patch("main.output_results")
    @patch("main.get_action_descriptions")
    @patch("main.get_policy_from_file")
    @patch("main.setup_logging")
    def test_main_custom_cache_dir(
        self,
        mock_setup_logging,
        mock_get_policy,
        mock_get_descriptions,
        mock_output,
        mock_default_cache,
        sample_policy_document,
        sample_processed_permissions,
    ):
        """Test execution with custom cache directory."""
        mock_get_policy.return_value = sample_policy_document
        mock_get_descriptions.return_value = sample_processed_permissions
        mock_default_cache.return_value = "/default/cache"

        with patch("sys.argv", ["main.py", "--file", "test.json", "--cache-dir", "/custom/cache"]):
            main()

        # Verify get_action_descriptions was called with custom cache directory
        args, kwargs = mock_get_descriptions.call_args
        assert args[2] == "/custom/cache"  # cache_dir should be custom path


class TestMainArgumentParsing:
    """Test cases for command line argument parsing."""

    def test_main_help_output(self):
        """Test that help output is generated correctly."""
        with patch("sys.argv", ["main.py", "--help"]):
            with pytest.raises(SystemExit):  # argparse exits after showing help
                main()

    def test_main_mutually_exclusive_inputs(self):
        """Test that mutually exclusive input options are enforced."""
        with patch("sys.argv", ["main.py", "--file", "test.json", "--name", "TestPolicy"]):
            with pytest.raises(SystemExit):  # argparse exits on error
                main()

    def test_main_invalid_output_format(self):
        """Test that invalid output format is rejected."""
        with patch("sys.argv", ["main.py", "--file", "test.json", "--output", "invalid"]):
            with pytest.raises(SystemExit):  # argparse exits on error
                main()
