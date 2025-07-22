"""Unit tests for policy_fetcher module."""

import json
import tempfile
from unittest.mock import Mock, patch

import pytest
from botocore.exceptions import ClientError

from policy_fetcher import get_policies_from_role, get_policies_from_user, get_policy_from_aws, get_policy_from_file


class TestGetPolicyFromFile:
    """Test cases for get_policy_from_file function."""

    def test_get_policy_from_file_success(self, sample_policy_document):
        """Test successful policy loading from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(sample_policy_document, f)
            f.flush()

            result = get_policy_from_file(f.name)
            assert result == sample_policy_document

    def test_get_policy_from_file_not_found(self):
        """Test file not found error."""
        with pytest.raises(FileNotFoundError) as exc_info:
            get_policy_from_file("/nonexistent/file.json")
        assert "Policy file not found" in str(exc_info.value)

    def test_get_policy_from_file_invalid_json(self):
        """Test invalid JSON error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("invalid json content")
            f.flush()

            with pytest.raises(ValueError) as exc_info:
                get_policy_from_file(f.name)
            assert "Invalid JSON" in str(exc_info.value)

    def test_get_policy_from_file_not_dict(self):
        """Test error when policy is not a dictionary."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(["not", "a", "dict"], f)
            f.flush()

            with pytest.raises(ValueError) as exc_info:
                get_policy_from_file(f.name)
            assert "Policy must be a JSON object" in str(exc_info.value)


class TestGetPolicyFromAws:
    """Test cases for get_policy_from_aws function."""

    @patch("boto3.client")
    def test_get_policy_from_aws_by_name(
        self, mock_boto3_client, sample_policy_document, sample_get_policy_response, sample_get_policy_version_response
    ):
        """Test fetching AWS managed policy by name."""
        mock_iam = Mock()

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        # Set up client mock to return the IAM client for any service (simplified)
        mock_boto3_client.return_value = mock_iam

        mock_iam.get_policy.return_value = sample_get_policy_response
        mock_iam.get_policy_version.return_value = sample_get_policy_version_response

        result = get_policy_from_aws("TestPolicy")

        assert result == sample_policy_document
        mock_iam.get_policy.assert_called_once_with(PolicyArn="arn:aws:iam::aws:policy/TestPolicy")

    @patch("boto3.client")
    def test_get_policy_from_aws_by_arn(
        self, mock_boto3_client, sample_policy_document, sample_get_policy_response, sample_get_policy_version_response
    ):
        """Test fetching policy by ARN."""
        mock_iam = Mock()

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        # Set up client mock to return the IAM client for any service (simplified)
        mock_boto3_client.return_value = mock_iam

        mock_iam.get_policy.return_value = sample_get_policy_response
        mock_iam.get_policy_version.return_value = sample_get_policy_version_response

        arn = "arn:aws:iam::123456789012:policy/TestPolicy"
        result = get_policy_from_aws(arn)

        assert result == sample_policy_document
        mock_iam.get_policy.assert_called_once_with(PolicyArn=arn)

    @patch("boto3.client")
    def test_get_policy_from_aws_customer_managed_fallback(
        self,
        mock_boto3_client,
        sample_policy_document,
        sample_get_policy_response,
        sample_get_policy_version_response,
        sample_get_caller_identity_response,
    ):
        """Test fallback to customer managed policy when AWS managed not found."""
        mock_iam = Mock()
        mock_sts = Mock()

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts

        # First call fails (AWS managed), second succeeds (customer managed)
        mock_iam.get_policy.side_effect = [
            ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetPolicy"),
            sample_get_policy_response,
        ]
        mock_iam.get_policy_version.return_value = sample_get_policy_version_response
        mock_sts.get_caller_identity.return_value = sample_get_caller_identity_response

        result = get_policy_from_aws("TestPolicy")

        assert result == sample_policy_document
        assert mock_iam.get_policy.call_count == 2

    @patch("boto3.client")
    def test_get_policy_from_aws_not_found(self, mock_boto3_client):
        """Test error when policy is not found."""
        mock_iam = Mock()
        mock_sts = Mock()

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        # Set up STS client mock
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts

        # Set up both calls to get_policy to fail
        mock_iam.get_policy.side_effect = [
            ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetPolicy"),  # AWS managed policy fails
            ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetPolicy"),  # Customer managed policy fails
        ]

        with pytest.raises(ValueError) as exc_info:
            get_policy_from_aws("NonExistentPolicy")
        assert "not found" in str(exc_info.value)

    @patch("boto3.client")
    def test_get_policy_from_aws_other_error(self, mock_boto3_client):
        """Test handling of other AWS errors."""
        mock_iam = Mock()
        mock_sts = Mock()

        # Create a specific NoSuchEntityException class
        class NoSuchEntityException(ClientError):
            pass

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = NoSuchEntityException

        # Set up STS client mock
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts
        mock_iam.get_policy.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetPolicy")

        with pytest.raises(Exception) as exc_info:
            get_policy_from_aws("TestPolicy")
        assert "Failed to fetch policy from AWS" in str(exc_info.value)


class TestGetPoliciesFromRole:
    """Test cases for get_policies_from_role function."""

    @patch("boto3.client")
    @patch("policy_fetcher.get_policy_from_aws")
    def test_get_policies_from_role_success(
        self,
        mock_get_policy,
        mock_boto3_client,
        sample_policy_document,
        sample_get_role_response,
        sample_list_attached_role_policies_response,
        sample_list_role_policies_response,
        sample_get_role_policy_response,
        sample_get_caller_identity_response,
        sample_get_policy_response,
        sample_get_policy_version_response,
    ):
        """Test successful fetching of all policies from a role."""
        mock_iam = Mock()
        mock_sts = Mock()
        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        mock_iam.get_role.return_value = sample_get_role_response
        mock_iam.list_attached_role_policies.return_value = sample_list_attached_role_policies_response
        mock_iam.list_role_policies.return_value = sample_list_role_policies_response
        mock_iam.get_role_policy.return_value = sample_get_role_policy_response
        mock_sts.get_caller_identity.return_value = sample_get_caller_identity_response
        mock_get_policy.return_value = sample_policy_document

        # Also set up the IAM client for get_policy calls that might happen
        mock_iam.get_policy.return_value = sample_get_policy_response
        mock_iam.get_policy_version.return_value = sample_get_policy_version_response

        result = get_policies_from_role("TestRole")

        assert len(result) == 3  # 1 managed + 1 inline + 1 trust policy
        assert result[0]["PolicyType"] == "Managed"
        assert result[1]["PolicyType"] == "Inline"
        assert result[2]["PolicyType"] == "Trust"
        assert result[2]["PolicyName"] == "AssumeRolePolicyDocument"

    @patch("boto3.client")
    def test_get_policies_from_role_not_found(self, mock_boto3_client):
        """Test error when role is not found."""
        mock_iam = Mock()
        mock_sts = Mock()

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        # Set up STS client mock
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts
        mock_iam.get_role.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetRole")

        with pytest.raises(ValueError) as exc_info:
            get_policies_from_role("NonExistentRole")
        assert "not found" in str(exc_info.value)

    @patch("boto3.client")
    def test_get_policies_from_role_other_error(self, mock_boto3_client):
        """Test handling of other AWS errors."""
        mock_iam = Mock()
        mock_sts = Mock()

        # Create a specific NoSuchEntityException class
        class NoSuchEntityException(ClientError):
            pass

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = NoSuchEntityException

        # Set up STS client mock
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts
        mock_iam.get_role.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetRole")

        with pytest.raises(Exception) as exc_info:
            get_policies_from_role("TestRole")
        assert "Failed to fetch policies from role" in str(exc_info.value)


class TestGetPoliciesFromUser:
    """Test cases for get_policies_from_user function."""

    @patch("boto3.client")
    @patch("policy_fetcher.get_policy_from_aws")
    def test_get_policies_from_user_success(
        self,
        mock_get_policy,
        mock_boto3_client,
        sample_policy_document,
        sample_get_user_response,
        sample_list_attached_user_policies_response,
        sample_list_user_policies_response,
        sample_get_user_policy_response,
        sample_get_caller_identity_response,
        sample_get_policy_response,
        sample_get_policy_version_response,
    ):
        """Test successful fetching of all policies from a user."""
        mock_iam = Mock()
        mock_sts = Mock()
        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        mock_iam.get_user.return_value = sample_get_user_response
        mock_iam.list_attached_user_policies.return_value = sample_list_attached_user_policies_response
        mock_iam.list_user_policies.return_value = sample_list_user_policies_response
        mock_iam.get_user_policy.return_value = sample_get_user_policy_response
        mock_sts.get_caller_identity.return_value = sample_get_caller_identity_response
        mock_get_policy.return_value = sample_policy_document

        # Also set up the IAM client for get_policy calls that might happen
        mock_iam.get_policy.return_value = sample_get_policy_response
        mock_iam.get_policy_version.return_value = sample_get_policy_version_response

        result = get_policies_from_user("TestUser")

        assert len(result) == 2  # 1 managed + 1 inline
        assert result[0]["PolicyType"] == "Managed"
        assert result[1]["PolicyType"] == "Inline"

    @patch("boto3.client")
    def test_get_policies_from_user_not_found(self, mock_boto3_client):
        """Test error when user is not found."""
        mock_iam = Mock()
        mock_sts = Mock()

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = ClientError

        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts
        mock_iam.get_user.side_effect = ClientError({"Error": {"Code": "NoSuchEntity"}}, "GetUser")

        with pytest.raises(ValueError) as exc_info:
            get_policies_from_user("NonExistentUser")
        assert "not found" in str(exc_info.value)

    @patch("boto3.client")
    def test_get_policies_from_user_other_error(self, mock_boto3_client):
        """Test handling of other AWS errors."""
        mock_iam = Mock()
        mock_sts = Mock()

        # Create a specific NoSuchEntityException class
        class NoSuchEntityException(ClientError):
            pass

        # Set up IAM client exceptions
        mock_iam.exceptions = Mock()
        mock_iam.exceptions.NoSuchEntityException = NoSuchEntityException

        # Set up STS client mock
        mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

        mock_boto3_client.side_effect = lambda service: mock_iam if service == "iam" else mock_sts
        mock_iam.get_user.side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, "GetUser")

        with pytest.raises(Exception) as exc_info:
            get_policies_from_user("TestUser")
        assert "Failed to fetch policies from user" in str(exc_info.value)
