"""Unit tests for utils module."""

from unittest.mock import patch

from utils import get_default_cache_dir, normalize_to_list


class TestGetDefaultCacheDir:
    """Test cases for get_default_cache_dir function."""

    @patch("utils.os.path.expanduser")
    def test_get_default_cache_dir(self, mock_expanduser):
        """Test getting default cache directory."""
        mock_expanduser.return_value = "/home/user/.aws-iam-policy-description"

        result = get_default_cache_dir()

        mock_expanduser.assert_called_once_with("~/.aws-iam-policy-description")
        assert result == "/home/user/.aws-iam-policy-description"

    @patch("utils.os.path.expanduser")
    def test_get_default_cache_dir_different_user(self, mock_expanduser):
        """Test getting default cache directory for different user."""
        mock_expanduser.return_value = "/Users/testuser/.aws-iam-policy-description"

        result = get_default_cache_dir()

        mock_expanduser.assert_called_once_with("~/.aws-iam-policy-description")
        assert result == "/Users/testuser/.aws-iam-policy-description"


class TestNormalizeToList:
    """Test cases for normalize_to_list function."""

    def test_normalize_to_list_string(self):
        """Test normalizing string to list."""
        result = normalize_to_list("test_string")
        assert result == ["test_string"]

    def test_normalize_to_list_empty_string(self):
        """Test normalizing empty string to list."""
        result = normalize_to_list("")
        assert result == [""]

    def test_normalize_to_list_list(self):
        """Test normalizing list to list (no change)."""
        input_list = ["item1", "item2", "item3"]
        result = normalize_to_list(input_list)
        assert result == input_list
        # Verify it's the same object (not a copy)
        assert result is input_list

    def test_normalize_to_list_empty_list(self):
        """Test normalizing empty list to list."""
        result = normalize_to_list([])
        assert result == []

    def test_normalize_to_list_none(self):
        """Test normalizing None to empty list."""
        result = normalize_to_list(None)
        assert result == []

    def test_normalize_to_list_integer(self):
        """Test normalizing integer to empty list."""
        result = normalize_to_list(42)
        assert result == []

    def test_normalize_to_list_boolean(self):
        """Test normalizing boolean to empty list."""
        result = normalize_to_list(True)
        assert result == []

        result = normalize_to_list(False)
        assert result == []

    def test_normalize_to_list_dict(self):
        """Test normalizing dictionary to empty list."""
        result = normalize_to_list({"key": "value"})
        assert result == []

    def test_normalize_to_list_mixed_list(self):
        """Test normalizing list with mixed types."""
        input_list = ["string", 42, None, True]
        result = normalize_to_list(input_list)
        assert result == input_list

    def test_normalize_to_list_unicode_string(self):
        """Test normalizing unicode string to list."""
        result = normalize_to_list("🔐 unicode test")
        assert result == ["🔐 unicode test"]

    def test_normalize_to_list_multiline_string(self):
        """Test normalizing multiline string to list."""
        multiline = "line1\nline2\nline3"
        result = normalize_to_list(multiline)
        assert result == [multiline]
