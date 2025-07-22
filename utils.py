"""Utility functions for the IAM policy description tool.

This module contains common utility functions used across the application.
"""

import os
from typing import List, Union

BEDROCK_MODEL_DEFAULT = "eu.anthropic.claude-sonnet-4-20250514-v1:0"
BEDROCK_REGION_DEFAULT = "eu-central-1"


def get_default_cache_dir() -> str:
    """Get the default cache directory for IAM definitions."""
    return os.path.expanduser("~/.aws-iam-policy-description")


def normalize_to_list(value: Union[str, List[str], None]) -> List[str]:
    """Convert string or list to list.

    Args:
        value: String, list, or None

    Returns:
        List of strings
    """
    if isinstance(value, str):
        return [value]
    elif isinstance(value, list):
        return value
    else:
        return []  # type: ignore[unreachable]
