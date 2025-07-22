"""Policy analysis module for processing IAM policy documents.

This module handles:
- Policy document validation
- IAM action description mapping
- Multiple policy processing
- IAM definitions fetching and caching
"""

import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

from utils import normalize_to_list


def setup_logging(verbose: bool = False) -> None:
    """Setup logging configuration."""
    from rich.logging import RichHandler

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(message)s", datefmt="[%X]", handlers=[RichHandler(rich_tracebacks=True)])


def get_cache_file_path(cache_dir: str) -> Path:
    """Get the path to the cached IAM definitions file."""
    cache_path = Path(cache_dir)
    cache_path.mkdir(parents=True, exist_ok=True)
    return cache_path / "iam_definitions.json"


def is_cache_valid(cache_file: Path, max_age_hours: int = 24) -> bool:
    """Check if cached file exists and is not older than max_age_hours."""
    if not cache_file.exists():
        return False

    file_age = datetime.now() - datetime.fromtimestamp(cache_file.stat().st_mtime)
    return file_age < timedelta(hours=max_age_hours)


def validate_policy_document(policy_document: Dict[str, Any]) -> None:
    """Validate basic IAM policy structure.

    Args:
        policy_document: Policy document to validate

    Raises:
        ValueError: If policy structure is invalid
    """
    if not isinstance(policy_document, dict):
        raise ValueError("Policy document must be a dictionary")

    if "Statement" not in policy_document:
        raise ValueError("Policy document must contain a 'Statement' key")

    statements = policy_document["Statement"]
    if not isinstance(statements, list):
        statements = [statements]

    for i, statement in enumerate(statements):
        if not isinstance(statement, dict):
            raise ValueError(f"Statement {i} must be a dictionary")

        if "Effect" not in statement:
            raise ValueError(f"Statement {i} must contain an 'Effect' key")

        if statement["Effect"] not in ["Allow", "Deny"]:
            raise ValueError(f"Statement {i} Effect must be 'Allow' or 'Deny'")

        if "Action" not in statement:
            raise ValueError(f"Statement {i} must contain an 'Action' key")


def fetch_iam_definitions(
    ssl_verify: bool = True, cache_dir: Optional[str] = None, use_cache: bool = True
) -> List[Dict[str, Any]]:
    """Fetch and parse IAM definitions from external API with caching support.

    Args:
        ssl_verify: Whether to verify SSL certificates
        cache_dir: Directory to store cached definitions
        use_cache: Whether to use caching

    Returns:
        List of IAM service definitions

    Raises:
        Exception: If fetching fails
    """
    url = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/iam_definition.json"

    # Try to use cache if enabled
    if use_cache and cache_dir:
        cache_file = get_cache_file_path(cache_dir)
        if is_cache_valid(cache_file):
            logging.info("Using cached IAM definitions")
            try:
                with open(cache_file, "r") as f:
                    cached_data = json.load(f)
                    return cached_data  # type: ignore[no-any-return]
            except (json.JSONDecodeError, IOError) as e:
                logging.warning(f"Failed to read cache file: {e}")

    # Fetch from API
    logging.info("Fetching IAM definitions from API...")
    try:
        response = requests.get(url, verify=ssl_verify, timeout=30)
        response.raise_for_status()
        definitions = json.loads(response.text)

        # Cache the result if caching is enabled
        if use_cache and cache_dir:
            try:
                with open(cache_file, "w") as f:
                    json.dump(definitions, f)
                logging.info(f"Cached IAM definitions to {cache_file}")
            except IOError as e:
                logging.warning(f"Failed to write cache file: {e}")

        return definitions  # type: ignore[no-any-return]
    except requests.exceptions.RequestException as e:
        raise Exception(f"Failed to fetch IAM definitions from {url}: {str(e)}")
    except json.JSONDecodeError as e:
        raise Exception(f"Invalid JSON in IAM definitions response: {str(e)}")


def build_action_lookup(iam_definitions: List[Dict[str, Any]]) -> Dict[str, str]:
    """Build a lookup dictionary for fast action description retrieval.

    Args:
        iam_definitions: List of IAM service definitions

    Returns:
        Dictionary mapping action names to descriptions
    """
    action_lookup = {}
    for service_def in iam_definitions:
        prefix = service_def.get("prefix")
        if not prefix:
            continue
        privileges = service_def.get("privileges", [])
        for privilege in privileges:
            privilege_name = privilege.get("privilege")
            description = privilege.get("description")
            if privilege_name and description:
                action_name = f"{prefix}:{privilege_name}"
                action_lookup[action_name] = description
    return action_lookup


def expand_wildcard_actions(action: str, action_lookup: Dict[str, str]) -> List[str]:
    """Expand wildcard actions to list of matching actions.

    Args:
        action: IAM action that may contain wildcards (e.g., 's3:Get*', 's3:*')
        action_lookup: Dictionary mapping actions to descriptions

    Returns:
        List of matching action names
    """
    if ":" not in action:
        return []

    try:
        service, privilege = action.split(":", 1)
    except ValueError:
        return []

    # Handle full service wildcard (e.g., 's3:*')
    if privilege == "*":
        return [act for act in action_lookup.keys() if act.startswith(f"{service}:")]

    # Handle privilege wildcard (e.g., 's3:Get*', 's3:Describe*')
    if privilege.endswith("*"):
        prefix = privilege[:-1]  # Remove the '*'
        if not prefix:  # Just '*' case, same as above
            return [act for act in action_lookup.keys() if act.startswith(f"{service}:")]

        # Find actions that start with the prefix
        pattern = f"{service}:{prefix}"
        return [act for act in action_lookup.keys() if act.startswith(pattern)]

    # Not a wildcard
    return [action] if action in action_lookup else []


def get_action_description(action: str, action_lookup: Dict[str, str]) -> str:
    """Get description for a single action.

    Args:
        action: IAM action name (e.g., 's3:GetObject')
        action_lookup: Dictionary mapping actions to descriptions

    Returns:
        Human-readable description of the action
    """
    if ":" not in action:
        return f"Invalid action format: {action}"

    try:
        service, privilege = action.split(":", 1)
    except ValueError:
        return f"Invalid action format: {action}"

    # Handle wildcard actions
    if "*" in privilege:
        matching_actions = expand_wildcard_actions(action, action_lookup)
        if matching_actions:
            if privilege == "*":
                return f"All actions under {service} ({len(matching_actions)} actions)"
            else:
                prefix = privilege.replace("*", "")
                return f"All {service} actions starting with '{prefix}' ({len(matching_actions)} actions)"
        else:
            return f"No actions found matching {action}"

    if privilege == "*":
        return f"All actions under {service}"

    return action_lookup.get(action, f"No description found for {action}")


def get_action_descriptions(
    policy_document: Dict[str, Any],
    ssl_verify: bool = True,
    cache_dir: Optional[str] = None,
    use_cache: bool = True,
    policy_metadata: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    """Extract action descriptions from policy document.

    Args:
        policy_document: IAM policy document
        ssl_verify: Whether to verify SSL certificates
        cache_dir: Directory for caching IAM definitions
        use_cache: Whether to use caching
        policy_metadata: Optional metadata about the policy

    Returns:
        List of statement maps with action descriptions
    """
    validate_policy_document(policy_document)
    permission_map = []

    # Fetch IAM definitions once and build lookup
    iam_definitions = fetch_iam_definitions(ssl_verify, cache_dir, use_cache)
    action_lookup = build_action_lookup(iam_definitions)

    statements = policy_document.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        statement_map = {}
        action_map = {}

        actions = normalize_to_list(statement.get("Action", []))
        effect = statement.get("Effect", "")
        resource = normalize_to_list(statement.get("Resource", []))
        condition = statement.get("Condition", {})
        sid = statement.get("Sid", "")
        principal = statement.get("Principal", {})

        statement_map["Sid"] = sid
        statement_map["Effect"] = effect
        statement_map["Resource"] = resource
        statement_map["Condition"] = condition
        statement_map["Principal"] = principal

        # Add policy metadata if provided
        if policy_metadata:
            statement_map["PolicyMetadata"] = policy_metadata

        for action in actions:
            # Check if this is a wildcard action
            if "*" in action and ":" in action:
                # Get the wildcard description
                wildcard_description = get_action_description(action, action_lookup)
                action_map[action] = wildcard_description

                # Also expand the wildcard to show individual actions
                expanded_actions = expand_wildcard_actions(action, action_lookup)
                for expanded_action in expanded_actions:
                    individual_description = action_lookup.get(
                        expanded_action, f"No description found for {expanded_action}"
                    )
                    action_map[expanded_action] = individual_description
            else:
                # Regular action
                description = get_action_description(action, action_lookup)
                action_map[action] = description

        statement_map["actions"] = action_map
        permission_map.append(statement_map)

    return permission_map


def process_multiple_policies(
    policies: List[Dict[str, Any]], ssl_verify: bool = True, cache_dir: Optional[str] = None, use_cache: bool = True
) -> List[Dict[str, Any]]:
    """Process multiple policies and return combined results.

    Args:
        policies: List of policy dictionaries with metadata
        ssl_verify: Whether to verify SSL certificates
        cache_dir: Directory for caching IAM definitions
        use_cache: Whether to use caching

    Returns:
        List of all statement maps with action descriptions
    """
    all_permissions = []

    for policy in policies:
        policy_name = policy.get("PolicyName", "Unknown")
        policy_type = policy.get("PolicyType", "Unknown")
        policy_arn = policy.get("PolicyArn", "")

        logging.info(f"Processing policy: {policy_name} ({policy_type})")

        metadata = {"PolicyName": policy_name, "PolicyType": policy_type, "PolicyArn": policy_arn}

        permissions = get_action_descriptions(policy["Document"], ssl_verify, cache_dir, use_cache, metadata)

        all_permissions.extend(permissions)

    return all_permissions
