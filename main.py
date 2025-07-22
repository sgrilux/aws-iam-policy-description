"""AWS IAM Policy Description Tool.

This is the main entry point for the IAM policy analysis tool.
It provides a command-line interface to analyze IAM policies from various sources
and output human-readable descriptions of permissions.
"""

import argparse
import logging
from typing import Any, Dict, List, Optional

from bedrock_analyzer import get_bedrock_policy_description
from output_formatter import output_results
from policy_analyzer import get_action_descriptions, process_multiple_policies, setup_logging
from policy_fetcher import get_policies_from_role, get_policies_from_user, get_policy_from_aws, get_policy_from_file
from utils import BEDROCK_MODEL_DEFAULT, BEDROCK_REGION_DEFAULT, get_default_cache_dir


def process_policy_analysis(
    policy_documents: List[Dict[str, Any]],
    analysis_mode: str,
    bedrock_model: str,
    bedrock_region: str,
    ssl_verify: bool,
    cache_dir: Optional[str],
    use_cache: bool,
    role_name: Optional[str] = None,
    user_name: Optional[str] = None,
) -> Dict[str, Any]:
    """Process policy analysis based on the specified mode."""
    results: Dict[str, Any] = {}

    # For single policy documents (file, name, arn)
    if len(policy_documents) == 1 and not role_name and not user_name:
        if analysis_mode in ["actions", "full"]:
            # Get detailed action descriptions
            results["actions"] = get_action_descriptions(policy_documents[0], ssl_verify, cache_dir, use_cache)

        if analysis_mode in ["description", "full"]:
            # Get Bedrock AI description
            results["bedrock_description"] = get_bedrock_policy_description(
                policy_documents=policy_documents, model_id=bedrock_model, region=bedrock_region
            )

    # For role or user analysis (multiple policies)
    else:
        # Process multiple policies from roles/users
        if analysis_mode in ["actions", "full"]:
            results["actions"] = process_multiple_policies(policy_documents, ssl_verify, cache_dir, use_cache)

        if analysis_mode in ["description", "full"]:
            # Get Bedrock AI description for the role/user
            results["bedrock_description"] = get_bedrock_policy_description(
                policy_documents=policy_documents,
                role_name=role_name,
                user_name=user_name,
                model_id=bedrock_model,
                region=bedrock_region,
            )

        # Add context information for roles/users
        results["context"] = {
            "type": "role" if role_name else "user",
            "name": role_name or user_name,
            "policy_count": len(policy_documents),
            "policies": [p.get("PolicyName", "Unknown") for p in policy_documents],
        }

    return results


def main() -> None:
    """Main function to process IAM policies and output descriptions."""
    parser = argparse.ArgumentParser(
        description="Process IAM policy and print action descriptions.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --file policy.json
  %(prog)s --name ReadOnlyAccess --output json
  %(prog)s --role MyRole --output csv --output-file results.csv
  %(prog)s --user MyUser --verbose
  %(prog)s --policy-arn arn:aws:iam::123456789012:policy/MyPolicy
  %(prog)s --file policy.json --analysis-mode description --output html
  """,
    )

    # Input source options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", type=str, help="Path to the IAM policy JSON file.")
    input_group.add_argument("--name", type=str, help="Name or ARN of the IAM policy.")
    input_group.add_argument("--role", type=str, help="Name of the IAM role (fetches all attached policies).")
    input_group.add_argument("--user", type=str, help="Name of the IAM user (fetches all attached policies).")
    input_group.add_argument("--policy-arn", type=str, help="ARN of the IAM policy.")

    # Output options
    parser.add_argument(
        "--output", choices=["table", "json", "csv", "html"], default="table", help="Output format (default: table)"
    )
    parser.add_argument("--output-file", type=str, help="Output file path (stdout if not specified)")

    # Analysis mode options
    parser.add_argument(
        "--analysis-mode",
        choices=["actions", "description", "full"],
        default="actions",
        help="Analysis mode: actions (detailed action list), description (AI summary via Bedrock), full (default: actions)",
    )

    # Advanced options
    parser.add_argument("--ssl-verify", action="store_false", help="Disable SSL certificate verification.")
    parser.add_argument(
        "--cache-dir", type=str, default=get_default_cache_dir(), help="Cache directory for IAM definitions"
    )
    parser.add_argument("--no-cache", action="store_true", help="Disable caching of IAM definitions")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    try:
        if args.file:
            # Single policy from file
            policy_document = get_policy_from_file(args.file)
            results = process_policy_analysis(
                [policy_document],
                args.analysis_mode,
                BEDROCK_MODEL_DEFAULT,
                BEDROCK_REGION_DEFAULT,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache,
            )

        elif args.name:
            # Single policy by name
            policy_document = get_policy_from_aws(args.name)
            results = process_policy_analysis(
                [policy_document],
                args.analysis_mode,
                BEDROCK_MODEL_DEFAULT,
                BEDROCK_REGION_DEFAULT,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache,
            )

        elif args.policy_arn:
            # Single policy by ARN
            policy_document = get_policy_from_aws(args.policy_arn)
            results = process_policy_analysis(
                [policy_document],
                args.analysis_mode,
                BEDROCK_MODEL_DEFAULT,
                BEDROCK_REGION_DEFAULT,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache,
            )

        elif args.role:
            # Multiple policies from role
            policies = get_policies_from_role(args.role)
            results = process_policy_analysis(
                policy_documents=policies,
                analysis_mode=args.analysis_mode,
                bedrock_model=BEDROCK_MODEL_DEFAULT,
                bedrock_region=BEDROCK_REGION_DEFAULT,
                ssl_verify=args.ssl_verify,
                cache_dir=args.cache_dir if not args.no_cache else None,
                use_cache=not args.no_cache,
                role_name=args.role,
            )

        elif args.user:
            # Multiple policies from user
            policies = get_policies_from_user(args.user)
            results = process_policy_analysis(
                policy_documents=policies,
                analysis_mode=args.analysis_mode,
                bedrock_model=BEDROCK_MODEL_DEFAULT,
                bedrock_region=BEDROCK_REGION_DEFAULT,
                ssl_verify=args.ssl_verify,
                cache_dir=args.cache_dir if not args.no_cache else None,
                use_cache=not args.no_cache,
                user_name=args.user,
            )

        else:
            raise ValueError("One of --file, --name, --policy-arn, --role, or --user must be provided.")

        output_results(results, args.output, args.output_file, args.analysis_mode)

    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        if args.verbose:
            raise


if __name__ == "__main__":
    main()
