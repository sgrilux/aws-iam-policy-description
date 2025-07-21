"""
AWS IAM Policy Description Tool

This is the main entry point for the IAM policy analysis tool.
It provides a command-line interface to analyze IAM policies from various sources
and output human-readable descriptions of permissions.
"""

import argparse
import logging

from policy_fetcher import (
    get_policy_from_file,
    get_policy_from_aws,
    get_policies_from_role,
    get_policies_from_user
)
from policy_analyzer import (
    setup_logging,
    get_action_descriptions,
    process_multiple_policies
)
from output_formatter import output_results
from utils import get_default_cache_dir


def main() -> None:
    """Main function to process IAM policies and output descriptions."""
    parser = argparse.ArgumentParser(
        description='Process IAM policy and print action descriptions.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s --file policy.json
  %(prog)s --name ReadOnlyAccess --output json
  %(prog)s --role MyRole --output csv --output-file results.csv
  %(prog)s --user MyUser --verbose
  %(prog)s --policy-arn arn:aws:iam::123456789012:policy/MyPolicy"""
    )

    # Input source options (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--file', type=str, help='Path to the IAM policy JSON file.')
    input_group.add_argument('--name', type=str, help='Name or ARN of the IAM policy.')
    input_group.add_argument('--role', type=str, help='Name of the IAM role (fetches all attached policies).')
    input_group.add_argument('--user', type=str, help='Name of the IAM user (fetches all attached policies).')
    input_group.add_argument('--policy-arn', type=str, help='ARN of the IAM policy.')

    # Output options
    parser.add_argument('--output', choices=['table', 'json', 'csv', 'html'], default='table', help='Output format (default: table)')
    parser.add_argument('--output-file', type=str, help='Output file path (stdout if not specified)')

    # Advanced options
    parser.add_argument('--ssl-verify', action='store_false', help='Disable SSL certificate verification.')
    parser.add_argument('--cache-dir', type=str, default=get_default_cache_dir(), help='Cache directory for IAM definitions')
    parser.add_argument('--no-cache', action='store_true', help='Disable caching of IAM definitions')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    try:
        if args.file:
            # Single policy from file
            policy_document = get_policy_from_file(args.file)
            action_descriptions = get_action_descriptions(
                policy_document,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache
            )

        elif args.name:
            # Single policy by name
            policy_document = get_policy_from_aws(args.name)
            action_descriptions = get_action_descriptions(
                policy_document,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache
            )

        elif args.policy_arn:
            # Single policy by ARN
            policy_document = get_policy_from_aws(args.policy_arn)
            action_descriptions = get_action_descriptions(
                policy_document,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache
            )

        elif args.role:
            # Multiple policies from role
            policies = get_policies_from_role(args.role)
            action_descriptions = process_multiple_policies(
                policies,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache
            )

        elif args.user:
            # Multiple policies from user
            policies = get_policies_from_user(args.user)
            action_descriptions = process_multiple_policies(
                policies,
                args.ssl_verify,
                args.cache_dir if not args.no_cache else None,
                not args.no_cache
            )

        else:
            raise ValueError("One of --file, --name, --policy-arn, --role, or --user must be provided.")

        output_results(action_descriptions, args.output, args.output_file)

    except KeyboardInterrupt:
        logging.info("Operation cancelled by user")
    except Exception as e:
        logging.error(f"An error occurred: {str(e)}")
        if args.verbose:
            raise


if __name__ == "__main__":
    main()
