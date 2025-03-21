import argparse
import json
import boto3
import requests
# import sys
from rich.console import Console
from rich.table import Table


def get_policy_from_file(file_path):
    with open(file_path, 'r') as file:
        try:
            policy = json.load(file)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in file {file_path}: {str(e)}")
    return policy


def get_policy_from_aws(policy_name):
    iam = boto3.client('iam')
    try:
        policy = iam.get_policy(PolicyArn=f"arn:aws:iam::aws:policy/{policy_name}")
        policy_version = policy['Policy']['DefaultVersionId']
        policy_document = iam.get_policy_version(PolicyArn=policy['Policy']['Arn'], VersionId=policy_version)['PolicyVersion']['Document']
        return policy_document
    except iam.exceptions.NoSuchEntityException:
        raise ValueError(f"Policy '{policy_name}' not found.")


def get_action_descriptions(policy_document, ssl_verify=False):
    permission_map = []

    # Load iam_definition dataset
    url = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/iam_definition.json"
    response = requests.get(url, verify=ssl_verify)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch IAM definitions from {url}: {response.status_code}")

    for statement in policy_document.get('Statement', []):
        statement_map = {}
        action_map = {}

        actions = statement.get('Action', [])
        effect = statement.get('Effect', '')
        resource = statement.get('Resource', [])

        statement_map["Effect"] = effect
        statement_map["Resource"] = resource

        for action in actions:

            service, privilege = action.split(':')
            if privilege == "*":
                description = f"All actions under {service}"
                action_map[action] = description
            else:
                iam_definitions = json.loads(response.text)
                for service_def in iam_definitions:
                    prefix = service_def.get("prefix")
                    privileges = service_def.get("privileges", [])
                    for pr in privileges:
                        privilege = pr.get("privilege")
                        action_name = f"{prefix}:{privilege}"
                        if action_name == action:
                            description = pr.get("description")
                            action_map[action] = description
                            break
                    if action in action_map:
                        break
            statement_map["actions"] = action_map
        permission_map.append(statement_map)

    return permission_map


def print_table(permission_map):
    console = Console()
    statement_index = 1

    policy_table = Table(title="Policy Description", show_header=True)

    for statement in permission_map:
        statement_table = Table(title=f"Statement {statement_index}", show_header=True, expand=True)
        statement_table.add_column("Action", style="cyan")
        statement_table.add_column("Effect", style="green")
        statement_table.add_column("Resource", style="magenta")

        actions = statement.get('actions', {})
        action_table = Table(show_header=False, box=None)
        for action, description in actions.items():
            action_table.add_row(action, description)

        resource_table = Table(show_header=False, box=None)
        for resource in statement.get('Resource', []):
            resource_table.add_row(resource)

        statement_table.add_row(action_table, statement.get("Effect"), resource_table)
        policy_table.add_row(statement_table)

        statement_index += 1
        policy_table.add_section()

    console.print(policy_table)


def main():
    parser = argparse.ArgumentParser(description='Process IAM policy and print action descriptions.')
    parser.add_argument('--file', type=str, help='Path to the IAM policy JSON file.')
    parser.add_argument('--name', type=str, help='Name of the IAM policy in AWS.')
    parser.add_argument('--ssl-verify', type=bool, default=True, help='Wheter to verify SSL certificate.')
    args = parser.parse_args()

    try:
        if args.file:
            policy_document = get_policy_from_file(args.file)
        elif args.name:
            policy_document = get_policy_from_aws(args.name)
        else:
            raise ValueError("Either --file or --name must be provided.")

        action_descriptions = get_action_descriptions(policy_document, args.ssl_verify)
        print_table(action_descriptions)
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        # Print stack trace
        # import traceback
        # traceback.print_exc()


if __name__ == "__main__":
    main()
