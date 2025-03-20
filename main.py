import argparse
import json
import boto3
import requests
from tabulate import tabulate


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


def extract_actions(policy_document):
    actions = set()
    for statement in policy_document.get('Statement', []):
        action = statement.get('Action', [])
        if isinstance(action, str):
            actions.add(action)
        elif isinstance(action, list):
            actions.update(action)
    return actions


def get_action_descriptions(actions):
    action_map = {}

    url = "https://raw.githubusercontent.com/iann0036/iam-dataset/main/aws/iam_definition.json"
    response = requests.get(url)
    if response.status_code != 200:
        raise Exception(f"Failed to fetch IAM definitions from {url}: {response.status_code}")
    iam_definitions = json.loads(response.text)

    for action in actions:
        service, privilege = action.split(':')
        if privilege == '*':
            description = f"All actions under {service}"
            action_map[action] = description
        else:
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
    return action_map


def main():
    parser = argparse.ArgumentParser(description='Process IAM policy and print action descriptions.')
    parser.add_argument('--file', type=str, help='Path to the IAM policy JSON file.')
    parser.add_argument('--name', type=str, help='Name of the IAM policy in AWS.')
    args = parser.parse_args()

    try:
        if args.file:
            policy_document = get_policy_from_file(args.file)
        elif args.name:
            policy_document = get_policy_from_aws(args.name)
        else:
            raise ValueError("Either --file or --name must be provided.")

        actions = extract_actions(policy_document)
        action_descriptions = get_action_descriptions(actions)

        table = [(action, desc) for action, desc in action_descriptions.items()]

        print(tabulate(sorted(table, key=lambda x: x[0]), headers=['Action', 'Description']))
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()
