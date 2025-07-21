"""
Policy fetching module for retrieving IAM policies from various sources.

This module handles fetching policies from:
- Local JSON files
- AWS managed policies (by name or ARN)
- Customer managed policies (by name or ARN)
- IAM roles (all attached policies)
- IAM users (all attached policies)
"""

import json
import logging
import boto3
from typing import Dict, List, Any


def get_policy_from_file(file_path: str) -> Dict[str, Any]:
    """Load and validate IAM policy from JSON file.
    
    Args:
        file_path: Path to the JSON policy file
        
    Returns:
        Dict containing the parsed policy document
        
    Raises:
        ValueError: If file contains invalid JSON
        FileNotFoundError: If file doesn't exist
    """
    try:
        with open(file_path, 'r') as file:
            policy = json.load(file)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in file {file_path}: {str(e)}")
    except FileNotFoundError:
        raise FileNotFoundError(f"Policy file not found: {file_path}")
    
    if not isinstance(policy, dict):
        raise ValueError(f"Policy must be a JSON object, got {type(policy).__name__}")
    
    return policy


def get_policy_from_aws(policy_identifier: str) -> Dict[str, Any]:
    """Fetch IAM managed policy from AWS.
    
    Args:
        policy_identifier: Name or ARN of the AWS managed policy
        
    Returns:
        Dict containing the policy document
        
    Raises:
        ValueError: If policy is not found
        Exception: If AWS API call fails
    """
    try:
        iam = boto3.client('iam')
        
        # Handle both policy names and ARNs
        if policy_identifier.startswith('arn:aws:iam::'):
            policy_arn = policy_identifier
        else:
            # Try AWS managed policy first
            policy_arn = f"arn:aws:iam::aws:policy/{policy_identifier}"
        
        try:
            policy = iam.get_policy(PolicyArn=policy_arn)
        except iam.exceptions.NoSuchEntityException:
            if not policy_identifier.startswith('arn:aws:iam::'):
                # Try as customer managed policy
                account_id = boto3.client('sts').get_caller_identity()['Account']
                policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_identifier}"
                policy = iam.get_policy(PolicyArn=policy_arn)
            else:
                raise
        
        policy_version = policy['Policy']['DefaultVersionId']
        policy_document = iam.get_policy_version(
            PolicyArn=policy['Policy']['Arn'], 
            VersionId=policy_version
        )['PolicyVersion']['Document']
        
        logging.info(f"Fetched policy: {policy['Policy']['PolicyName']} ({policy['Policy']['Arn']})")
        return policy_document
    except iam.exceptions.NoSuchEntityException:
        raise ValueError(f"Policy '{policy_identifier}' not found.")
    except Exception as e:
        raise Exception(f"Failed to fetch policy from AWS: {str(e)}")


def get_policies_from_role(role_name: str) -> List[Dict[str, Any]]:
    """Fetch all policies attached to an IAM role.
    
    Args:
        role_name: Name of the IAM role
        
    Returns:
        List of policy documents with metadata
        
    Raises:
        ValueError: If role is not found
        Exception: If AWS API call fails
    """
    try:
        iam = boto3.client('iam')
        policies = []
        
        # Check if role exists
        try:
            role = iam.get_role(RoleName=role_name)
            logging.info(f"Found role: {role['Role']['RoleName']} ({role['Role']['Arn']})")
        except iam.exceptions.NoSuchEntityException:
            raise ValueError(f"Role '{role_name}' not found.")
        
        # Get attached managed policies
        attached_policies = iam.list_attached_role_policies(RoleName=role_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            policy_name = policy['PolicyName']
            
            logging.info(f"Fetching attached policy: {policy_name}")
            policy_doc = get_policy_from_aws(policy_arn)
            policies.append({
                'PolicyName': policy_name,
                'PolicyArn': policy_arn,
                'PolicyType': 'Managed',
                'Document': policy_doc
            })
        
        # Get inline policies
        inline_policies = iam.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies['PolicyNames']:
            logging.info(f"Fetching inline policy: {policy_name}")
            policy_doc = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            policies.append({
                'PolicyName': policy_name,
                'PolicyArn': f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:role/{role_name}/policy/{policy_name}",
                'PolicyType': 'Inline',
                'Document': policy_doc['PolicyDocument']
            })
        
        # Get assume role policy document
        assume_role_policy = role['Role']['AssumeRolePolicyDocument']
        policies.append({
            'PolicyName': 'AssumeRolePolicyDocument',
            'PolicyArn': f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:role/{role_name}/assume-role-policy",
            'PolicyType': 'Trust',
            'Document': assume_role_policy
        })
        
        logging.info(f"Found {len(policies)} policies for role '{role_name}'")
        return policies
        
    except Exception as e:
        if "not found" in str(e).lower():
            raise ValueError(f"Role '{role_name}' not found.")
        raise Exception(f"Failed to fetch policies from role: {str(e)}")


def get_policies_from_user(user_name: str) -> List[Dict[str, Any]]:
    """Fetch all policies attached to an IAM user.
    
    Args:
        user_name: Name of the IAM user
        
    Returns:
        List of policy documents with metadata
        
    Raises:
        ValueError: If user is not found
        Exception: If AWS API call fails
    """
    try:
        iam = boto3.client('iam')
        policies = []
        
        # Check if user exists
        try:
            user = iam.get_user(UserName=user_name)
            logging.info(f"Found user: {user['User']['UserName']} ({user['User']['Arn']})")
        except iam.exceptions.NoSuchEntityException:
            raise ValueError(f"User '{user_name}' not found.")
        
        # Get attached managed policies
        attached_policies = iam.list_attached_user_policies(UserName=user_name)
        for policy in attached_policies['AttachedPolicies']:
            policy_arn = policy['PolicyArn']
            policy_name = policy['PolicyName']
            
            logging.info(f"Fetching attached policy: {policy_name}")
            policy_doc = get_policy_from_aws(policy_arn)
            policies.append({
                'PolicyName': policy_name,
                'PolicyArn': policy_arn,
                'PolicyType': 'Managed',
                'Document': policy_doc
            })
        
        # Get inline policies
        inline_policies = iam.list_user_policies(UserName=user_name)
        for policy_name in inline_policies['PolicyNames']:
            logging.info(f"Fetching inline policy: {policy_name}")
            policy_doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
            policies.append({
                'PolicyName': policy_name,
                'PolicyArn': f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:user/{user_name}/policy/{policy_name}",
                'PolicyType': 'Inline',
                'Document': policy_doc['PolicyDocument']
            })
        
        logging.info(f"Found {len(policies)} policies for user '{user_name}'")
        return policies
        
    except Exception as e:
        if "not found" in str(e).lower():
            raise ValueError(f"User '{user_name}' not found.")
        raise Exception(f"Failed to fetch policies from user: {str(e)}")