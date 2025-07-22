"""Amazon Bedrock Integration for IAM Policy Analysis.

This module provides functionality to generate natural language descriptions
of IAM policies using Amazon Bedrock's large language models.
"""

import json
import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from utils import BEDROCK_MODEL_DEFAULT, BEDROCK_REGION_DEFAULT


def get_bedrock_policy_description(
    policy_documents: List[Dict[str, Any]],
    role_name: Optional[str] = None,
    user_name: Optional[str] = None,
    model_id: str = BEDROCK_MODEL_DEFAULT,
    region: str = BEDROCK_REGION_DEFAULT,
) -> Optional[str]:
    """Generate a natural language description of an IAM policy using Bedrock.

    Args:
        policy_document: The IAM policy document as a dictionary
        model_id: The Bedrock model ID to use for analysis
        region: AWS region for the Bedrock service

    Returns:
        A natural language description of the policy, or None if failed
    """
    try:
        # Initialize Bedrock client
        bedrock_client = boto3.client("bedrock-runtime", region_name=region)

        # Create the prompt for policy analysis
        prompt = create_policy_analysis_prompt(
            policy_documents=policy_documents, role_name=role_name, user_name=user_name
        )

        # Prepare the request based on model type
        if "anthropic.claude" in model_id:
            response = invoke_claude_model(bedrock_client, model_id, prompt)
        else:
            logging.warning(f"Unsupported model type: {model_id}. Falling back to Claude format.")
            response = invoke_claude_model(bedrock_client, model_id, prompt)

        return response

    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        error_message = e.response.get("Error", {}).get("Message", str(e))

        if error_code == "AccessDeniedException":
            logging.error("Access denied to Bedrock. Please check your AWS permissions.")
        elif error_code == "ValidationException":
            logging.error(f"Invalid request to Bedrock: {error_message}")
        elif error_code == "ResourceNotFoundException":
            logging.error(f"Model not found: {model_id}. Please check the model ID and region.")
        elif error_code == "ThrottlingException":
            logging.error("Bedrock request was throttled. Please try again later.")
        else:
            logging.error(f"Bedrock error ({error_code}): {error_message}")

        return None

    except BotoCoreError as e:
        logging.error(f"AWS SDK error: {str(e)}")
        return None

    except Exception as e:
        logging.error(f"Unexpected error calling Bedrock: {str(e)}")
        return None


def create_policy_analysis_prompt(
    policy_documents: List[Dict[str, Any]], role_name: Optional[str] = None, user_name: Optional[str] = None
) -> str:
    """Create a comprehensive prompt for IAM policy analysis.

    Args:
        policy_documents: The IAM policy documents
        role_name: The name of the IAM role (if applicable)
        user_name: The name of the IAM user (if applicable)

    Returns:
        A formatted prompt for the AI model
    """
    policy_json = json.dumps(policy_documents, indent=2)

    # Create context-specific introduction
    if role_name:
        context_intro = f"You are analyzing all IAM policies attached to the IAM role '{role_name}'."
        policy_count = len(policy_documents)
        policy_list = [p.get("PolicyName", "Unknown") for p in policy_documents]
        context_details = f"This role has {policy_count} attached policies: {', '.join(policy_list)}"
    elif user_name:
        context_intro = f"You are analyzing all IAM policies attached to the IAM user '{user_name}'."
        policy_count = len(policy_documents)
        policy_list = [p.get("PolicyName", "Unknown") for p in policy_documents]
        context_details = f"This user has {policy_count} attached policies: {', '.join(policy_list)}"
    else:
        context_intro = "You are analyzing a single IAM policy document."
        context_details = ""

    prompt = f"""You are an AWS security expert analyzing IAM policies. {context_intro}

{context_details}

Please provide a concise analysis focusing on the key aspects of the following IAM policy document(s).

Your analysis should include only:

1. **Permissions Summary**: What are the main types of permissions granted? Group similar actions together (e.g., "S3 read/write operations", "EC2 management", "IAM user management").

2. **Resource Scope**: What AWS resources can be accessed? Specify resource types, ARN patterns, and any restrictions or wildcards.

Please keep your response concise, professional, and use bullet points for clarity. Focus only on what permissions are granted and what resources they apply to.

IAM Policy Document(s):
```json
{policy_json}
```

Analysis:"""

    return prompt


def invoke_claude_model(client, model_id: str, prompt: str) -> Optional[str]:
    """Invoke Anthropic Claude models via Bedrock."""
    try:
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 2000,
            "temperature": 0.1,
            "messages": [{"role": "user", "content": prompt}],
        }

        response = client.invoke_model(modelId=model_id, body=json.dumps(body))

        response_body = json.loads(response["body"].read())
        return response_body.get("content", [{}])[0].get("text", "")  # type: ignore[no-any-return]

    except Exception as e:
        logging.error(f"Error invoking Claude model: {str(e)}")
        return None


def list_available_models(region: str = "us-east-1") -> Dict[str, Any]:
    """List available Bedrock models in the specified region.

    Args:
        region: AWS region to query

    Returns:
        Dictionary containing available models information
    """
    try:
        bedrock_client = boto3.client("bedrock", region_name=region)
        response = bedrock_client.list_foundation_models()

        models = {}
        for model in response.get("modelSummaries", []):
            model_id = model.get("modelId", "")
            models[model_id] = {
                "name": model.get("modelName", ""),
                "provider": model.get("providerName", ""),
                "input_modalities": model.get("inputModalities", []),
                "output_modalities": model.get("outputModalities", []),
                "response_streaming": model.get("responseStreamingSupported", False),
            }

        return models

    except Exception as e:
        logging.error(f"Error listing Bedrock models: {str(e)}")
        return {}
