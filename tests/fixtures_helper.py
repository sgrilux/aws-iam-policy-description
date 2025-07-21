"""
Test fixtures and mock data for unit tests.
"""


# Expected output formats for testing
# EXPECTED_JSON_OUTPUT = json.dumps(SAMPLE_PROCESSED_PERMISSIONS, indent=2)

EXPECTED_CSV_OUTPUT = """Statement,PolicyName,PolicyType,Sid,Action,Description,Effect,Resource,Principal,Condition
1,TestPolicy,Managed,AllowS3ReadAccess,s3:GetObject,Grants permission to retrieve objects from Amazon S3,Allow,arn:aws:s3:::test-bucket,,
1,TestPolicy,Managed,AllowS3ReadAccess,s3:GetObject,Grants permission to retrieve objects from Amazon S3,Allow,arn:aws:s3:::test-bucket/*,,
1,TestPolicy,Managed,AllowS3ReadAccess,s3:ListBucket,Grants permission to list some or all of the objects in an Amazon S3 bucket,Allow,arn:aws:s3:::test-bucket,,
1,TestPolicy,Managed,AllowS3ReadAccess,s3:ListBucket,Grants permission to list some or all of the objects in an Amazon S3 bucket,Allow,arn:aws:s3:::test-bucket/*,,
2,TestPolicy,Managed,,s3:DeleteObject,Grants permission to remove objects from Amazon S3,Deny,arn:aws:s3:::test-bucket/*,,
"""

# Invalid policy documents for testing validation
INVALID_POLICY_NO_STATEMENT = {
    "Version": "2012-10-17"
}

INVALID_POLICY_NO_EFFECT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::test-bucket/*"
        }
    ]
}

INVALID_POLICY_INVALID_EFFECT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Maybe",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::test-bucket/*"
        }
    ]
}

INVALID_POLICY_NO_ACTION = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Resource": "arn:aws:s3:::test-bucket/*"
        }
    ]
}
