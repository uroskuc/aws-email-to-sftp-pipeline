"""
Lambda 1: API Gateway → S3

Receives a binary payload from API Gateway, validates a shared secret,
and writes the file to S3 under a configurable prefix with SSE enabled.

Env vars:
- BUCKET_NAME        – target S3 bucket
- INCOMING_PREFIX    – prefix within the bucket, e.g. "incoming/"
- SECRET_PARAM_NAME  – SSM SecureString with the shared API key used in x-api-key header
"""

import os
import base64
import boto3

s3 = boto3.client("s3")
ssm = boto3.client("ssm")

BUCKET_NAME = os.environ["BUCKET_NAME"]
INCOMING_PREFIX = os.environ["INCOMING_PREFIX"]
SECRET_PARAM_NAME = os.environ["SECRET_PARAM_NAME"]

# Cache the shared secret so we don't hit SSM on every invocation
CACHED_SECRET = None


def get_shared_secret() -> str:
    """Return the shared secret from SSM, cached across invocations.
        Could also be moved to Secrets Manager with rotation in a larger setup
    """

    global CACHED_SECRET
    if CACHED_SECRET is None:
        resp = ssm.get_parameter(
            Name=SECRET_PARAM_NAME,
            WithDecryption=True,
        )
        CACHED_SECRET = resp["Parameter"]["Value"]
    return CACHED_SECRET


def lambda_handler(event, context):
    # 1. Auth check: caller must send x-api-key header with the correct secret
    headers = event.get("headers", {}) or {}
    provided_key = headers.get("x-api-key")

    expected_key = get_shared_secret()
    if provided_key != expected_key:
        return {
            "statusCode": 403,
            "body": "Forbidden",
        }

    # 2. Caller must send x-filename header so we know what to call the file
    original_filename = headers.get("x-filename")
    if not original_filename:
        return {
            "statusCode": 400,
            "body": "Missing x-filename header",
        }

    # 3. Extract file bytes from request body
    body_b64 = event.get("body", "")
    if event.get("isBase64Encoded", False):
        file_bytes = base64.b64decode(body_b64)
    else:
        file_bytes = body_b64.encode("utf-8")

    # 4. Build final object key in S3 using only the original filename
    s3_key = f"{INCOMING_PREFIX}{original_filename}"

    # 5. Upload securely to S3 (server-side encryption required)
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=s3_key,
        Body=file_bytes,
        ServerSideEncryption="AES256",  # SSE-S3 encryption at rest
        ContentType="application/octet-stream",  # generic binary payload
    )

    # 6. Return OK to caller
    return {
        "statusCode": 200,
        "body": f"Stored as s3://{BUCKET_NAME}/{s3_key}",
    }
