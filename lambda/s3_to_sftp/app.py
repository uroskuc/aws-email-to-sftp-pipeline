"""
Lambda 2: S3 → SFTP bridge

Primary mode:
- Triggered by S3 ObjectCreated events.
- Streams each new object from S3 to one or more SFTP destinations.
- Destination base dirs are selected via filename-based routing rules
  stored in SSM Parameter Store (SecureString JSON).

Secondary (legacy/test) mode:
- Accepts a direct payload (filename + content/contentBase64)
  and uploads to SFTP using the same configuration model.

Env vars:
- SFTP_PARAM_NAME – SSM SecureString containing SFTP config + routing rules.

Expected SSM JSON structure (sanitized example):

{
  "host": "sftp.example.com",
  "port": 22,
  "user": "username",
  "password": "REDACTED",
  "remote_dir": "/default/out",
  "hostkey_fingerprint": "SHA256:...",
  "routes": [
  { "pattern": "REPORT_DAILY", "base_dir": ["/reports/daily"] },
  { "pattern": "REPORT_INTRADAY", "base_dir": ["/reports/daily", "/partners/intraday"] }
]

}
"""

import os
import json
import io
import re
import base64
import datetime
import hashlib
import logging
from typing import Dict, Any, List
from urllib.parse import unquote_plus
import posixpath  # for safe filename extraction from S3 keys

import boto3
import botocore
import paramiko

# ----- logging -----
logger = logging.getLogger()
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)
logger.setLevel(logging.INFO)

# ----- AWS clients (outside handler for connection reuse) -----
ssm = boto3.client("ssm")
s3 = boto3.client("s3")


# =========================
# --- Utility functions ---
# =========================

def _get_secure_param(name: str) -> str:
    """Return decrypted SecureString value from SSM Parameter Store."""
    resp = ssm.get_parameter(Name=name, WithDecryption=True)
    return resp["Parameter"]["Value"]


def _sanitize_filename(name: str) -> str:
    """Keep only safe characters; limit length to 255 bytes."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)[:255]


def _ensure_dir(sftp: paramiko.SFTPClient, remote_dir: str) -> None:
    """
    Verify that remote_dir exists and is accessible. Do NOT try to create it.
    Raise a clean error if it's not accessible.
    """
    if not remote_dir or remote_dir == "/":
        return

    try:
        sftp.chdir(remote_dir)
    except Exception as e:
        raise FileNotFoundError(f"SFTP: cannot access directory '{remote_dir}': {e}")


def _sha256_fingerprint(host_key: paramiko.PKey) -> str:
    """Return SSH host key fingerprint in 'SHA256:...' form."""
    return "SHA256:" + base64.b64encode(
        hashlib.sha256(host_key.asbytes()).digest()
    ).decode("utf-8")


def _choose_base_dirs_for_name(filename: str, sftp_cfg: Dict[str, Any]) -> List[str]:
    """
    Return one or more SFTP base dirs for the given filename based on SSM 'routes'.
    - Each route: { "pattern": <regex>, "base_dir": <str or [str,...]> }
    - If no route matches, fall back to sftp_cfg['remote_dir'] (if present).
    - If neither rule nor remote_dir exists, raise a clear error.

    All returned dirs are normalized to absolute POSIX paths (no trailing slash).
    """
    name = posixpath.basename(filename or "")
    matched: List[str] = []

    for rule in sftp_cfg.get("routes", []):
        pat = rule.get("pattern")
        target = rule.get("base_dir")
        if not pat or not target:
            continue
        try:
            if re.search(pat, name):
                if isinstance(target, list):
                    matched.extend(target)
                else:
                    matched.append(target)
        except re.error:
            # Invalid regex in SSM; skip and continue
            continue

    if not matched:
        fallback = sftp_cfg.get("remote_dir")
        if not fallback:
            raise RuntimeError(
                f"No route matched filename '{name}' and SSM config has no 'remote_dir' fallback."
            )
        matched = [fallback]

    # Normalize to absolute POSIX paths
    normalized: List[str] = []
    for d in matched:
        d = d if d.startswith("/") else f"/{d}"
        normalized.append(d.rstrip("/"))
    return normalized


def _open_sftp_conn(cfg: Dict[str, Any]) -> paramiko.SFTPClient:
    """Open and return an SFTP client based on the given cfg dict."""
    host = cfg["host"]
    port = int(cfg.get("port", 22))
    user = cfg["user"]
    password = cfg["password"]
    hostkey_fp_expected = cfg.get("hostkey_fingerprint")  # optional

    transport = paramiko.Transport((host, port))
    transport.banner_timeout = 20
    transport.auth_timeout = 20
    transport.set_keepalive(15)

    transport.connect(username=user, password=password)

    # Optional host key pinning
    try:
        key = transport.get_remote_server_key()
        if hostkey_fp_expected:
            got = _sha256_fingerprint(key)
            if got != hostkey_fp_expected:
                transport.close()
                raise RuntimeError(
                    f"Host key mismatch. Expected {hostkey_fp_expected}, got {got}"
                )
    except Exception as e:
        logger.warning("Could not verify host key fingerprint: %s", e)

    return paramiko.SFTPClient.from_transport(transport)


def _close_sftp(sftp: paramiko.SFTPClient) -> None:
    """Close SFTP client safely."""
    try:
        if sftp:
            sftp.close()
    except Exception:
        pass


def _stream_s3_to_sftp(
    bucket: str,
    key: str,
    sftp: paramiko.SFTPClient,
    remote_path: str,
    chunk_size: int = 8 * 1024 * 1024,
) -> int:
    """
    Stream an S3 object to SFTP without loading the whole file in memory.
    Returns the number of bytes written.
    """
    try:
        obj = s3.get_object(Bucket=bucket, Key=key)
    except botocore.exceptions.ClientError as e:
        raise RuntimeError(f"S3 get_object failed for s3://{bucket}/{key}: {e}")

    body = obj["Body"]
    total = 0
    with sftp.file(remote_path, "wb") as remote_fh:
        while True:
            chunk = body.read(chunk_size)
            if not chunk:
                break
            remote_fh.write(chunk)
            total += len(chunk)
        remote_fh.flush()
    return total


# ==============================================
# --- Backwards-compatible request validation ---
# ==============================================

def _handle_direct_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Backwards-compatible path: allow manual invocation that directly sends file content.

    Expected event shape (examples):
    {
      "filename": "example.txt",
      "contentBase64": "...",    # preferred
      "remote_dir": "/optional/override"
    }
    OR
    {
      "filename": "example.txt",
      "content": "raw text",
      "remote_dir": "/optional/override"
    }
    """
    filename = event.get("filename") or (
        f"lambda-upload-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.txt"
    )
    filename = _sanitize_filename(filename)

    b64 = event.get("contentBase64")
    text = event.get("content")

    if b64:
        try:
            file_bytes = base64.b64decode(b64)
        except Exception:
            return {"statusCode": 400, "body": "contentBase64 is not valid base64"}
    else:
        if text is None:
            text = f"Hello from Lambda at {datetime.datetime.utcnow().isoformat()}Z"
        file_bytes = text.encode("utf-8")

    param_name = os.environ["SFTP_PARAM_NAME"]  # required
    sftp_cfg = json.loads(_get_secure_param(param_name))

    remote_dir_override = event.get("remote_dir")

    # Decide one or more destinations:
    # 1) explicit override from event (absolute-ize), else
    # 2) route by filename via SSM 'routes', else
    # 3) fallback to ssm['remote_dir'] (error if none)
    if remote_dir_override:
        base_dirs = [
            remote_dir_override
            if remote_dir_override.startswith("/")
            else f"/{remote_dir_override}"
        ]
    else:
        base_dirs = _choose_base_dirs_for_name(filename, sftp_cfg)

    sftp = None
    try:
        sftp = _open_sftp_conn(sftp_cfg)
        uploaded_to: List[str] = []
        total_written = 0
        for base_dir in base_dirs:
            _ensure_dir(sftp, base_dir)
            remote_path = f"{base_dir}/{filename}"
            sftp.putfo(io.BytesIO(file_bytes), remote_path)
            logger.info("Upload ok: %s (%d bytes)", remote_path, len(file_bytes))
            uploaded_to.append(remote_path)
            total_written += len(file_bytes)
        return {
            "statusCode": 200,
            "body": json.dumps(
                {
                    "ok": True,
                    "uploaded_to": uploaded_to,
                    "size_bytes_total": total_written,
                }
            ),
        }

    except Exception as e:
        logger.exception("Direct payload upload failed")
        return {"statusCode": 500, "body": f"SFTP error: {repr(e)}"}
    finally:
        _close_sftp(sftp)


# ========================================
# --- S3 Event-driven transfer to SFTP  ---
# ========================================

def _records_from_s3_event(event: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract (bucket, key) pairs from S3 event. Ignores non-object-created records."""
    out: List[Dict[str, str]] = []
    for rec in event.get("Records", []):
        if (
            rec.get("eventSource") == "aws:s3"
            and rec.get("eventName", "").startswith("ObjectCreated:")
        ):
            bucket = rec["s3"]["bucket"]["name"]
            key = rec["s3"]["object"]["key"]
            # S3 event delivers URL-encoded key
            key = unquote_plus(key)
            out.append({"bucket": bucket, "key": key})
    return out


def _remote_path_from_key(base_dir: str, key: str, naming: str = "basename") -> str:
    """
    Map S3 key to SFTP path.

    naming = "basename" (default) -> place only the filename under base_dir
    naming = "preserve"           -> replicate S3 key folders under base_dir
    """
    if not base_dir.startswith("/"):
        base_dir = "/" + base_dir

    if naming == "preserve":
        cleaned = "/".join(part for part in key.split("/") if part)
        return f"{base_dir.rstrip('/')}/{cleaned}"
    else:
        from posixpath import basename
        return f"{base_dir.rstrip('/')}/{basename(key)}"


# ======================
# --- Lambda handler ---
# ======================

def lambda_handler(event, context):
    """
    Dual-mode handler:

    1) If invoked by S3 event (Records[].eventSource == 'aws:s3'),
       stream each created object to SFTP using routing rules from SSM.

    2) Otherwise, fall back to the direct-payload API behavior
       (filename/content or contentBase64), useful for manual/testing.

    Env:
    - SFTP_PARAM_NAME: SSM SecureString with SFTP config + routing.
    """
    try:
        # If it's an S3 event, process records
        s3_records = _records_from_s3_event(event)
        if s3_records:
            param_name = os.environ["SFTP_PARAM_NAME"]
            sftp_cfg = json.loads(_get_secure_param(param_name))
            results: List[Dict[str, Any]] = []
            sftp = None
            try:
                sftp = _open_sftp_conn(sftp_cfg)
                for rec in s3_records:
                    bucket = rec["bucket"]
                    key = rec["key"]
                    file_name = posixpath.basename(key)
                    base_dirs = _choose_base_dirs_for_name(file_name, sftp_cfg)
                    for base_dir in base_dirs:
                        remote_path = _remote_path_from_key(
                            base_dir, key, naming="basename"
                        )
                        parent = "/".join(remote_path.split("/")[:-1]) or "/"
                        _ensure_dir(sftp, parent)

                        bytes_written = _stream_s3_to_sftp(
                            bucket, key, sftp, remote_path
                        )
                        logger.info(
                            "Transferred s3://%s/%s -> %s (%d bytes)",
                            bucket,
                            key,
                            remote_path,
                            bytes_written,
                        )
                        results.append(
                            {
                                "bucket": bucket,
                                "key": key,
                                "uploaded_to": remote_path,
                                "size_bytes": bytes_written,
                            }
                        )
                return {
                    "statusCode": 200,
                    "body": json.dumps({"ok": True, "results": results}),
                }
            except Exception as e:
                logger.exception("S3 event handling failed")
                return {
                    "statusCode": 500,
                    "body": f"Error while transferring from S3: {repr(e)}",
                }
            finally:
                _close_sftp(sftp)

        # Otherwise, handle as direct API payload
        if not isinstance(event, dict):
            return {"statusCode": 400, "body": "Invalid event: expected JSON object"}
        return _handle_direct_payload(event)

    except Exception as e:
        logger.exception("Unhandled error")
        return {"statusCode": 500, "body": f"Error: {repr(e)}"}
