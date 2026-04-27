"""
GitHub webhook payload verification and parsing — webhook_handler.py
====================================================================

ASSUMPTIONS
-----------
1. Only ``pull_request`` events with actions ``opened``, ``synchronize``, and
   ``reopened`` are processed. All other actions (closed, labeled, etc.) return
   None from parse_webhook_payload() and are silently ignored at the route level.
2. verify_webhook_signature() uses HMAC-SHA256 matching GitHub's X-Hub-Signature-256
   scheme. If the webhook secret is empty/unset it logs a warning and returns True
   (permissive mode) — production deployments must always set the secret.
3. The ``installation`` key in the payload is required for GitHub App webhooks. If
   missing (e.g. a plain repository webhook not coming through an App), installation_id
   defaults to 0 and get_installation_access_token() will subsequently fail — the
   pipeline logs the error and never crashes the response handler.
4. parse_webhook_payload() treats KeyError on any required field as a malformed
   payload and returns None rather than raising, so the webhook route can always
   return HTTP 200 even on unexpected payload shapes (GitHub will retry on 5xx).
5. WebhookEvent is a plain dataclass — no Pydantic validation — to keep it
   dependency-free and avoid double-parsing cost in the route handler.
"""

import hashlib
import hmac
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

_SUPPORTED_ACTIONS = frozenset({"opened", "synchronize", "reopened"})


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------

@dataclass
class WebhookEvent:
    """Parsed representation of a GitHub pull_request webhook event."""

    action: str
    installation_id: int
    repo_full_name: str
    repo_clone_url: str
    pr_number: int
    pr_head_sha: str
    pr_head_ref: str       # branch name (e.g. "feature/my-branch")
    pr_base_ref: str       # target branch name (e.g. "main")


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def verify_webhook_signature(
    raw_body: bytes,
    signature_header: str,
    secret: str,
) -> bool:
    """
    Verify the HMAC-SHA256 signature on an incoming GitHub webhook request.

    Parameters
    ----------
    raw_body : bytes
        The raw (un-decoded) request body. Must be read BEFORE JSON parsing
        because HMAC is computed over the exact bytes GitHub sent.
    signature_header : str
        The value of the ``X-Hub-Signature-256`` header. Expected format:
        ``sha256=<hex-digest>``.
    secret : str
        The webhook secret configured in the GitHub App settings.

    Returns
    -------
    bool
        True if the signature is valid (or if no secret is configured).
        False if the header is missing/malformed or the digest does not match.
    """
    if not secret:
        logger.warning(
            "GITHUB_APP_WEBHOOK_SECRET is not set — skipping signature verification. "
            "Set this variable in production."
        )
        return True

    if not signature_header or not signature_header.startswith("sha256="):
        logger.warning(
            "X-Hub-Signature-256 header missing or malformed: %r", signature_header
        )
        return False

    expected = "sha256=" + hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    valid = hmac.compare_digest(expected, signature_header)
    if not valid:
        logger.warning("Webhook signature mismatch — request rejected")
    return valid


def parse_webhook_payload(payload: dict) -> Optional[WebhookEvent]:
    """
    Parse a ``pull_request`` webhook payload dict into a WebhookEvent.

    Returns None for unsupported actions or malformed payloads; the caller
    should respond with HTTP 200 in both cases (GitHub must not retry).

    Parameters
    ----------
    payload : dict
        The JSON-decoded webhook body.

    Returns
    -------
    WebhookEvent | None
        Parsed event, or None if the action is unsupported or required fields
        are absent.
    """
    action = payload.get("action", "")
    if action not in _SUPPORTED_ACTIONS:
        logger.info(
            "PR action '%s' is not in supported set %s — ignoring",
            action, sorted(_SUPPORTED_ACTIONS),
        )
        return None

    try:
        pr = payload["pull_request"]
        repo = payload["repository"]
        installation = payload.get("installation") or {}

        event = WebhookEvent(
            action=action,
            installation_id=int(installation.get("id", 0)),
            repo_full_name=repo["full_name"],
            repo_clone_url=repo["clone_url"],
            pr_number=int(pr["number"]),
            pr_head_sha=pr["head"]["sha"],
            pr_head_ref=pr["head"]["ref"],
            pr_base_ref=pr["base"]["ref"],
        )
        logger.debug(
            "Parsed WebhookEvent: repo=%s pr=#%d action=%s sha=%s",
            event.repo_full_name, event.pr_number, event.action, event.pr_head_sha[:7],
        )
        return event

    except (KeyError, TypeError, ValueError) as exc:
        logger.error("Malformed pull_request webhook payload — %s", exc)
        return None
