"""
github_app — Intelli-Scan GitHub App integration package.

Exports the public surface used by main.py.
"""

from .app_config import (
    GitHubAppConfig,
    load_github_app_config,
    get_installation_access_token,
    github_app_configured,
)
from .webhook_handler import (
    WebhookEvent,
    verify_webhook_signature,
    parse_webhook_payload,
)
from .diff_scanner import DiffScopedScanner
from .pr_manager import PRManager

__all__ = [
    "GitHubAppConfig",
    "load_github_app_config",
    "get_installation_access_token",
    "github_app_configured",
    "WebhookEvent",
    "verify_webhook_signature",
    "parse_webhook_payload",
    "DiffScopedScanner",
    "PRManager",
]
