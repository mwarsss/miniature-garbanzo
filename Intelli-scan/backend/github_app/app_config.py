"""
GitHub App configuration and authentication — app_config.py
============================================================

ASSUMPTIONS
-----------
1. GITHUB_APP_ID is the numeric App ID (string) from the GitHub App settings page
   under Settings → Developer settings → GitHub Apps → your app → General.
2. GITHUB_APP_PRIVATE_KEY is the full RSA private key content (PEM format). When set
   via an environment variable, literal newlines may be escaped as \\n — both forms
   are normalised here before use.
3. GITHUB_APP_WEBHOOK_SECRET is the arbitrary secret string configured in the GitHub
   App's "Webhook" section. It must match what the app receives in
   X-Hub-Signature-256.
4. GITHUB_APP_CLIENT_ID and GITHUB_APP_CLIENT_SECRET are the OAuth app credentials
   visible on the same settings page. They are not used for webhook auth but are
   required for the GitHub App OAuth flow if needed in future.
5. Per spec: the JWT/installation token exchange is hand-rolled via requests
   rather than delegated to PyGithub, because PyGithub's AppAuth helpers require
   the same steps and pinning to PyGithub's internal implementation is fragile.
6. JWT expiry is set to 10 minutes (the GitHub-documented maximum for App JWTs).
   Tokens are NOT cached here; the caller receives a fresh token per pipeline run.
7. PyJWT with the [cryptography] extra is required for RS256 signing. If unavailable,
   every call to get_installation_access_token() raises RuntimeError immediately.
8. github_app_configured() is purely an env-var existence check — it does NOT verify
   that the credentials are valid. Used by the /webhooks/github/status health route.
"""

import os
import time
import logging
import requests
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Soft import — fail loudly at call-time, not at import-time
# ---------------------------------------------------------------------------
try:
    import jwt as _pyjwt
    _JWT_AVAILABLE = True
except ImportError:
    _pyjwt = None  # type: ignore[assignment]
    _JWT_AVAILABLE = False
    logger.error(
        "PyJWT not installed — GitHub App JWT signing unavailable. "
        "Run: pip install PyJWT[cryptography]"
    )

_REQUIRED_ENV_VARS = (
    "GITHUB_APP_ID",
    "GITHUB_APP_PRIVATE_KEY",
    "GITHUB_APP_WEBHOOK_SECRET",
    "GITHUB_APP_CLIENT_ID",
    "GITHUB_APP_CLIENT_SECRET",
)


# ---------------------------------------------------------------------------
# Config dataclass
# ---------------------------------------------------------------------------

@dataclass
class GitHubAppConfig:
    """Holds all credentials required to act as the Intelli-Scan GitHub App."""

    app_id: str
    private_key: str      # Full PEM string, newlines normalised
    webhook_secret: str
    client_id: str
    client_secret: str


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def load_github_app_config() -> GitHubAppConfig:
    """
    Read GitHub App credentials from environment variables and return a
    GitHubAppConfig.

    Does NOT validate that the credentials are correct — call
    get_installation_access_token() to verify connectivity.
    """
    raw_key = os.environ.get("GITHUB_APP_PRIVATE_KEY", "")
    # Normalise \\n escape sequences that shells or .env parsers may introduce
    if raw_key and "\\n" in raw_key:
        raw_key = raw_key.replace("\\n", "\n")

    return GitHubAppConfig(
        app_id=os.environ.get("GITHUB_APP_ID", ""),
        private_key=raw_key,
        webhook_secret=os.environ.get("GITHUB_APP_WEBHOOK_SECRET", ""),
        client_id=os.environ.get("GITHUB_APP_CLIENT_ID", ""),
        client_secret=os.environ.get("GITHUB_APP_CLIENT_SECRET", ""),
    )


def github_app_configured() -> bool:
    """Return True only if all 5 required GitHub App env vars are present and non-empty."""
    return all(os.environ.get(v) for v in _REQUIRED_ENV_VARS)


def get_installation_access_token(installation_id: int, config: GitHubAppConfig) -> str:
    """
    Exchange a short-lived GitHub App JWT for an installation access token.

    Flow
    ----
    1. Generate a JWT signed with the App's RSA private key (RS256, 10-minute TTL).
    2. POST /app/installations/{installation_id}/access_tokens with the JWT as Bearer.
    3. Return the ``token`` string from the JSON response.

    Parameters
    ----------
    installation_id : int
        The numeric installation ID found in the webhook payload under
        ``installation.id``.
    config : GitHubAppConfig
        Loaded via load_github_app_config().

    Returns
    -------
    str
        A short-lived installation access token (~1 hour TTL).

    Raises
    ------
    RuntimeError
        If PyJWT is missing, if the RSA key is invalid, or if the GitHub API
        returns a non-2xx response.
    """
    app_jwt = _generate_app_jwt(config)

    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    headers = {
        "Authorization": f"Bearer {app_jwt}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        resp = requests.post(url, headers=headers, timeout=30)
        resp.raise_for_status()
    except requests.RequestException as exc:
        logger.error(
            "GitHub installation token request failed (installation_id=%d): %s",
            installation_id, exc,
        )
        raise RuntimeError(f"GitHub token exchange failed: {exc}") from exc

    token = resp.json().get("token", "")
    if not token:
        raise RuntimeError(
            f"GitHub API returned empty token for installation {installation_id}"
        )

    logger.debug(
        "Installation access token obtained for installation_id=%d", installation_id
    )
    return token


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _generate_app_jwt(config: GitHubAppConfig) -> str:
    """
    Build a RS256-signed JWT for the GitHub App.

    iat is set 60 seconds in the past to absorb clock skew between this server
    and GitHub's API servers — a common production issue.
    """
    if not _JWT_AVAILABLE:
        raise RuntimeError(
            "PyJWT is required for GitHub App authentication. "
            "Install it with: pip install PyJWT[cryptography]"
        )
    if not config.private_key:
        raise RuntimeError("GITHUB_APP_PRIVATE_KEY is not set")
    if not config.app_id:
        raise RuntimeError("GITHUB_APP_ID is not set")

    now = int(time.time())
    payload = {
        "iat": now - 60,          # issued-at: 60s in the past for clock drift
        "exp": now + (10 * 60),   # expires in 10 minutes (GitHub maximum)
        "iss": config.app_id,
    }

    try:
        token: str = _pyjwt.encode(payload, config.private_key, algorithm="RS256")
        return token
    except Exception as exc:
        logger.error("Failed to sign GitHub App JWT: %s", exc)
        raise RuntimeError(f"JWT signing failed: {exc}") from exc
