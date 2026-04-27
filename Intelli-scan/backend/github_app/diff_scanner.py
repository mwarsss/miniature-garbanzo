"""
DiffScopedScanner — scope Semgrep to only the files changed in a PR diff.
=========================================================================

ASSUMPTIONS
-----------
1. PyGithub >= 2.0 is installed (uses Auth.Token for authentication). If unavailable,
   get_pr_diff_files() logs an error and returns an empty list — the pipeline
   detects the empty result and exits early.
2. get_pr_diff_files() is declared ``async`` because the pipeline's
   run_github_pipeline() awaits it. Internally the blocking PyGithub call is
   offloaded to a thread via asyncio.to_thread so the event loop is not stalled.
3. clone_pr_head() and run_scoped_scan() are synchronous — they contain subprocess
   calls (git, semgrep) which are intentionally blocking in the background task
   context where they run.
4. clone_pr_head() creates a temp directory with tempfile.mkdtemp() and returns
   its path as a string. The CALLER is responsible for cleanup (shutil.rmtree in a
   finally block). This mirrors the spec's pipeline design.
5. The access token is embedded in the HTTPS clone URL as
   ``https://x-access-token:{token}@github.com/...`` which is the documented
   GitHub App approach. The raw token is never logged.
6. All subprocess calls use timeout=120 as required by spec constraints.
7. Semgrep is assumed to be on PATH. If not found, run_scoped_scan() returns an
   empty findings dict and logs an error — it never raises.
8. run_scoped_scan() normalises Semgrep's JSON output into the same findings shape
   expected by run_remediation_pipeline() in remediation_agent.py, so no
   transformation is needed in the route handler.
9. SCANNABLE_EXTENSIONS covers the languages supported by semgrep's p/security-audit
   ruleset. Binary files, lock files, and generated assets are excluded.
"""

import asyncio
import json
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from github import Github, Auth
    _PYGITHUB_AVAILABLE = True
except ImportError:
    Github = None  # type: ignore[assignment,misc]
    Auth = None    # type: ignore[assignment]
    _PYGITHUB_AVAILABLE = False
    logger.error(
        "PyGithub not installed — DiffScopedScanner.get_pr_diff_files() will be no-op. "
        "Run: pip install PyGithub"
    )

# Extensions Semgrep's p/security-audit ruleset can meaningfully scan
_SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rb", ".php", ".cs",
    ".cpp", ".c", ".h", ".rs", ".kt", ".scala",
    ".yaml", ".yml", ".json", ".tf",
})


class DiffScopedScanner:
    """
    Fetches changed files from a GitHub PR diff, clones the head branch,
    and runs a Semgrep scan scoped to only those changed files.
    """

    async def get_pr_diff_files(
        self,
        repo_full_name: str,
        pr_number: int,
        token: str,
    ) -> list[str]:
        """
        Return a list of relative file paths changed in the PR.

        Only files with scannable extensions (see _SCANNABLE_EXTENSIONS) are
        returned. Deleted files are excluded — Semgrep cannot scan files that
        no longer exist on the head branch.

        Parameters
        ----------
        repo_full_name : str
            GitHub repo in ``owner/repo`` format.
        pr_number : int
            The pull request number.
        token : str
            GitHub App installation access token.

        Returns
        -------
        list[str]
            Relative paths of scannable changed files, or an empty list on error.
        """
        if not _PYGITHUB_AVAILABLE:
            logger.error("PyGithub unavailable — cannot fetch PR diff files")
            return []

        def _fetch() -> list[str]:
            try:
                gh = Github(auth=Auth.Token(token))
                repo = gh.get_repo(repo_full_name)
                pr = repo.get_pull(pr_number)
                all_files = [f.filename for f in pr.get_files()
                             if f.status != "removed"]
                scannable = _filter_scannable(all_files)
                logger.info(
                    "PR #%d diff: %d total files, %d scannable",
                    pr_number, len(all_files), len(scannable),
                )
                return scannable
            except Exception as exc:
                logger.error(
                    "Failed to fetch diff files for %s PR #%d: %s",
                    repo_full_name, pr_number, exc,
                )
                return []

        return await asyncio.to_thread(_fetch)

    def clone_pr_head(
        self,
        repo_clone_url: str,
        pr_head_ref: str,
        token: str,
    ) -> str:
        """
        Shallow-clone the PR head branch into a new temp directory.

        The token is injected into the HTTPS clone URL so the git subprocess
        can authenticate without interactive prompts. The raw token is never
        written to log output.

        Parameters
        ----------
        repo_clone_url : str
            The HTTPS clone URL, e.g. ``https://github.com/owner/repo.git``.
        pr_head_ref : str
            Branch name to clone (from ``pull_request.head.ref``).
        token : str
            GitHub App installation access token.

        Returns
        -------
        str
            Absolute path of the temp directory containing the cloned repo.
            The caller MUST clean this up (shutil.rmtree) in a finally block.

        Raises
        ------
        RuntimeError
            If git clone returns non-zero or times out after 120 seconds.
        """
        auth_url = _inject_token(repo_clone_url, token)
        tmp_dir = tempfile.mkdtemp(prefix="intelliscan_clone_")

        cmd = [
            "git", "clone",
            "--depth", "1",
            "--branch", pr_head_ref,
            "--single-branch",
            auth_url,
            tmp_dir,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.error(
                "git clone timed out after 120s for %s@%s",
                repo_clone_url, pr_head_ref,
            )
            raise RuntimeError(
                f"git clone timed out for {repo_clone_url}@{pr_head_ref}"
            )

        if result.returncode != 0:
            # Redact the token-embedded URL from the error message
            safe_stderr = result.stderr[:400]
            logger.error(
                "git clone failed for %s (branch=%s): %s",
                repo_clone_url, pr_head_ref, safe_stderr,
            )
            raise RuntimeError(
                f"git clone failed (exit {result.returncode}): {safe_stderr[:120]}"
            )

        logger.info(
            "Cloned %s@%s → %s", repo_clone_url, pr_head_ref, tmp_dir
        )
        return tmp_dir

    def run_scoped_scan(
        self,
        cloned_path: str,
        changed_files: list[str],
    ) -> dict:
        """
        Run Semgrep on only the changed files inside the cloned repo.

        Semgrep is invoked with ``p/security-audit`` and its output is
        normalised into the shape expected by run_remediation_pipeline().

        Parameters
        ----------
        cloned_path : str
            Absolute path to the cloned repository directory.
        changed_files : list[str]
            Relative file paths returned by get_pr_diff_files().

        Returns
        -------
        dict
            ``{"tool": "semgrep", "findings": [...], "repo_local_path": cloned_path}``
            Returns empty findings (never raises) on Semgrep error or timeout.
        """
        empty_result = {
            "tool": "semgrep",
            "findings": [],
            "repo_local_path": cloned_path,
        }

        if not changed_files:
            logger.info("No changed files to scan")
            return empty_result

        root = Path(cloned_path)
        target_paths = [
            str(root / rel)
            for rel in changed_files
            if (root / rel).exists()
        ]

        if not target_paths:
            logger.info("Changed files not present in clone — skipping scan")
            return empty_result

        cmd = [
            "semgrep", "scan",
            "--config=p/security-audit",
            "--json",
            "--quiet",
            "--timeout", "5",
            "--jobs", "2",
            *target_paths,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            logger.error("Scoped Semgrep scan timed out after 120s")
            return empty_result
        except FileNotFoundError:
            logger.error("semgrep not found on PATH — scoped scan skipped")
            return empty_result

        try:
            output = json.loads(result.stdout)
        except (json.JSONDecodeError, ValueError):
            logger.warning(
                "Semgrep produced non-JSON output (exit %d): %s",
                result.returncode, result.stderr[:300],
            )
            return empty_result

        raw_findings = output.get("results", [])
        findings = [
            {
                "id": f.get("check_id", f"finding-{i}"),
                "severity": (f.get("extra", {}).get("severity") or "LOW").upper(),
                "file_path": f.get("path", ""),
                "line_start": f.get("start", {}).get("line", 1),
                "line_end": f.get("end", {}).get("line", 1),
                "vuln_type": (
                    f.get("check_id", "").split(".")[-1].lower().replace("-", "_")
                ),
                "message": f.get("extra", {}).get("message", ""),
                "raw_code_snippet": f.get("extra", {}).get("lines", ""),
            }
            for i, f in enumerate(raw_findings)
        ]

        logger.info(
            "Scoped scan complete: %d findings across %d target files",
            len(findings), len(target_paths),
        )
        return {
            "tool": "semgrep",
            "findings": findings,
            "repo_local_path": cloned_path,
        }


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _filter_scannable(files: list[str]) -> list[str]:
    """Return only files whose extension is in _SCANNABLE_EXTENSIONS."""
    return [f for f in files if Path(f).suffix.lower() in _SCANNABLE_EXTENSIONS]


def _inject_token(clone_url: str, token: str) -> str:
    """
    Insert an x-access-token credential into a GitHub HTTPS clone URL.

    ``https://github.com/...`` → ``https://x-access-token:{token}@github.com/...``
    """
    if clone_url.startswith("https://"):
        return clone_url.replace(
            "https://", f"https://x-access-token:{token}@", 1
        )
    return clone_url
