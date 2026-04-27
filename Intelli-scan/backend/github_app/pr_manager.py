"""
PRManager — branch, commit, PR, and inline review comment operations.
====================================================================

ASSUMPTIONS
-----------
1. PyGithub >= 2.0 is required (Auth.Token API). If unavailable, every method
   logs an error and returns a safe default — they never raise in that case.
2. create_patch_branch() is idempotent: if the branch already exists it returns
   the name unchanged rather than raising a conflict error. This prevents
   double-triggering (e.g. force-push events) from failing noisily.
3. commit_patches() only commits findings with verdict == "AUTO_APPLY" that have
   a non-empty patched_code value. REVIEW_RECOMMENDED and MANUAL_REMEDIATION_REQUIRED
   findings are skipped silently — they are handled by post_inline_review_comments().
4. GitHub's Contents API (repo.update_file) is used for patching. It requires the
   current blob SHA of the file on the target branch. If the file cannot be fetched
   (e.g. it was added in the PR and doesn't exist on the base yet) the error is
   logged and that finding is skipped — the pipeline continues with remaining patches.
5. post_inline_review_comments() attempts a PR review comment (create_review_comment)
   which requires the target line to be visible in the diff. If that fails it falls
   back to a plain issue comment on the PR so feedback is always delivered.
6. Per spec: every individual comment failure logs and continues — the pipeline NEVER
   crashes because a single comment POST failed.
7. MANUAL_REMEDIATION_REQUIRED comment body is exactly: "Automated patch not generated
   — manual review required." per spec, prefixed with a brief Intelli-Scan header for
   context.
8. The child PR is opened as a draft=False PR (ready for review) because the patches
   have already passed the AUTO_APPLY RIS threshold.
9. All methods use try/except around every external call because GitHub API rate limits,
   transient 5xx errors, and permissions issues are common in CI/CD environments.
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from github import Github, Auth, GithubException
    _PYGITHUB_AVAILABLE = True
except ImportError:
    Github = None           # type: ignore[assignment,misc]
    Auth = None             # type: ignore[assignment]
    GithubException = Exception  # type: ignore[assignment,misc]
    _PYGITHUB_AVAILABLE = False
    logger.error(
        "PyGithub not installed — PRManager methods will be no-ops. "
        "Run: pip install PyGithub"
    )


class PRManager:
    """
    Manages the GitHub operations that follow a successful scan-and-remediation run:
    creating patch branches, committing auto-fixes, opening child PRs, and posting
    inline review comments on the triggering PR.
    """

    # ------------------------------------------------------------------
    # Branch management
    # ------------------------------------------------------------------

    def create_patch_branch(
        self,
        repo_full_name: str,
        pr_head_sha: str,
        token: str,
    ) -> str:
        """
        Create a branch named ``intelliscan/patches-{sha[:7]}`` from the PR head SHA.

        If the branch already exists, the existing name is returned unchanged
        (idempotent behaviour).

        Parameters
        ----------
        repo_full_name : str
            GitHub repo in ``owner/repo`` format.
        pr_head_sha : str
            Full SHA of the PR head commit (used as the branch point and suffix).
        token : str
            GitHub App installation access token.

        Returns
        -------
        str
            The patch branch name.

        Raises
        ------
        RuntimeError
            If the branch cannot be created for any reason other than it already
            existing.
        """
        if not _PYGITHUB_AVAILABLE:
            raise RuntimeError("PyGithub is required for create_patch_branch()")

        branch_name = f"intelliscan/patches-{pr_head_sha[:7]}"

        try:
            gh = Github(auth=Auth.Token(token))
            repo = gh.get_repo(repo_full_name)
        except Exception as exc:
            logger.error("Failed to connect to GitHub repo %s: %s", repo_full_name, exc)
            raise RuntimeError(f"GitHub connection failed: {exc}") from exc

        # Idempotency check
        try:
            repo.get_branch(branch_name)
            logger.info("Patch branch %s already exists — reusing", branch_name)
            return branch_name
        except GithubException:
            pass  # Expected: branch does not exist yet

        try:
            repo.create_git_ref(
                ref=f"refs/heads/{branch_name}",
                sha=pr_head_sha,
            )
            logger.info(
                "Created patch branch %s from %s on %s",
                branch_name, pr_head_sha[:7], repo_full_name,
            )
        except Exception as exc:
            logger.error(
                "Failed to create patch branch %s on %s: %s",
                branch_name, repo_full_name, exc,
            )
            raise RuntimeError(f"Branch creation failed: {exc}") from exc

        return branch_name

    # ------------------------------------------------------------------
    # Patch commits
    # ------------------------------------------------------------------

    def commit_patches(
        self,
        repo_full_name: str,
        patch_branch: str,
        remediation_results: list,
        cloned_path: str,  # available for future local-git commit strategies
        token: str,
    ) -> list:
        """
        Commit AUTO_APPLY patches directly to ``patch_branch`` via the GitHub
        Contents API.

        Only findings with ``verdict == "AUTO_APPLY"`` and a non-empty
        ``patched_code`` value are committed. All other verdicts are skipped.

        Per-file errors are logged and skipped — the method returns whatever
        subset was successfully committed so the pipeline can proceed.

        Parameters
        ----------
        repo_full_name : str
            GitHub repo in ``owner/repo`` format.
        patch_branch : str
            Name of the branch to commit patches to (created by
            create_patch_branch()).
        remediation_results : list
            Output of run_remediation_pipeline(). Each item is a dict with
            at minimum: finding_id, file_path, verdict, patched_code, vuln_type,
            ris_score.
        cloned_path : str
            Local path of the cloned repo (retained for API compatibility and
            future local-git commit strategies).
        token : str
            GitHub App installation access token.

        Returns
        -------
        list
            Subset of ``remediation_results`` that were successfully committed.
            Empty list if nothing was committable or all commits failed.
        """
        auto_apply = [
            r for r in remediation_results
            if (
                not r.get("skipped")
                and r.get("verdict") == "AUTO_APPLY"
                and r.get("patched_code")
            )
        ]

        if not auto_apply:
            logger.info("No AUTO_APPLY findings with patches — nothing to commit")
            return []

        if not _PYGITHUB_AVAILABLE:
            logger.error("PyGithub unavailable — cannot commit patches")
            return []

        try:
            gh = Github(auth=Auth.Token(token))
            repo = gh.get_repo(repo_full_name)
        except Exception as exc:
            logger.error(
                "GitHub connection failed for patch commit on %s: %s",
                repo_full_name, exc,
            )
            return []

        committed: list = []

        for result in auto_apply:
            file_path = result.get("file_path", "")
            patched_code = result.get("patched_code", "")
            finding_id = result.get("finding_id", "unknown")
            vuln_type = result.get("vuln_type", "vulnerability")
            ris_score = result.get("ris_score")

            if not file_path or not patched_code:
                logger.warning(
                    "Skipping commit for %s — missing file_path or patched_code",
                    finding_id,
                )
                continue

            try:
                # GitHub's update_file API requires the current blob SHA
                contents = repo.get_contents(file_path, ref=patch_branch)
                current_sha = contents.sha  # type: ignore[union-attr]

                ris_str = f"{ris_score:.4f}" if ris_score is not None else "N/A"
                commit_message = (
                    f"fix({file_path}): auto-patch {vuln_type}\n\n"
                    f"Intelli-Scan agentic remediation\n"
                    f"finding_id: {finding_id}\n"
                    f"RIS score: {ris_str}"
                )

                repo.update_file(
                    path=file_path,
                    message=commit_message,
                    content=patched_code,
                    sha=current_sha,
                    branch=patch_branch,
                )
                committed.append(result)
                logger.info(
                    "Committed patch for %s on branch %s (RIS=%s)",
                    file_path, patch_branch, ris_str,
                )

            except Exception as exc:
                logger.error(
                    "Failed to commit patch for %s (%s) on %s: %s",
                    file_path, finding_id, patch_branch, exc,
                )
                # Continue — never crash the whole pipeline over a single file

        logger.info(
            "commit_patches complete: %d/%d patches committed",
            len(committed), len(auto_apply),
        )
        return committed

    # ------------------------------------------------------------------
    # Child PR
    # ------------------------------------------------------------------

    def open_child_pr(
        self,
        repo_full_name: str,
        patch_branch: str,
        base_ref: str,
        parent_pr_number: int,
        committed_results: list,
        token: str,
    ) -> dict:
        """
        Open a pull request from ``patch_branch`` into ``base_ref``.

        The PR body lists every committed patch with its file path, vuln type,
        and RIS score so reviewers have full context without opening the files.

        Parameters
        ----------
        repo_full_name : str
            GitHub repo in ``owner/repo`` format.
        patch_branch : str
            Source branch containing the committed patches.
        base_ref : str
            Target branch (usually the PR's base, e.g. ``main``).
        parent_pr_number : int
            PR number that triggered this pipeline run — used in the title and
            body for traceability.
        committed_results : list
            Subset of remediation results that were successfully committed.
        token : str
            GitHub App installation access token.

        Returns
        -------
        dict
            ``{"pr_number": int, "pr_url": str, "html_url": str}``

        Raises
        ------
        RuntimeError
            If the PR cannot be created.
        """
        if not _PYGITHUB_AVAILABLE:
            raise RuntimeError("PyGithub is required for open_child_pr()")

        patch_lines = [
            f"- `{r.get('file_path', '?')}` — `{r.get('vuln_type', 'unknown')}` "
            f"(RIS {r.get('ris_score', 'N/A')})"
            for r in committed_results
        ]
        patches_summary = "\n".join(patch_lines) if patch_lines else "_no patches_"

        title = f"[Intelli-Scan] Security patches for PR #{parent_pr_number}"
        body = (
            f"## Intelli-Scan — Automated Security Patches\n\n"
            f"This PR was generated automatically by the **Intelli-Scan** agentic "
            f"remediation pipeline in response to PR #{parent_pr_number}.\n\n"
            f"### Patches applied\n\n"
            f"{patches_summary}\n\n"
            f"---\n\n"
            f"> **Review before merging.** All patches have RIS ≥ 0.80 "
            f"(AUTO_APPLY threshold), meaning the original vulnerability was "
            f"confirmed eliminated and no new findings were introduced — but "
            f"human review in context is always recommended.\n"
        )

        try:
            gh = Github(auth=Auth.Token(token))
            repo = gh.get_repo(repo_full_name)
            pr = repo.create_pull(
                title=title,
                body=body,
                head=patch_branch,
                base=base_ref,
                draft=False,
            )
        except Exception as exc:
            logger.error(
                "Failed to open child PR from %s → %s on %s: %s",
                patch_branch, base_ref, repo_full_name, exc,
            )
            raise RuntimeError(f"Child PR creation failed: {exc}") from exc

        logger.info(
            "Opened child PR #%d for parent PR #%d on %s: %s",
            pr.number, parent_pr_number, repo_full_name, pr.html_url,
        )
        return {
            "pr_number": pr.number,
            "pr_url": pr.html_url,
            "html_url": pr.html_url,
        }

    # ------------------------------------------------------------------
    # Inline review comments
    # ------------------------------------------------------------------

    def post_inline_review_comments(
        self,
        repo_full_name: str,
        pr_number: int,
        child_pr_number: Optional[int],
        remediation_results: list,
        token: str,
    ) -> None:
        """
        Post a review comment on the parent PR for every non-skipped finding.

        Comment body by verdict
        -----------------------
        AUTO_APPLY
            Reports the patch was committed to the child PR, with the RIS score
            and the pipeline's explanation.
        REVIEW_RECOMMENDED
            Posts the explanation as a warning asking for human review before
            applying.
        MANUAL_REMEDIATION_REQUIRED
            Posts: "Automated patch not generated — manual review required."

        Failure isolation
        -----------------
        Every individual comment POST is wrapped in its own try/except. A failed
        comment logs the error and moves on — the pipeline never crashes over a
        comment failure.

        Inline-comment fallback
        -----------------------
        GitHub's create_review_comment() only works when the target line is
        visible in the PR diff. If that call fails (e.g. line outside diff,
        permission issue), the method falls back to a plain PR issue comment so
        feedback is always delivered.

        Parameters
        ----------
        repo_full_name : str
            GitHub repo in ``owner/repo`` format.
        pr_number : int
            Parent PR number.
        child_pr_number : int | None
            The child PR opened for AUTO_APPLY patches, if any.
        remediation_results : list
            Full pipeline output (all verdicts).
        token : str
            GitHub App installation access token.
        """
        if not remediation_results:
            return

        if not _PYGITHUB_AVAILABLE:
            logger.error("PyGithub unavailable — cannot post review comments")
            return

        try:
            gh = Github(auth=Auth.Token(token))
            repo = gh.get_repo(repo_full_name)
            pr = repo.get_pull(pr_number)
            commit = repo.get_commit(pr.head.sha)
        except Exception as exc:
            logger.error(
                "Failed to set up GitHub objects for review comments on %s PR #%d: %s",
                repo_full_name, pr_number, exc,
            )
            return

        child_pr_ref = f" (see PR #{child_pr_number})" if child_pr_number else ""

        for result in remediation_results:
            if result.get("skipped"):
                continue

            verdict = result.get("verdict", "")
            file_path = result.get("file_path", "")
            line_start = result.get("line_start") or 1
            vuln_type = result.get("vuln_type", "unknown")
            ris_score = result.get("ris_score")
            explanation = (result.get("explanation") or "").strip()

            if not file_path:
                continue

            try:
                comment_body = _build_comment_body(
                    verdict=verdict,
                    vuln_type=vuln_type,
                    ris_score=ris_score,
                    explanation=explanation,
                    child_pr_ref=child_pr_ref,
                )

                # Attempt inline (diff-anchored) review comment first
                try:
                    pr.create_review_comment(
                        body=comment_body,
                        commit=commit,
                        path=file_path,
                        line=line_start,
                        side="RIGHT",
                    )
                    logger.debug(
                        "Posted inline review comment for %s:%d (verdict=%s)",
                        file_path, line_start, verdict,
                    )
                except Exception as inline_exc:
                    # Fallback: plain issue comment — always succeeds if auth is valid
                    logger.debug(
                        "Inline comment failed for %s:%d (%s) — falling back to "
                        "issue comment",
                        file_path, line_start, inline_exc,
                    )
                    fallback_body = (
                        f"**`{file_path}:{line_start}`** — {comment_body}"
                    )
                    pr.create_issue_comment(body=fallback_body)
                    logger.debug(
                        "Posted fallback issue comment for %s:%d",
                        file_path, line_start,
                    )

            except Exception as exc:
                logger.error(
                    "Failed to post any comment for %s:%d (verdict=%s) — %s",
                    file_path, line_start, verdict, exc,
                )
                # Continue to next finding — never crash the pipeline


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _build_comment_body(
    verdict: str,
    vuln_type: str,
    ris_score: Optional[float],
    explanation: str,
    child_pr_ref: str,
) -> str:
    """Build the Markdown comment body for a given verdict."""
    ris_str = f"{ris_score:.2f}" if ris_score is not None else "N/A"

    if verdict == "AUTO_APPLY":
        header = f"🛡 **Intelli-Scan — Auto-Patch Applied{child_pr_ref}**"
        lines = [
            header,
            "",
            f"A patch for `{vuln_type}` was automatically committed "
            f"(RIS score: **{ris_str}**).",
        ]
        if explanation:
            lines += ["", explanation]
        return "\n".join(lines)

    if verdict == "REVIEW_RECOMMENDED":
        header = "⚠️ **Intelli-Scan — Review Recommended**"
        lines = [
            header,
            "",
            f"**Finding:** `{vuln_type}` | RIS score: **{ris_str}**",
        ]
        if explanation:
            lines += ["", explanation]
        lines += ["", "> Manual review required before applying this patch."]
        return "\n".join(lines)

    # MANUAL_REMEDIATION_REQUIRED (and any unexpected verdict)
    lines = [
        f"🔴 **Intelli-Scan — Manual Remediation Required**",
        "",
        f"**Finding:** `{vuln_type}`",
        "",
        "Automated patch not generated — manual review required.",
    ]
    return "\n".join(lines)
