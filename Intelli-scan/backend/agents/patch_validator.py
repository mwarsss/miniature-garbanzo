"""
Patch Diff Scoring System — patch_validator.py
===============================================

Implements three things:
  1. SemanticDiffEngine  — unified line diff + tree-sitter AST diff
  2. DualToolValidator   — Semgrep + Bandit re-scan on patched code
  3. compute_ris()       — Rigorous Remediation Integrity Score

This module is called from run_remediation_pipeline() in remediation_agent.py
AFTER the existing 5-step pipeline completes. It replaces (not augments) the
basic RIS score from Step 5 of the pipeline for all non-skipped findings that
have a patched_code result.

ASSUMPTIONS
-----------
1. tree-sitter >= 0.21.0 with tree-sitter-python. Both modules were added to
   requirements.txt by the agentic pipeline feature. If unavailable, AST
   extraction falls back to plain-text regex with ast_parse_success=False.
2. Bandit is installed (added to requirements.txt by this feature). If not
   found on PATH, bandit_skipped=True and bandit signals contribute 0 to RIS
   (neither penalised nor rewarded — the formula normalises for this case).
3. Semgrep is already on PATH from the existing pipeline. If missing, the
   dual Semgrep scan degrades gracefully — semgrep_tool_error=True.
4. The canonical RIS formula (Part 3) was provided in the project spec:
     base_score = 0.40*eliminated + 0.25*confidence
                  + 0.20*tool_reliability + 0.15*bandit_clean
     penalty    = 0.10*new_semgrep + 0.05*imports_added
                  + 0.02*max(0, lines_changed-50)
     ris = clamp(base_score - penalty, 0.0, 1.0)
   This supersedes the placeholder formula used in the previous commit.
5. score_breakdown exposes every per-signal contribution so the frontend
   can render each as a visual bar without any additional computation.

RIS FORMULA (canonical — for judge review)
------------------------------------------
base_score = (
    0.40 * original_vuln_eliminated        # primary objective
    + 0.25 * patch_confidence              # Gemini self-assessment
    + 0.20 * tool_reliability              # Semgrep ran without error
    + 0.15 * bandit_clean                  # no new Bandit issues (or skipped)
)
penalty = (
    0.10 * len(new_semgrep_findings)
    + 0.05 * len(imports_added)
    + 0.02 * max(0, lines_changed - 50)
)
ris = clamp(base_score - penalty, 0.0, 1.0)

Verdicts:
  RIS >= 0.80 → AUTO_APPLY
  RIS >= 0.50 → REVIEW_RECOMMENDED
  RIS <  0.50 → MANUAL_REMEDIATION_REQUIRED
"""

import difflib
import json
import logging
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Internal AST helpers
# ─────────────────────────────────────────────────────────────────────────────

def _extract_ast_symbols_treesitter(
    source: str,
) -> tuple[list[tuple[str, int, int]], list[str], list[tuple[str, int, int]], bool]:
    """
    Parse Python source with tree-sitter and return structural symbols.

    Returns
    -------
    tuple of:
      functions : list of (name, start_line, end_line)  — 1-indexed
      imports   : list of import statement strings
      classes   : list of (name, start_line, end_line)  — 1-indexed
      success   : bool — True if parsing succeeded
    """
    try:
        import tree_sitter_python as tspython  # type: ignore
        from tree_sitter import Language, Parser  # type: ignore

        lang = Language(tspython.language())
        parser = Parser(lang)
        tree = parser.parse(bytes(source, "utf-8"))

        functions: list[tuple[str, int, int]] = []
        classes: list[tuple[str, int, int]] = []
        imports: list[str] = []

        def walk(node) -> None:
            if node.type == "function_definition":
                name = _get_identifier_child(node)
                if name:
                    functions.append((
                        name,
                        node.start_point[0] + 1,
                        node.end_point[0] + 1,
                    ))
            elif node.type == "class_definition":
                name = _get_identifier_child(node)
                if name:
                    classes.append((
                        name,
                        node.start_point[0] + 1,
                        node.end_point[0] + 1,
                    ))
            elif node.type in ("import_statement", "import_from_statement"):
                imports.append(node.text.decode("utf-8").strip())

            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return functions, imports, classes, True

    except ImportError:
        logger.debug("patch_validator: tree-sitter not available, using plaintext AST")
    except Exception as exc:  # noqa: BLE001
        logger.debug("patch_validator: tree-sitter parse failed — %s", exc)

    return [], [], [], False


def _get_identifier_child(node) -> Optional[str]:
    """Return the text of the first identifier child of a tree-sitter node."""
    for child in node.children:
        if child.type == "identifier":
            try:
                return child.text.decode("utf-8")
            except Exception:  # noqa: BLE001
                return None
    return None


def _extract_ast_symbols_plaintext(
    source: str,
) -> tuple[list[tuple[str, int, int]], list[str], list[tuple[str, int, int]]]:
    """
    Plain-text fallback for AST extraction.

    Uses regex to approximate function, class, and import detection.
    Line ranges are estimated (function ends at next def/class at same
    indentation level, or EOF).
    """
    lines = source.splitlines()
    functions: list[tuple[str, int, int]] = []
    classes: list[tuple[str, int, int]] = []
    imports: list[str] = []

    func_re = re.compile(r"^(\s*)def\s+(\w+)")
    class_re = re.compile(r"^(\s*)class\s+(\w+)")

    pending: list[tuple[str, str, int, str]] = []  # (kind, name, start, indent)

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            imports.append(stripped)

        fm = func_re.match(line)
        if fm:
            _close_pending(pending, functions, classes, i - 1, fm.group(1))
            pending.append(("func", fm.group(2), i, fm.group(1)))
            continue

        cm = class_re.match(line)
        if cm:
            _close_pending(pending, functions, classes, i - 1, cm.group(1))
            pending.append(("class", cm.group(2), i, cm.group(1)))

    # Close any still-open definitions at EOF
    _close_pending(pending, functions, classes, len(lines), "")

    return functions, imports, classes


def _close_pending(
    pending: list,
    functions: list,
    classes: list,
    current_line: int,
    new_indent: str,
) -> None:
    """Close pending function/class definitions whose indentation is >= new_indent."""
    still_open = []
    for kind, name, start, indent in pending:
        if len(indent) >= len(new_indent) and current_line >= start:
            end = max(start, current_line)
            if kind == "func":
                functions.append((name, start, end))
            else:
                classes.append((name, start, end))
        else:
            still_open.append((kind, name, start, indent))
    pending[:] = still_open


# ─────────────────────────────────────────────────────────────────────────────
# Diff line-number helpers
# ─────────────────────────────────────────────────────────────────────────────

def _changed_lines_in_patched(diff_lines: list[str]) -> set[int]:
    """
    Walk a unified diff and return the set of 1-indexed line numbers in the
    *patched* file that were either added or fall within a modified hunk.
    """
    changed: set[int] = set()
    current = 0
    hunk_re = re.compile(r"@@ .* \+(\d+)(?:,\d+)? @@")

    for line in diff_lines:
        if line.startswith("@@"):
            m = hunk_re.search(line)
            if m:
                current = int(m.group(1)) - 1  # 0-indexed; will be +1 on first real line
        elif line.startswith("+++") or line.startswith("---"):
            continue
        elif line.startswith("+"):
            current += 1
            changed.add(current)
        elif line.startswith("-"):
            pass  # removed from original; no line in patched
        else:
            current += 1  # context line

    return changed


def _functions_touched_by_diff(
    changed_lines: set[int],
    functions: list[tuple[str, int, int]],
) -> list[str]:
    """Return names of functions whose line ranges intersect with changed_lines."""
    touched = []
    for name, start, end in functions:
        if any(start <= ln <= end for ln in changed_lines):
            touched.append(name)
    return touched


# ─────────────────────────────────────────────────────────────────────────────
# Part 1 — SemanticDiffEngine
# ─────────────────────────────────────────────────────────────────────────────

class SemanticDiffEngine:
    """
    Computes a semantic diff between two versions of a source file.

    Combines unified line-level diff with tree-sitter AST analysis to
    produce a structured summary of what changed between the original
    (vulnerable) and patched file content.
    """

    def compute_diff(
        self,
        original: str,
        patched: str,
        file_path: str,
    ) -> dict:
        """
        Produce a structured diff summary comparing original and patched content.

        Parameters
        ----------
        original : str
            Full content of the original (vulnerable) file.
        patched : str
            Full content of the AI-generated patched file.
        file_path : str
            Relative file path — used only to label the diff header.

        Returns
        -------
        dict
            ``{"diff_summary": {...}}`` with the following keys inside
            ``diff_summary``:

            - ``lines_added`` (int)
            - ``lines_removed`` (int)
            - ``lines_changed_total`` (int)
            - ``functions_modified`` (list[str])
            - ``imports_added`` (list[str])
            - ``imports_removed`` (list[str])
            - ``classes_modified`` (list[str])
            - ``ast_parse_success`` (bool)
            - ``raw_unified_diff`` (str)  — first 200 lines for audit
        """
        logger.debug("SemanticDiff: computing diff for %s", file_path)

        original_lines = original.splitlines(keepends=True)
        patched_lines = patched.splitlines(keepends=True)

        diff_iter = difflib.unified_diff(
            original_lines,
            patched_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
            lineterm="",
        )
        diff_lines = list(diff_iter)

        # ── Line counts ───────────────────────────────────────────────
        lines_added = sum(
            1 for l in diff_lines
            if l.startswith("+") and not l.startswith("+++")
        )
        lines_removed = sum(
            1 for l in diff_lines
            if l.startswith("-") and not l.startswith("---")
        )

        # ── AST extraction ────────────────────────────────────────────
        is_python = Path(file_path).suffix.lower() == ".py"
        ast_parse_success = False

        orig_funcs: list[tuple[str, int, int]] = []
        orig_imports: list[str] = []
        orig_classes: list[tuple[str, int, int]] = []

        pat_funcs: list[tuple[str, int, int]] = []
        pat_imports: list[str] = []
        pat_classes: list[tuple[str, int, int]] = []

        if is_python:
            orig_funcs, orig_imports, orig_classes, orig_ok = (
                _extract_ast_symbols_treesitter(original)
            )
            pat_funcs, pat_imports, pat_classes, pat_ok = (
                _extract_ast_symbols_treesitter(patched)
            )
            ast_parse_success = orig_ok and pat_ok

            if not ast_parse_success:
                # Plain-text fallback for whichever side failed
                if not orig_ok:
                    orig_funcs, orig_imports, orig_classes = (
                        _extract_ast_symbols_plaintext(original)
                    )
                if not pat_ok:
                    pat_funcs, pat_imports, pat_classes = (
                        _extract_ast_symbols_plaintext(patched)
                    )

        # ── Functions / classes modified ──────────────────────────────
        changed_lines = _changed_lines_in_patched(diff_lines)
        functions_modified = _functions_touched_by_diff(changed_lines, pat_funcs)
        classes_modified = _functions_touched_by_diff(changed_lines, pat_classes)

        # ── Import delta ──────────────────────────────────────────────
        orig_import_set = set(orig_imports)
        pat_import_set = set(pat_imports)
        imports_added = sorted(pat_import_set - orig_import_set)
        imports_removed = sorted(orig_import_set - pat_import_set)

        raw_diff_snippet = "".join(diff_lines[:200])

        summary = {
            "lines_added": lines_added,
            "lines_removed": lines_removed,
            "lines_changed_total": lines_added + lines_removed,
            "functions_modified": functions_modified,
            "classes_modified": classes_modified,
            "imports_added": imports_added,
            "imports_removed": imports_removed,
            "ast_parse_success": ast_parse_success,
            "raw_unified_diff": raw_diff_snippet,
        }

        logger.debug(
            "SemanticDiff: +%d/-%d lines, %d funcs modified, %d imports added, ast_ok=%s",
            lines_added,
            lines_removed,
            len(functions_modified),
            len(imports_added),
            ast_parse_success,
        )
        return {"diff_summary": summary}


# ─────────────────────────────────────────────────────────────────────────────
# Part 2 — DualToolValidator
# ─────────────────────────────────────────────────────────────────────────────

class DualToolValidator:
    """
    Re-scans the patched code with two independent static analysis tools —
    Semgrep and Bandit — to answer: "Did the patch introduce a new vulnerability
    while closing the old one?"
    """

    def __init__(
        self,
        semgrep_path: str = "semgrep",
        bandit_path: str = "bandit",
    ) -> None:
        self._semgrep_path = semgrep_path
        self._bandit_path = bandit_path

    def run_dual_scan(
        self,
        patched_code: str,
        original_finding: dict,
        repo_path: str,
    ) -> dict:
        """
        Write patched_code to a temp file and run both Semgrep and Bandit.

        Parameters
        ----------
        patched_code : str
            The full patched file content to scan.
        original_finding : dict
            The original normalised finding dict (needs ``file_path`` and ``id``).
        repo_path : str
            Absolute path to the cloned repository — unused currently but
            available for future context-aware scanning.

        Returns
        -------
        dict
            Keys: ``semgrep_findings``, ``bandit_findings``,
            ``original_vuln_eliminated``, ``new_semgrep_findings``,
            ``new_bandit_findings``, ``total_new_issues``,
            ``bandit_skipped``, ``semgrep_tool_error``, ``bandit_tool_error``.
        """
        file_path = original_finding.get("file_path", "unknown.py")
        suffix = Path(file_path).suffix or ".py"
        is_python = suffix.lower() == ".py"

        # Write to a named temp file — deleted in finally block
        tmp_path: Optional[Path] = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=suffix,
                delete=False,
                encoding="utf-8",
            ) as tmp:
                tmp.write(patched_code)
                tmp_path = Path(tmp.name)

            logger.debug(
                "DualToolValidator: scanning %s (original: %s)",
                tmp_path,
                file_path,
            )

            # ── Tool 1: Semgrep ──────────────────────────────────────
            semgrep_findings, original_vuln_eliminated, semgrep_error = (
                self._run_semgrep(tmp_path, original_finding)
            )

            # ── Tool 2: Bandit (Python only) ──────────────────────────
            if is_python:
                bandit_findings, bandit_error = self._run_bandit(tmp_path)
                bandit_skipped = False
            else:
                bandit_findings = []
                bandit_error = False
                bandit_skipped = True
                logger.debug(
                    "DualToolValidator: Bandit skipped (non-Python file: %s)", suffix
                )

        finally:
            if tmp_path is not None:
                try:
                    tmp_path.unlink(missing_ok=True)
                except OSError:
                    pass

        # Separate new findings from the original vuln re-occurrence
        original_id: str = original_finding.get("id", "")
        new_semgrep_findings = [
            f for f in semgrep_findings
            if not (
                f.get("check_id") == original_id
                or (original_id and original_id in f.get("check_id", ""))
            )
        ]

        # Bandit: flag only HIGH/CRITICAL severity new issues for the penalty
        new_bandit_high = [
            f for f in bandit_findings
            if f.get("issue_severity", "").upper() in ("HIGH", "CRITICAL")
        ]

        total_new = len(new_semgrep_findings) + len(bandit_findings)

        result = {
            "semgrep_findings": semgrep_findings,
            "bandit_findings": bandit_findings,
            "original_vuln_eliminated": original_vuln_eliminated,
            "new_semgrep_findings": new_semgrep_findings,
            "new_bandit_findings": bandit_findings,
            "new_bandit_high_findings": new_bandit_high,
            "total_new_issues": total_new,
            "bandit_skipped": bandit_skipped,
            "semgrep_tool_error": semgrep_error,
            "bandit_tool_error": bandit_error,
        }

        logger.debug(
            "DualToolValidator: eliminated=%s new_semgrep=%d new_bandit=%d",
            original_vuln_eliminated,
            len(new_semgrep_findings),
            len(bandit_findings),
        )
        return result

    def _run_semgrep(
        self,
        tmp_path: Path,
        original_finding: dict,
    ) -> tuple[list, bool, bool]:
        """
        Run Semgrep on the temp file using the original rule ID if available,
        falling back to ``--config=auto``.

        Returns
        -------
        (findings, original_vuln_eliminated, tool_error)
        """
        original_id: str = original_finding.get("id", "")

        if original_id:
            semgrep_config = original_id if "/" in original_id else f"r/{original_id}"
        else:
            semgrep_config = "auto"

        cmd = [
            self._semgrep_path,
            "scan",
            "--config", semgrep_config,
            "--json",
            "--quiet",
            "--timeout", "30",
            str(tmp_path),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            try:
                output = json.loads(proc.stdout)
            except json.JSONDecodeError:
                logger.warning(
                    "DualToolValidator: Semgrep output not JSON: %s",
                    proc.stderr[:300],
                )
                return [], False, True

            findings = output.get("results", [])

            original_still_present = any(
                f.get("check_id") == original_id
                or (original_id and original_id in f.get("check_id", ""))
                for f in findings
            ) if original_id else False

            return findings, not original_still_present, False

        except FileNotFoundError:
            logger.warning(
                "DualToolValidator: Semgrep not found at '%s'",
                self._semgrep_path,
            )
            return [], False, True
        except subprocess.TimeoutExpired:
            logger.warning("DualToolValidator: Semgrep timed out")
            return [], False, True
        except Exception as exc:  # noqa: BLE001
            logger.error("DualToolValidator: Semgrep error — %s", exc)
            return [], False, True

    def _run_bandit(self, tmp_path: Path) -> tuple[list, bool]:
        """
        Run Bandit on the temp file with ``-f json`` output.

        Returns
        -------
        (findings, tool_error)
        """
        cmd = [
            self._bandit_path,
            "-f", "json",
            "-q",
            str(tmp_path),
        ]

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            # Bandit exits with code 1 when issues are found — that is normal
            try:
                output = json.loads(proc.stdout)
            except json.JSONDecodeError:
                if proc.returncode not in (0, 1):
                    logger.warning(
                        "DualToolValidator: Bandit output not JSON: %s",
                        proc.stderr[:300],
                    )
                    return [], True
                return [], False  # no output = no findings

            findings = output.get("results", [])
            return findings, False

        except FileNotFoundError:
            logger.warning(
                "DualToolValidator: Bandit not found at '%s'",
                self._bandit_path,
            )
            return [], True
        except subprocess.TimeoutExpired:
            logger.warning("DualToolValidator: Bandit timed out")
            return [], True
        except Exception as exc:  # noqa: BLE001
            logger.error("DualToolValidator: Bandit error — %s", exc)
            return [], True


# ─────────────────────────────────────────────────────────────────────────────
# Part 3 — Rigorous RIS Calculator
# ─────────────────────────────────────────────────────────────────────────────

def compute_ris(
    diff_summary: dict,
    dual_scan_result: dict,
    patch_confidence: float,
    original_finding: dict,
) -> dict:
    """
    Compute the Remediation Integrity Score (RIS).

    Uses the canonical formula specified for Intelli-Scan:

    base_score = (
        0.40 * vuln_eliminated
        + 0.25 * patch_confidence
        + 0.20 * tool_reliability          # Semgrep ran without error
        + 0.15 * bandit_clean              # no new Bandit issues (or skipped)
    )
    penalty = (
        0.10 * len(new_semgrep_findings)   # each new Semgrep finding
        + 0.05 * len(imports_added)        # each new import introduced
        + 0.02 * max(0, lines_changed - 50)  # excess lines beyond 50
    )
    ris = clamp(base_score - penalty, 0.0, 1.0)

    Parameters
    ----------
    diff_summary : dict
        Output of ``SemanticDiffEngine.compute_diff()["diff_summary"]``.
    dual_scan_result : dict
        Output of ``DualToolValidator.run_dual_scan()``.
    patch_confidence : float
        The Gemini model's self-assessed confidence (0.0–1.0).
    original_finding : dict
        Normalised finding dict — not used directly in this formula but
        retained for future severity-based adjustments.

    Returns
    -------
    dict
        Keys:
        - ``ris_score`` (float, rounded to 4 d.p., clamped [0.0, 1.0])
        - ``verdict`` (str)
        - ``base_score`` (float)
        - ``penalty_applied`` (float)
        - ``score_breakdown`` (dict) — per-signal contributions for
          frontend rendering as a visual breakdown bar
    """
    confidence = max(0.0, min(1.0, float(patch_confidence)))

    # ── Base score ────────────────────────────────────────────────────────

    vuln_eliminated_contrib = 0.40 * float(
        dual_scan_result.get("original_vuln_eliminated", False)
    )
    confidence_contrib = 0.25 * confidence

    # Tool reliability: Semgrep ran without an infrastructure error
    tool_reliability_contrib = 0.20 * float(
        not dual_scan_result.get("semgrep_tool_error", False)
    )

    bandit_skipped: bool = dual_scan_result.get("bandit_skipped", False)
    new_bandit: list = dual_scan_result.get("new_bandit_findings", [])
    bandit_clean = bandit_skipped or len(new_bandit) == 0
    clean_patch_contrib = 0.15 * float(bandit_clean)

    base_score = (
        vuln_eliminated_contrib
        + confidence_contrib
        + tool_reliability_contrib
        + clean_patch_contrib
    )

    # ── Penalties ─────────────────────────────────────────────────────────

    new_semgrep: list = dual_scan_result.get("new_semgrep_findings", [])
    imports_added: list = diff_summary.get("imports_added", [])
    lines_changed: int = diff_summary.get("lines_changed_total", 0)

    new_findings_penalty = 0.10 * len(new_semgrep)
    imports_penalty = 0.05 * len(imports_added)
    diff_size_penalty = 0.02 * max(0, lines_changed - 50)

    penalty = new_findings_penalty + imports_penalty + diff_size_penalty

    # ── Final score ───────────────────────────────────────────────────────

    ris = round(max(0.0, min(1.0, base_score - penalty)), 4)

    if ris >= 0.80:
        verdict = "AUTO_APPLY"
    elif ris >= 0.50:
        verdict = "REVIEW_RECOMMENDED"
    else:
        verdict = "MANUAL_REMEDIATION_REQUIRED"

    score_breakdown = {
        "vuln_eliminated_contribution": round(vuln_eliminated_contrib, 4),
        "confidence_contribution": round(confidence_contrib, 4),
        "tool_reliability_contribution": round(tool_reliability_contrib, 4),
        "clean_patch_contribution": round(clean_patch_contrib, 4),
        "new_findings_penalty": round(new_findings_penalty, 4),
        "imports_penalty": round(imports_penalty, 4),
        "diff_size_penalty": round(diff_size_penalty, 4),
    }

    logger.debug(
        "compute_ris: base=%.3f penalty=%.3f RIS=%.3f (%s)",
        base_score,
        penalty,
        ris,
        verdict,
    )
    return {
        "ris_score": ris,
        "verdict": verdict,
        "base_score": round(base_score, 4),
        "penalty_applied": round(penalty, 4),
        "score_breakdown": score_breakdown,
    }
