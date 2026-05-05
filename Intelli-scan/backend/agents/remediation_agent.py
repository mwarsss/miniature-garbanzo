"""
Agentic Remediation Loop for Intelli-Scan
==========================================

This module replaces the one-shot Gemini prompting approach with a 5-step
sequential agent pipeline that triages, contextualises, patches, validates,
and scores each security finding individually.

ASSUMPTIONS
-----------
1. repo_local_path in scan_output is a valid, accessible path. If missing or
   the directory no longer exists (temp dirs are cleaned after scanning),
   the Context Agent falls back to using only raw_code_snippet from the finding.
2. tree-sitter >= 0.21.0 API is used. If the library is absent or parsing
   fails for any reason, the agent transparently falls back to plain-text
   slicing for context extraction — no crash.
3. The Gemini model instance must be passed to run_remediation_pipeline() as
   `gemini_model`. It must be a google.generativeai.GenerativeModel object
   with a synchronous generate_content() method. If None, all patch steps
   produce confidence=0.0 / patched_code=None (degraded mode).
4. Semgrep validation is best-effort. If `semgrep` is not on PATH, the step
   marks vuln_eliminated=False and surfaces a warning rather than raising.
5. Non-Python files skip py_compile; syntax_valid defaults to True so that
   patches for JS/TS/Go/etc. are not penalised for an unchecked syntax step.
6. The SKIP_LIST covers low-signal / informational vuln types where automated
   patching produces more noise than value (e.g., broad info-disclosure or
   generic style warnings). Operators should extend this list to match their
   risk appetite.
7. Semgrep re-validation uses the original finding's check_id as the rule
   selector. If the rule is a namespaced registry rule (contains slashes) it
   is passed verbatim; otherwise it is treated as a local rule tag.
8. Gemini responses are expected to be JSON (possibly fence-wrapped). If the
   model produces non-JSON output the step returns a degraded result rather
   than propagating an exception.
"""

import json
import logging
import py_compile
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Rigorous patch validation — imported lazily so the module is still usable
# if patch_validator has a transient import error (e.g. during testing).
try:
    from agents.patch_validator import SemanticDiffEngine, DualToolValidator, compute_ris as _compute_rigorous_ris
    _PATCH_VALIDATOR_AVAILABLE = True
except ImportError:
    try:
        from .patch_validator import SemanticDiffEngine, DualToolValidator, compute_ris as _compute_rigorous_ris
        _PATCH_VALIDATOR_AVAILABLE = True
    except ImportError:
        logger.warning("patch_validator not importable; rigorous RIS will be skipped")
        _PATCH_VALIDATOR_AVAILABLE = False

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SKIP_LIST: set[str] = {
    "generic-comment-todo",
    "generic-print-statement",
    "generic-empty-catch",
    "info-disclosure-generic",
    "logging-sensitive-data",
    "missing-docstring",
    "use-of-print",
    "broad-except",
}

# CVSS-like heuristic lookup table: (severity, vuln_type_prefix) -> base score
_SEVERITY_BASE: dict[str, int] = {
    "CRITICAL": 80,
    "HIGH": 60,
    "MEDIUM": 40,
    "LOW": 15,
}

_VULN_MODIFIER: dict[str, int] = {
    "sql-injection": 20,
    "command-injection": 20,
    "code-injection": 20,
    "xxe": 18,
    "ssrf": 18,
    "path-traversal": 15,
    "insecure-deserialization": 15,
    "hardcoded-secret": 12,
    "hardcoded-password": 12,
    "weak-crypto": 10,
    "xss": 10,
    "csrf": 10,
    "open-redirect": 8,
    "sensitive-data-exposure": 8,
    "insecure-tls": 7,
    "missing-auth": 10,
    "broken-access-control": 12,
    "directory-traversal": 15,
    "prototype-pollution": 10,
    "regex-injection": 6,
}

_GEMINI_MAX_FILE_CHARS = 8_000


# ---------------------------------------------------------------------------
# Helper: strip Gemini markdown fences from JSON responses
# ---------------------------------------------------------------------------

def _strip_fences(text: str) -> str:
    """Remove ```json / ``` markdown code fences if present."""
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


# ---------------------------------------------------------------------------
# RemediationAgent
# ---------------------------------------------------------------------------

class RemediationAgent:
    """
    Five-step sequential agent that processes a single security finding through
    triage → context gathering → patch generation → validation → scoring.
    """

    def __init__(
        self,
        gemini_model=None,
        semgrep_path: str = "semgrep",
    ) -> None:
        """
        Initialise the agent.

        Parameters
        ----------
        gemini_model:
            A pre-configured google.generativeai.GenerativeModel instance.
            If None, the patch step returns a degraded (no-op) result.
        semgrep_path:
            Path or command name for the Semgrep binary. Defaults to 'semgrep'.
        """
        self._model = gemini_model
        self._semgrep_path = semgrep_path

    # ------------------------------------------------------------------
    # Step 1 — Triage Agent
    # ------------------------------------------------------------------

    def triage(self, finding: dict) -> dict:
        """
        Score the finding for exploitability using CVSS-like heuristics and
        determine whether it should be skipped.

        Parameters
        ----------
        finding : dict
            A single finding from scanner.py output (normalised format).

        Returns
        -------
        dict
            The enriched finding with added keys:
            - ``priority_score`` (int 0–100)
            - ``skip`` (bool)
        """
        logger.debug("Triage: entering for finding id=%s", finding.get("id"))

        severity = finding.get("severity", "LOW").upper()
        vuln_type = finding.get("vuln_type", "").lower()

        base = _SEVERITY_BASE.get(severity, 15)

        # Find the best matching modifier by checking if any key is a prefix/substring
        modifier = 0
        for key, val in _VULN_MODIFIER.items():
            if key in vuln_type:
                modifier = max(modifier, val)

        priority_score = min(100, base + modifier)

        skip = severity == "LOW" and vuln_type in SKIP_LIST

        result = {
            **finding,
            "priority_score": priority_score,
            "skip": skip,
        }
        logger.debug(
            "Triage: id=%s priority=%d skip=%s",
            finding.get("id"),
            priority_score,
            skip,
        )
        return result

    # ------------------------------------------------------------------
    # Step 2 — Context Agent
    # ------------------------------------------------------------------

    def gather_context(self, finding: dict, repo_path: str) -> dict:
        """
        Read the affected source file and extract AST context with tree-sitter,
        falling back to plain-text slicing if parsing fails.

        Parameters
        ----------
        finding : dict
            Enriched finding dict (output of :meth:`triage`).
        repo_path : str
            Absolute path to the cloned repository on disk.

        Returns
        -------
        dict
            Keys: ``full_file_content``, ``function_name``, ``imports``,
            ``context_window``.
        """
        logger.debug("Context: entering for finding id=%s", finding.get("id"))

        file_path = Path(repo_path) / finding.get("file_path", "")
        line_start: int = finding.get("line_start", 1)
        line_end: int = finding.get("line_end", line_start)

        # Default degraded result used on any I/O / parse failure
        degraded: dict = {
            "full_file_content": finding.get("raw_code_snippet", ""),
            "function_name": None,
            "imports": [],
            "context_window": finding.get("raw_code_snippet", ""),
        }

        if not file_path.exists():
            logger.debug(
                "Context: file not found at %s, using snippet fallback", file_path
            )
            return degraded

        try:
            full_content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.error("Context: cannot read %s — %s", file_path, exc)
            return degraded

        lines = full_content.splitlines()
        ctx_start = max(0, line_start - 11)
        ctx_end = min(len(lines), line_end + 10)
        context_window = "\n".join(lines[ctx_start:ctx_end])

        function_name: Optional[str] = None
        imports: list[str] = []

        # Attempt tree-sitter AST parsing (Python files only)
        if file_path.suffix == ".py":
            function_name, imports = self._parse_ast_python(
                full_content, line_start, lines
            )

        result = {
            "full_file_content": full_content,
            "function_name": function_name,
            "imports": imports,
            "context_window": context_window,
        }
        logger.debug(
            "Context: id=%s function=%s imports_count=%d",
            finding.get("id"),
            function_name,
            len(imports),
        )
        return result

    def _parse_ast_python(
        self, source: str, target_line: int, lines: list[str]
    ) -> tuple[Optional[str], list[str]]:
        """
        Use tree-sitter to find the enclosing function/class name and all imports.

        Returns (function_name, imports_list). Falls back gracefully on error.
        """
        try:
            import tree_sitter_python as tspython  # type: ignore
            from tree_sitter import Language, Parser  # type: ignore

            lang = Language(tspython.language())
            parser = Parser(lang)
            tree = parser.parse(bytes(source, "utf-8"))

            # --- Extract imports ---
            import_lines: list[str] = []
            for raw_line in lines:
                stripped = raw_line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    import_lines.append(stripped)

            # --- Find enclosing function or class ---
            func_name: Optional[str] = self._find_enclosing_scope(
                tree.root_node, target_line
            )
            return func_name, import_lines

        except ImportError:
            logger.debug("tree-sitter not available; using plain-text fallback")
        except Exception as exc:  # noqa: BLE001
            logger.debug("AST parse failed (%s); using plain-text fallback", exc)

        # Plain-text fallback: grep for def/class above target line
        func_name = self._find_enclosing_scope_plaintext(lines, target_line)
        imports = [
            l.strip()
            for l in lines
            if l.strip().startswith("import ") or l.strip().startswith("from ")
        ]
        return func_name, imports

    @staticmethod
    def _find_enclosing_scope(root_node, target_line: int) -> Optional[str]:
        """
        Walk the tree-sitter AST and return the innermost function or class
        name whose body contains ``target_line`` (1-indexed).
        """
        best_name: Optional[str] = None
        best_start: int = -1

        def walk(node):
            nonlocal best_name, best_start
            if node.type in ("function_definition", "class_definition"):
                start_line = node.start_point[0] + 1  # tree-sitter is 0-indexed
                end_line = node.end_point[0] + 1
                if start_line <= target_line <= end_line:
                    if start_line > best_start:
                        # Get the identifier child node (name)
                        for child in node.children:
                            if child.type == "identifier":
                                best_name = child.text.decode("utf-8")
                                best_start = start_line
                                break
            for child in node.children:
                walk(child)

        walk(root_node)
        return best_name

    @staticmethod
    def _find_enclosing_scope_plaintext(lines: list[str], target_line: int) -> Optional[str]:
        """
        Scan backwards from target_line to find the nearest def/class header.
        """
        import re
        pattern = re.compile(r"^\s*(def|class)\s+(\w+)")
        for i in range(min(target_line - 1, len(lines) - 1), -1, -1):
            m = pattern.match(lines[i])
            if m:
                return m.group(2)
        return None

    # ------------------------------------------------------------------
    # Step 3 — Patch Agent
    # ------------------------------------------------------------------

    def generate_patch(self, finding: dict, context: dict) -> dict:
        """
        Build a structured prompt and call Gemini to produce a patch.

        Parameters
        ----------
        finding : dict
            Enriched finding dict.
        context : dict
            Output of :meth:`gather_context`.

        Returns
        -------
        dict
            Keys: ``patched_code``, ``explanation``, ``confidence``,
            ``raw_prompt``.
        """
        logger.debug("Patch: entering for finding id=%s", finding.get("id"))

        degraded = {
            "patched_code": None,
            "explanation": "Patch generation unavailable (AI model not configured).",
            "confidence": 0.0,
            "raw_prompt": "",
        }

        if self._model is None:
            logger.debug("Patch: no model configured, returning degraded result")
            return degraded

        file_content = context.get("full_file_content", "") or ""
        if len(file_content) > _GEMINI_MAX_FILE_CHARS:
            file_content = file_content[:_GEMINI_MAX_FILE_CHARS]
            file_content += "\n# ... (file truncated to 8000 chars) ..."

        function_ctx = (
            f"The vulnerability is inside function/class: `{context['function_name']}`."
            if context.get("function_name")
            else "The enclosing function/class could not be determined."
        )

        # SCA (dependency) findings get a specialised prompt — no line-level patch needed
        is_sca = finding.get("vuln_type") == "dependency_vulnerability"
        if is_sca:
            pkg = finding.get("package_name", finding.get("id", "unknown"))
            installed = finding.get("installed_version", "?")
            fixed = finding.get("fixed_version", "")
            cve_id = finding.get("cve_id", "")
            fix_instruction = (
                f"Upgrade `{pkg}` from `{installed}` to `{fixed}`."
                if fixed else
                f"No upstream fix is available for `{pkg}` {installed}. "
                "Suggest the safest mitigation (e.g. remove, replace, or pin with a comment)."
            )
            prompt = f"""You are a senior DevSecOps engineer fixing a vulnerable dependency.

## Vulnerability
- CVE / ID: {cve_id}
- Package: {pkg} (installed: {installed})
- Severity: {finding.get('severity', 'UNKNOWN')}
- Finding: {finding.get('message', '')}

## Dependency Manifest
File: {finding.get('file_path', 'dependency manifest')}
```
{file_content or '(file not available — provide a generic patch example)'}
```

## Task
{fix_instruction}

Respond with ONLY a JSON object (no markdown, no commentary):
{{
  "patched_code": "<the complete corrected manifest content, or a minimal diff-style snippet if the full file is unavailable>",
  "explanation": "<one paragraph: what the CVE is, why the package is dangerous, and what the fix does>",
  "confidence": <float 0.0–1.0>
}}
"""
        else:
            prompt = f"""You are a senior application security engineer tasked with fixing a specific \
security vulnerability in source code.

## Vulnerability Details
- Type: {finding.get('vuln_type', 'unknown')}
- Severity: {finding.get('severity', 'unknown')}
- File: {finding.get('file_path', 'unknown')}
- Lines: {finding.get('line_start', '?')}–{finding.get('line_end', '?')}
- Message: {finding.get('message', '')}
- {function_ctx}

## Relevant Imports
{chr(10).join(context.get('imports', [])) or 'None detected'}

## Context Window (surrounding code)
```
{context.get('context_window', '')}
```

## Full File Content
```
{file_content}
```

## Instructions
Fix ONLY the specific vulnerability described above.
Do not introduce new imports unless strictly necessary to implement the fix.
Do not refactor, rename, or reformat unrelated code.
Preserve all existing functionality and the original file structure.

Respond with ONLY a JSON object (no markdown, no commentary) with exactly these keys:
{{
  "patched_code": "<the complete corrected file content>",
  "explanation": "<one paragraph plain-English explanation of the fix>",
  "confidence": <float between 0.0 and 1.0 representing your self-assessed confidence>
}}
"""

        try:
            response = self._model.generate_content(prompt)
            raw_text = response.text
            cleaned = _strip_fences(raw_text)
            parsed = json.loads(cleaned)

            patched_code = str(parsed.get("patched_code", "") or "")
            explanation = str(parsed.get("explanation", "") or "")
            confidence = float(parsed.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            logger.debug(
                "Patch: id=%s confidence=%.2f patched_chars=%d",
                finding.get("id"),
                confidence,
                len(patched_code),
            )
            return {
                "patched_code": patched_code if patched_code else None,
                "explanation": explanation,
                "confidence": confidence,
                "raw_prompt": prompt,
            }

        except json.JSONDecodeError as exc:
            logger.error("Patch: JSON parse error for id=%s — %s", finding.get("id"), exc)
            return {**degraded, "raw_prompt": prompt, "confidence": 0.1}
        except Exception as exc:  # noqa: BLE001
            logger.error("Patch: Gemini API error for id=%s — %s", finding.get("id"), exc)
            return {**degraded, "raw_prompt": prompt}

    # ------------------------------------------------------------------
    # Step 4 — Validator Agent
    # ------------------------------------------------------------------

    def validate_patch(self, finding: dict, patch: dict, repo_path: str) -> dict:
        """
        Write the patched code to a temp file, check syntax, and re-run Semgrep
        to verify the original vulnerability is eliminated.

        Parameters
        ----------
        finding : dict
            Enriched finding dict.
        patch : dict
            Output of :meth:`generate_patch`.
        repo_path : str
            Absolute path to the cloned repository (used for Semgrep context).

        Returns
        -------
        dict
            Keys: ``syntax_valid``, ``vuln_eliminated``, ``new_findings``,
            ``validation_passed``.
        """
        logger.debug("Validate: entering for finding id=%s", finding.get("id"))

        patched_code = patch.get("patched_code")

        if not patched_code:
            logger.debug("Validate: no patched_code, skipping validation")
            return {
                "syntax_valid": False,
                "vuln_eliminated": False,
                "new_findings": [],
                "validation_passed": False,
            }

        file_path = finding.get("file_path", "unknown.py")
        suffix = Path(file_path).suffix or ".py"

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=suffix,
            delete=False,
            encoding="utf-8",
        ) as tmp:
            tmp.write(patched_code)
            tmp_path = Path(tmp.name)

        try:
            syntax_valid = self._check_syntax(tmp_path, suffix)
            vuln_eliminated, new_findings = self._run_semgrep_validation(
                tmp_path, finding
            )
        finally:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass

        validation_passed = syntax_valid and vuln_eliminated
        logger.debug(
            "Validate: id=%s syntax=%s eliminated=%s new_findings=%d passed=%s",
            finding.get("id"),
            syntax_valid,
            vuln_eliminated,
            len(new_findings),
            validation_passed,
        )
        return {
            "syntax_valid": syntax_valid,
            "vuln_eliminated": vuln_eliminated,
            "new_findings": new_findings,
            "validation_passed": validation_passed,
        }

    @staticmethod
    def _check_syntax(tmp_path: Path, suffix: str) -> bool:
        """Run py_compile for .py files; return True for other file types."""
        if suffix != ".py":
            return True
        try:
            py_compile.compile(str(tmp_path), doraise=True)
            return True
        except py_compile.PyCompileError as exc:
            logger.debug("Syntax error in patched file: %s", exc)
            return False

    def _run_semgrep_validation(
        self, tmp_path: Path, finding: dict
    ) -> tuple[bool, list]:
        """
        Run Semgrep on the temp file targeting the original rule.

        Returns (vuln_eliminated, new_findings_list).
        """
        check_id: str = finding.get("id", "")
        if not check_id:
            # Cannot validate without a rule ID; assume eliminated
            return True, []

        # Build the Semgrep --config argument from the rule ID.
        # Registry rules look like "python.lang.security.audit.something".
        # We pass them verbatim; semgrep handles the r/ prefix resolution
        # when connected but we use the auto config otherwise.
        semgrep_config = check_id if "/" in check_id else f"r/{check_id}"

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
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=45,
            )
            try:
                output = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.debug("Semgrep produced non-JSON output: %s", result.stderr[:200])
                # Cannot parse; conservatively say not eliminated
                return False, []

            findings = output.get("results", [])

            # Separate original vuln recurrences from brand-new issues
            original_still_present = any(
                f.get("check_id") == check_id or check_id in f.get("check_id", "")
                for f in findings
            )

            vuln_eliminated = not original_still_present
            new_findings = [
                f for f in findings
                if f.get("check_id") != check_id and check_id not in f.get("check_id", "")
            ]
            return vuln_eliminated, new_findings

        except FileNotFoundError:
            logger.warning(
                "Semgrep not found at '%s'; skipping re-validation", self._semgrep_path
            )
            # Degraded: cannot verify; assume the patch worked if confidence is high
            return False, []
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep validation timed out for %s", tmp_path)
            return False, []
        except Exception as exc:  # noqa: BLE001
            logger.error("Semgrep validation error: %s", exc)
            return False, []

    # ------------------------------------------------------------------
    # Step 5 — Confidence Scorer
    # ------------------------------------------------------------------

    def score_remediation(self, patch: dict, validation: dict) -> dict:
        """
        Compute the Remediation Integrity Score (RIS) and assign a verdict.

        RIS = 0.5 * vuln_eliminated
            + 0.3 * model_confidence
            + 0.2 * syntax_valid
            - 0.1 * len(new_findings)

        Clamped to [0.0, 1.0].

        Verdicts
        --------
        - RIS >= 0.8  → ``AUTO_APPLY``
        - RIS >= 0.5  → ``REVIEW_RECOMMENDED``
        - RIS <  0.5  → ``MANUAL_REMEDIATION_REQUIRED``

        Parameters
        ----------
        patch : dict
            Output of :meth:`generate_patch`.
        validation : dict
            Output of :meth:`validate_patch`.

        Returns
        -------
        dict
            Keys: ``ris_score`` (float), ``verdict`` (str).
        """
        logger.debug("Score: computing RIS")

        vuln_eliminated = float(validation.get("vuln_eliminated", False))
        syntax_valid = float(validation.get("syntax_valid", False))
        confidence = float(patch.get("confidence", 0.0))
        new_count = len(validation.get("new_findings", []))

        ris = (
            0.5 * vuln_eliminated
            + 0.3 * confidence
            + 0.2 * syntax_valid
            - 0.1 * new_count
        )
        ris = max(0.0, min(1.0, ris))

        if ris >= 0.8:
            verdict = "AUTO_APPLY"
        elif ris >= 0.5:
            verdict = "REVIEW_RECOMMENDED"
        else:
            verdict = "MANUAL_REMEDIATION_REQUIRED"

        logger.debug("Score: RIS=%.3f verdict=%s", ris, verdict)
        return {"ris_score": round(ris, 4), "verdict": verdict}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def run_remediation_pipeline(
    scan_output: dict,
    gemini_model=None,
    semgrep_path: str = "semgrep",
    bandit_path: str = "bandit",
) -> list[dict]:
    """
    Run the full 5-step agentic remediation pipeline over every finding in
    ``scan_output``.

    Parameters
    ----------
    scan_output : dict
        Normalised scanner output with keys ``findings`` (list) and
        ``repo_local_path`` (str).
    gemini_model :
        A pre-configured ``google.generativeai.GenerativeModel`` instance.
        Pass ``None`` to run in degraded mode (no AI patches).
    semgrep_path : str
        Path or command name for the Semgrep binary.

    Returns
    -------
    list[dict]
        One result dict per finding with the shape::

            {
                "finding_id": str,
                "file_path": str,
                "vuln_type": str,
                "priority_score": int,
                "skipped": bool,
                "patched_code": str | None,
                "explanation": str | None,
                "ris_score": float | None,
                "verdict": str,
                "new_findings_introduced": list,
                "validation_passed": bool | None,
            }
    """
    agent = RemediationAgent(gemini_model=gemini_model, semgrep_path=semgrep_path)
    repo_path: str = scan_output.get("repo_local_path", "")
    findings: list[dict] = scan_output.get("findings", [])
    results: list[dict] = []

    # Initialise enhanced validation components once (re-used across all findings)
    if _PATCH_VALIDATOR_AVAILABLE:
        _diff_engine = SemanticDiffEngine()
        _dual_validator = DualToolValidator(
            semgrep_path=semgrep_path,
            bandit_path=bandit_path,
        )
    else:
        _diff_engine = None
        _dual_validator = None

    logger.info(
        "Pipeline: starting remediation for %d finding(s), repo=%s",
        len(findings),
        repo_path,
    )

    for finding in findings:
        finding_id = finding.get("id", "unknown")
        file_path = finding.get("file_path", "")
        vuln_type = finding.get("vuln_type", "")

        # ---- Step 1: Triage ----
        logger.debug("Pipeline: [%s] Step 1 — triage", finding_id)
        triaged = agent.triage(finding)

        if triaged["skip"]:
            logger.info("Pipeline: [%s] skipped (LOW severity + SKIP_LIST)", finding_id)
            results.append(
                {
                    "finding_id": finding_id,
                    "file_path": file_path,
                    "vuln_type": vuln_type,
                    "priority_score": triaged["priority_score"],
                    "skipped": True,
                    "patched_code": None,
                    "explanation": "Skipped: LOW severity finding in skip list.",
                    "ris_score": None,
                    "verdict": "SKIPPED",
                    "new_findings_introduced": [],
                    "validation_passed": None,
                    "diff_summary": None,
                    "dual_scan_result": None,
                    "ris_breakdown": None,
                    "rigorous_ris": False,
                }
            )
            continue

        # ---- Step 2: Context ----
        logger.debug("Pipeline: [%s] Step 2 — gather_context", finding_id)
        context = agent.gather_context(triaged, repo_path)

        # ---- Step 3: Patch ----
        logger.debug("Pipeline: [%s] Step 3 — generate_patch", finding_id)
        patch = agent.generate_patch(triaged, context)

        # ---- Step 4: Validate ----
        logger.debug("Pipeline: [%s] Step 4 — validate_patch", finding_id)
        validation = agent.validate_patch(triaged, patch, repo_path)

        # Early exit: failed validation + low model confidence
        if not validation["validation_passed"] and patch["confidence"] < 0.4:
            logger.info(
                "Pipeline: [%s] early exit — validation failed & confidence=%.2f",
                finding_id,
                patch["confidence"],
            )
            results.append(
                {
                    "finding_id": finding_id,
                    "file_path": file_path,
                    "vuln_type": vuln_type,
                    "priority_score": triaged["priority_score"],
                    "skipped": False,
                    "patched_code": patch.get("patched_code"),
                    "explanation": patch.get("explanation"),
                    "ris_score": 0.0,
                    "verdict": "MANUAL_REMEDIATION_REQUIRED",
                    "new_findings_introduced": validation.get("new_findings", []),
                    "validation_passed": False,
                    "diff_summary": None,
                    "dual_scan_result": None,
                    "ris_breakdown": None,
                    "rigorous_ris": False,
                }
            )
            continue

        # ---- Step 5: Score (basic — preserved as basic_ris for comparison) ----
        logger.debug("Pipeline: [%s] Step 5 — score_remediation", finding_id)
        basic_score = agent.score_remediation(patch, validation)
        # Start with basic score; Step 6 will replace ris_score/verdict if it runs
        score = {
            "ris_score": basic_score["ris_score"],
            "verdict": basic_score["verdict"],
        }

        # ---- Step 6: Rigorous RIS (replaces Step 5 score) ----
        # Runs when patched_code exists regardless of whether validation_passed,
        # so judges see the diff/dual-scan analysis even on borderline patches.
        diff_summary_dict: Optional[dict] = None
        dual_scan_result_dict: Optional[dict] = None
        ris_breakdown: Optional[dict] = None
        rigorous_ris_ran = False

        if (
            _PATCH_VALIDATOR_AVAILABLE
            and _diff_engine is not None
            and _dual_validator is not None
            and (validation["validation_passed"] or patch.get("patched_code") is not None)
            and patch.get("patched_code")
        ):
            try:
                logger.debug("Pipeline: [%s] Step 6 — rigorous RIS", finding_id)
                patched_content: str = patch["patched_code"]

                # Prefer reading original file from disk for accuracy;
                # fall back to the context snapshot captured in Step 2.
                original_content = ""
                if repo_path and file_path:
                    orig_path = Path(repo_path) / file_path
                    if orig_path.exists():
                        try:
                            original_content = orig_path.read_text(
                                encoding="utf-8", errors="replace"
                            )
                        except OSError:
                            pass
                if not original_content:
                    original_content = context.get("full_file_content", "") or ""

                diff_out = _diff_engine.compute_diff(
                    original_content, patched_content, file_path
                )
                diff_summary_dict = diff_out.get("diff_summary")

                dual_scan_result_dict = _dual_validator.run_dual_scan(
                    patched_content, triaged, repo_path
                )

                rigorous = _compute_rigorous_ris(
                    diff_summary=diff_summary_dict or {},
                    dual_scan_result=dual_scan_result_dict,
                    patch_confidence=patch.get("confidence", 0.0),
                    original_finding=triaged,
                )
                # Replace Step 5 score with the rigorous one
                score = {
                    "ris_score": rigorous["ris_score"],
                    "verdict": rigorous["verdict"],
                }
                ris_breakdown = rigorous.get("score_breakdown")
                rigorous_ris_ran = True

            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Pipeline: [%s] rigorous RIS failed (%s) — keeping basic score",
                    finding_id,
                    exc,
                )

        results.append(
            {
                "finding_id": finding_id,
                "file_path": file_path,
                "vuln_type": vuln_type,
                "priority_score": triaged["priority_score"],
                "skipped": False,
                "patched_code": patch.get("patched_code"),
                "explanation": patch.get("explanation"),
                "ris_score": score["ris_score"],
                "verdict": score["verdict"],
                "basic_ris": basic_score["ris_score"],       # Step 5 score preserved
                "new_findings_introduced": validation.get("new_findings", []),
                "validation_passed": validation["validation_passed"],
                "diff_summary": diff_summary_dict,
                "dual_scan_result": dual_scan_result_dict,
                "ris_breakdown": ris_breakdown,
                "rigorous_ris": rigorous_ris_ran,
            }
        )

        logger.info(
            "Pipeline: [%s] done — verdict=%s RIS=%.3f",
            finding_id,
            score["verdict"],
            score["ris_score"],
        )

    logger.info(
        "Pipeline: completed %d finding(s) processed", len(results)
    )
    return results
