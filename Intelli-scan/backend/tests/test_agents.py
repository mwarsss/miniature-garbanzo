"""
Tests for agents/remediation_agent.py and agents/patch_validator.py.

All tests are pure-Python (no network, no Semgrep/Bandit binaries required)
because every external call is mocked at the subprocess level.
"""
import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# RemediationAgent — unit tests
# ─────────────────────────────────────────────────────────────────────────────

from agents.remediation_agent import RemediationAgent, run_remediation_pipeline


# Shared minimal finding fixture
@pytest.fixture
def base_finding():
    return {
        "id": "python.lang.security.sqli",
        "file_path": "src/db.py",
        "vuln_type": "sql-injection",
        "severity": "HIGH",
        "message": "SQL injection via string formatting",
        "line_start": 42,
        "line_end": 42,
        "raw_code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
    }


class TestTriage:
    def test_high_sqli_gets_high_priority(self, base_finding):
        agent = RemediationAgent()
        result = agent.triage(base_finding)
        assert result["priority_score"] >= 60
        assert result["skip"] is False

    def test_low_severity_skip_list_gets_skipped(self):
        agent = RemediationAgent()
        finding = {
            "id": "generic-print-statement",
            "file_path": "app.py",
            "vuln_type": "use-of-print",
            "severity": "LOW",
            "message": "print() used",
            "line_start": 1,
            "line_end": 1,
        }
        result = agent.triage(finding)
        assert result["skip"] is True

    def test_critical_severity_maxes_base(self):
        agent = RemediationAgent()
        finding = {
            "id": "test",
            "file_path": "x.py",
            "vuln_type": "command-injection",
            "severity": "CRITICAL",
            "message": "cmd injection",
            "line_start": 1,
            "line_end": 1,
        }
        result = agent.triage(finding)
        assert result["priority_score"] == 100

    def test_unknown_severity_defaults_to_low_base(self):
        agent = RemediationAgent()
        finding = {
            "id": "x",
            "file_path": "x.py",
            "vuln_type": "obscure-vuln",
            "severity": "UNKNOWN",
            "message": "some issue",
            "line_start": 1,
            "line_end": 1,
        }
        result = agent.triage(finding)
        # Falls back to LOW base (15); no modifier for unknown vuln
        assert result["priority_score"] == 15
        assert result["skip"] is False


class TestGatherContext:
    def test_missing_file_returns_degraded(self, base_finding, tmp_path):
        agent = RemediationAgent()
        result = agent.gather_context(base_finding, str(tmp_path))
        # File doesn't exist inside tmp_path — degraded result
        assert result["function_name"] is None
        assert isinstance(result["imports"], list)

    def test_existing_file_is_read(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        content = "import os\ndef vulnerable(user_id):\n    cursor.execute(f'SELECT * FROM users WHERE id={user_id}')\n"
        (src / "db.py").write_text(content)
        finding = {
            "id": "x", "file_path": "src/db.py", "vuln_type": "sqli",
            "severity": "HIGH", "message": "", "line_start": 2, "line_end": 3,
            "raw_code_snippet": "",
        }
        agent = RemediationAgent()
        result = agent.gather_context(finding, str(tmp_path))
        assert "import os" in result["full_file_content"]
        assert "vulnerable" in result["context_window"]

    def test_context_window_contains_target_lines(self, tmp_path):
        src = tmp_path / "src"
        src.mkdir()
        lines = [f"line_{i}\n" for i in range(60)]
        lines[41] = "VULNERABLE_LINE\n"
        (src / "db.py").write_text("".join(lines))
        finding = {
            "id": "x",
            "file_path": "src/db.py",
            "vuln_type": "sqli",
            "severity": "HIGH",
            "message": "",
            "line_start": 42,
            "line_end": 42,
            "raw_code_snippet": "",
        }
        agent = RemediationAgent()
        result = agent.gather_context(finding, str(tmp_path))
        assert "VULNERABLE_LINE" in result["context_window"]


class TestGeneratePatch:
    def test_no_model_returns_degraded(self, base_finding):
        agent = RemediationAgent(gemini_model=None)
        ctx = {"full_file_content": "", "function_name": None, "imports": [], "context_window": ""}
        result = agent.generate_patch(base_finding, ctx)
        assert result["patched_code"] is None
        assert result["confidence"] == 0.0

    def test_model_json_response_is_parsed(self, base_finding):
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = json.dumps({
            "patched_code": "cursor.execute(q, (val,))",
            "explanation": "Use parameterized query.",
            "confidence": 0.9,
        })
        agent = RemediationAgent(gemini_model=mock_model)
        ctx = {"full_file_content": "x", "function_name": "vuln", "imports": [], "context_window": "x"}
        result = agent.generate_patch(base_finding, ctx)
        assert result["patched_code"] == "cursor.execute(q, (val,))"
        assert result["confidence"] == 0.9

    def test_fenced_json_response_is_stripped(self, base_finding):
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = (
            "```json\n"
            + json.dumps({"patched_code": "fixed", "explanation": "ok", "confidence": 0.7})
            + "\n```"
        )
        agent = RemediationAgent(gemini_model=mock_model)
        ctx = {"full_file_content": "", "function_name": None, "imports": [], "context_window": ""}
        result = agent.generate_patch(base_finding, ctx)
        assert result["patched_code"] == "fixed"

    def test_invalid_json_returns_degraded(self, base_finding):
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = "not json at all"
        agent = RemediationAgent(gemini_model=mock_model)
        ctx = {"full_file_content": "", "function_name": None, "imports": [], "context_window": ""}
        result = agent.generate_patch(base_finding, ctx)
        assert result["confidence"] == 0.1  # degraded JSON parse path

    def test_confidence_is_clamped(self, base_finding):
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = json.dumps({
            "patched_code": "x",
            "explanation": "y",
            "confidence": 99.0,  # way out of range
        })
        agent = RemediationAgent(gemini_model=mock_model)
        ctx = {"full_file_content": "", "function_name": None, "imports": [], "context_window": ""}
        result = agent.generate_patch(base_finding, ctx)
        assert result["confidence"] == 1.0

    def test_file_content_is_truncated_at_8000_chars(self, base_finding):
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = json.dumps({
            "patched_code": "x", "explanation": "y", "confidence": 0.5
        })
        agent = RemediationAgent(gemini_model=mock_model)
        big_content = "x" * 20_000
        ctx = {"full_file_content": big_content, "function_name": None, "imports": [], "context_window": ""}
        agent.generate_patch(base_finding, ctx)
        prompt_sent = mock_model.generate_content.call_args[0][0]
        # Truncated snippet should appear in the prompt
        assert "(file truncated" in prompt_sent


class TestValidatePatch:
    def test_no_patched_code_fails_immediately(self, base_finding):
        agent = RemediationAgent()
        result = agent.validate_patch(base_finding, {"patched_code": None, "confidence": 0.9}, "/tmp")
        assert result["validation_passed"] is False
        assert result["syntax_valid"] is False

    def test_valid_python_passes_syntax(self, base_finding):
        good_code = "def foo():\n    return 42\n"
        with patch.object(RemediationAgent, '_run_semgrep_validation', return_value=(True, [])):
            agent = RemediationAgent()
            result = agent.validate_patch(base_finding, {"patched_code": good_code, "confidence": 0.9}, "/tmp")
        assert result["syntax_valid"] is True
        assert result["validation_passed"] is True

    def test_syntax_error_fails_validation(self, base_finding):
        bad_code = "def broken(\n    return 1\n"
        with patch.object(RemediationAgent, '_run_semgrep_validation', return_value=(True, [])):
            agent = RemediationAgent()
            result = agent.validate_patch(base_finding, {"patched_code": bad_code, "confidence": 0.9}, "/tmp")
        assert result["syntax_valid"] is False
        assert result["validation_passed"] is False

    def test_semgrep_not_found_degrades_gracefully(self, base_finding):
        good_code = "x = 1\n"
        finding = {**base_finding, "file_path": "src/db.py"}
        with patch('subprocess.run', side_effect=FileNotFoundError):
            agent = RemediationAgent(semgrep_path="nonexistent-semgrep")
            result = agent.validate_patch(finding, {"patched_code": good_code, "confidence": 0.9}, "/tmp")
        assert result["vuln_eliminated"] is False

    def test_non_python_file_skips_syntax_check(self):
        agent = RemediationAgent()
        finding = {
            "id": "x",
            "file_path": "main.go",
            "vuln_type": "sqli",
            "severity": "HIGH",
            "message": "",
            "line_start": 1,
            "line_end": 1,
        }
        with patch.object(RemediationAgent, '_run_semgrep_validation', return_value=(True, [])):
            result = agent.validate_patch(finding, {"patched_code": "package main", "confidence": 0.8}, "/tmp")
        assert result["syntax_valid"] is True


class TestScoreRemediation:
    def test_perfect_patch_scores_auto_apply(self):
        agent = RemediationAgent()
        patch = {"confidence": 1.0}
        validation = {"vuln_eliminated": True, "syntax_valid": True, "new_findings": []}
        result = agent.score_remediation(patch, validation)
        assert result["ris_score"] == 1.0
        assert result["verdict"] == "AUTO_APPLY"

    def test_failed_patch_scores_manual_required(self):
        agent = RemediationAgent()
        patch = {"confidence": 0.0}
        validation = {"vuln_eliminated": False, "syntax_valid": False, "new_findings": ["x", "y", "z"]}
        result = agent.score_remediation(patch, validation)
        assert result["ris_score"] == 0.0
        assert result["verdict"] == "MANUAL_REMEDIATION_REQUIRED"

    def test_review_recommended_threshold(self):
        agent = RemediationAgent()
        patch = {"confidence": 0.5}
        validation = {"vuln_eliminated": False, "syntax_valid": True, "new_findings": []}
        result = agent.score_remediation(patch, validation)
        # 0.5*0 + 0.3*0.5 + 0.2*1.0 - 0.1*0 = 0.35 → MANUAL
        # border is at 0.5; this is below
        assert result["verdict"] == "MANUAL_REMEDIATION_REQUIRED"

    def test_ris_is_clamped_to_zero(self):
        agent = RemediationAgent()
        patch = {"confidence": 0.0}
        validation = {"vuln_eliminated": False, "syntax_valid": False, "new_findings": ["a"] * 20}
        result = agent.score_remediation(patch, validation)
        assert result["ris_score"] == 0.0


class TestRunRemediationPipeline:
    def test_empty_findings_returns_empty_list(self):
        results = run_remediation_pipeline({"findings": [], "repo_local_path": ""})
        assert results == []

    def test_skipped_finding_has_skipped_true(self):
        findings = [{
            "id": "use-of-print",
            "file_path": "x.py",
            "vuln_type": "use-of-print",
            "severity": "LOW",
            "message": "print used",
            "line_start": 1,
            "line_end": 1,
        }]
        results = run_remediation_pipeline({"findings": findings, "repo_local_path": ""})
        assert len(results) == 1
        assert results[0]["skipped"] is True
        assert results[0]["verdict"] == "SKIPPED"
        assert results[0]["rigorous_ris"] is False

    def test_full_path_result_has_all_keys(self):
        """Ensure every expected key is present in the result dict."""
        mock_model = MagicMock()
        mock_model.generate_content.return_value.text = json.dumps({
            "patched_code": "x = 1",
            "explanation": "fixed",
            "confidence": 0.8,
        })
        finding = {
            "id": "python.lang.security.sqli",
            "file_path": "src/db.py",
            "vuln_type": "sql-injection",
            "severity": "HIGH",
            "message": "sqli",
            "line_start": 1,
            "line_end": 1,
        }
        with patch('subprocess.run', side_effect=FileNotFoundError):
            results = run_remediation_pipeline(
                {"findings": [finding], "repo_local_path": ""},
                gemini_model=mock_model,
            )
        assert len(results) == 1
        r = results[0]
        expected_keys = [
            "finding_id", "file_path", "vuln_type", "priority_score",
            "skipped", "patched_code", "explanation", "ris_score", "verdict",
            "new_findings_introduced", "validation_passed", "diff_summary",
            "dual_scan_result", "ris_breakdown", "rigorous_ris",
        ]
        for key in expected_keys:
            assert key in r, f"Missing key: {key}"

    def test_no_model_returns_manual_required(self):
        finding = {
            "id": "python.lang.security.sqli",
            "file_path": "src/db.py",
            "vuln_type": "sql-injection",
            "severity": "HIGH",
            "message": "sqli",
            "line_start": 1,
            "line_end": 1,
        }
        with patch('subprocess.run', side_effect=FileNotFoundError):
            results = run_remediation_pipeline(
                {"findings": [finding], "repo_local_path": ""},
                gemini_model=None,
            )
        assert results[0]["verdict"] == "MANUAL_REMEDIATION_REQUIRED"
        assert results[0]["ris_score"] == 0.0


# ─────────────────────────────────────────────────────────────────────────────
# SemanticDiffEngine — unit tests
# ─────────────────────────────────────────────────────────────────────────────

from agents.patch_validator import SemanticDiffEngine, DualToolValidator, compute_ris


ORIGINAL_PY = """\
import os

def vulnerable(user_id):
    query = f"SELECT * FROM users WHERE id={user_id}"
    cursor.execute(query)
"""

PATCHED_PY = """\
import os

def vulnerable(user_id):
    query = "SELECT * FROM users WHERE id=%s"
    cursor.execute(query, (user_id,))
"""


class TestSemanticDiffEngine:
    def test_basic_diff_line_counts(self):
        engine = SemanticDiffEngine()
        result = engine.compute_diff(ORIGINAL_PY, PATCHED_PY, "src/db.py")
        summary = result["diff_summary"]
        assert summary["lines_added"] >= 1
        assert summary["lines_removed"] >= 1
        assert summary["lines_changed_total"] == summary["lines_added"] + summary["lines_removed"]

    def test_identical_files_produce_zero_diff(self):
        engine = SemanticDiffEngine()
        result = engine.compute_diff(ORIGINAL_PY, ORIGINAL_PY, "src/db.py")
        summary = result["diff_summary"]
        assert summary["lines_added"] == 0
        assert summary["lines_removed"] == 0

    def test_imports_added_detected(self):
        original = "x = 1\n"
        patched = "import hashlib\nx = 1\n"
        engine = SemanticDiffEngine()
        result = engine.compute_diff(original, patched, "x.py")
        summary = result["diff_summary"]
        assert "import hashlib" in summary["imports_added"]

    def test_imports_removed_detected(self):
        original = "import os\nx = 1\n"
        patched = "x = 1\n"
        engine = SemanticDiffEngine()
        result = engine.compute_diff(original, patched, "x.py")
        summary = result["diff_summary"]
        assert "import os" in summary["imports_removed"]

    def test_non_python_file_skips_ast(self):
        engine = SemanticDiffEngine()
        result = engine.compute_diff("x := 1\n", "x := 2\n", "main.go")
        summary = result["diff_summary"]
        # Non-Python: AST parse skipped, functions_modified empty, ast_parse_success False
        assert summary["ast_parse_success"] is False
        assert summary["functions_modified"] == []

    def test_result_has_all_expected_keys(self):
        engine = SemanticDiffEngine()
        result = engine.compute_diff(ORIGINAL_PY, PATCHED_PY, "src/db.py")
        summary = result["diff_summary"]
        for key in [
            "lines_added", "lines_removed", "lines_changed_total",
            "functions_modified", "imports_added", "imports_removed",
            "ast_parse_success", "raw_unified_diff",
        ]:
            assert key in summary, f"Missing key: {key}"

    def test_functions_modified_includes_changed_function(self):
        engine = SemanticDiffEngine()
        result = engine.compute_diff(ORIGINAL_PY, PATCHED_PY, "src/db.py")
        summary = result["diff_summary"]
        # `vulnerable` function changed in both versions
        assert "vulnerable" in summary["functions_modified"]


# ─────────────────────────────────────────────────────────────────────────────
# DualToolValidator — unit tests (subprocess mocked)
# ─────────────────────────────────────────────────────────────────────────────

SEMGREP_CLEAN_OUTPUT = json.dumps({"results": [], "errors": []})
SEMGREP_FINDING_OUTPUT = json.dumps({
    "results": [
        {
            "check_id": "python.lang.security.sqli",
            "path": "/tmp/x.py",
            "extra": {"message": "SQL injection detected"},
        }
    ],
    "errors": [],
})
BANDIT_CLEAN_OUTPUT = json.dumps({"results": [], "errors": []})
BANDIT_FINDING_OUTPUT = json.dumps({
    "results": [
        {
            "test_id": "B602",
            "test_name": "subprocess_popen_with_shell_equals_true",
            "issue_severity": "HIGH",
            "issue_confidence": "HIGH",
            "line_number": 5,
        }
    ],
    "errors": [],
})


def _make_proc(stdout: str, returncode: int = 0):
    mock = MagicMock()
    mock.stdout = stdout
    mock.returncode = returncode
    return mock


class TestDualToolValidator:
    def test_clean_patch_both_tools(self):
        finding = {
            "id": "python.lang.security.sqli",
            "file_path": "src/db.py",
            "vuln_type": "sqli",
            "severity": "HIGH",
            "message": "",
            "line_start": 1,
            "line_end": 1,
        }
        with patch('subprocess.run', return_value=_make_proc(SEMGREP_CLEAN_OUTPUT)):
            validator = DualToolValidator()
            result = validator.run_dual_scan(PATCHED_PY, finding, "/repo")
        assert result["original_vuln_eliminated"] is True
        assert result["new_semgrep_findings"] == []
        # Bandit also ran and returned clean
        assert result["bandit_skipped"] is False

    def test_vuln_still_present(self):
        finding = {
            "id": "python.lang.security.sqli",
            "file_path": "src/db.py",
            "vuln_type": "sqli",
            "severity": "HIGH",
            "message": "",
            "line_start": 1,
            "line_end": 1,
        }
        with patch('subprocess.run', return_value=_make_proc(SEMGREP_FINDING_OUTPUT)):
            validator = DualToolValidator()
            result = validator.run_dual_scan(ORIGINAL_PY, finding, "/repo")
        assert result["original_vuln_eliminated"] is False

    def test_semgrep_not_found_sets_tool_error(self):
        finding = {
            "id": "x", "file_path": "src/db.py", "vuln_type": "sqli",
            "severity": "HIGH", "message": "", "line_start": 1, "line_end": 1,
        }
        with patch('subprocess.run', side_effect=FileNotFoundError):
            validator = DualToolValidator(semgrep_path="nonexistent")
            result = validator.run_dual_scan("x = 1", finding, "/repo")
        assert result["semgrep_tool_error"] is True

    def test_non_python_file_skips_bandit(self):
        finding = {
            "id": "x", "file_path": "main.go", "vuln_type": "sqli",
            "severity": "HIGH", "message": "", "line_start": 1, "line_end": 1,
        }
        with patch('subprocess.run', return_value=_make_proc(SEMGREP_CLEAN_OUTPUT)):
            validator = DualToolValidator()
            result = validator.run_dual_scan("package main", finding, "/repo")
        assert result["bandit_skipped"] is True
        assert result["bandit_findings"] == []

    def test_bandit_exit_1_with_findings_not_tool_error(self):
        finding = {
            "id": "x", "file_path": "src/x.py", "vuln_type": "sqli",
            "severity": "HIGH", "message": "", "line_start": 1, "line_end": 1,
        }
        # semgrep clean, bandit returns code 1 (normal when issues found)
        def fake_run(cmd, **kwargs):
            if "semgrep" in cmd[0]:
                return _make_proc(SEMGREP_CLEAN_OUTPUT, 0)
            return _make_proc(BANDIT_FINDING_OUTPUT, 1)

        with patch('subprocess.run', side_effect=fake_run):
            validator = DualToolValidator()
            result = validator.run_dual_scan("import subprocess\nsubprocess.Popen(['ls'], shell=True)\n", finding, "/repo")
        assert result["bandit_tool_error"] is False
        assert len(result["bandit_findings"]) == 1


# ─────────────────────────────────────────────────────────────────────────────
# compute_ris — unit tests
# ─────────────────────────────────────────────────────────────────────────────

class TestComputeRIS:
    def _perfect_dual(self):
        return {
            "original_vuln_eliminated": True,
            "new_semgrep_findings": [],
            "new_bandit_findings": [],
            "bandit_skipped": False,
            "semgrep_tool_error": False,
        }

    def _failing_dual(self):
        return {
            "original_vuln_eliminated": False,
            "new_semgrep_findings": ["a", "b"],
            "new_bandit_findings": ["c"],
            "bandit_skipped": False,
            "semgrep_tool_error": False,
        }

    def _perfect_diff(self):
        return {
            "imports_added": [],
            "lines_changed_total": 2,
        }

    def test_perfect_patch_scores_1_0(self):
        result = compute_ris(
            diff_summary=self._perfect_diff(),
            dual_scan_result=self._perfect_dual(),
            patch_confidence=1.0,
            original_finding={},
        )
        assert result["ris_score"] == 1.0
        assert result["verdict"] == "AUTO_APPLY"

    def test_vuln_not_eliminated_below_auto_apply(self):
        dual = {**self._perfect_dual(), "original_vuln_eliminated": False}
        result = compute_ris(
            diff_summary=self._perfect_diff(),
            dual_scan_result=dual,
            patch_confidence=1.0,
            original_finding={},
        )
        # base = 0 + 0.25 + 0.20 + 0.15 = 0.60, penalty = 0
        assert result["ris_score"] == 0.60
        assert result["verdict"] == "REVIEW_RECOMMENDED"

    def test_new_findings_penalty_reduces_score(self):
        dual = {**self._perfect_dual(), "new_semgrep_findings": ["a", "b", "c"]}
        result = compute_ris(
            diff_summary=self._perfect_diff(),
            dual_scan_result=dual,
            patch_confidence=1.0,
            original_finding={},
        )
        # base = 1.0, penalty = 0.10*3 = 0.30
        assert result["ris_score"] == 0.70
        assert result["verdict"] == "REVIEW_RECOMMENDED"

    def test_imports_added_penalty(self):
        diff = {**self._perfect_diff(), "imports_added": ["import hashlib", "import hmac"]}
        result = compute_ris(
            diff_summary=diff,
            dual_scan_result=self._perfect_dual(),
            patch_confidence=1.0,
            original_finding={},
        )
        # base = 1.0, penalty = 0.05*2 = 0.10
        assert result["ris_score"] == 0.90

    def test_large_diff_penalty(self):
        diff = {**self._perfect_diff(), "lines_changed_total": 100}
        result = compute_ris(
            diff_summary=diff,
            dual_scan_result=self._perfect_dual(),
            patch_confidence=1.0,
            original_finding={},
        )
        # penalty += 0.02 * max(0, 100-50) = 0.02*50 = 1.0 → clamped to 0.0
        assert result["ris_score"] == 0.0
        assert result["verdict"] == "MANUAL_REMEDIATION_REQUIRED"

    def test_ris_never_goes_negative(self):
        result = compute_ris(
            diff_summary={"imports_added": ["a"] * 20, "lines_changed_total": 500},
            dual_scan_result=self._failing_dual(),
            patch_confidence=0.0,
            original_finding={},
        )
        assert result["ris_score"] == 0.0

    def test_ris_never_exceeds_one(self):
        result = compute_ris(
            diff_summary={"imports_added": [], "lines_changed_total": 0},
            dual_scan_result=self._perfect_dual(),
            patch_confidence=1.0,
            original_finding={},
        )
        assert result["ris_score"] <= 1.0

    def test_score_breakdown_keys_present(self):
        result = compute_ris(
            diff_summary=self._perfect_diff(),
            dual_scan_result=self._perfect_dual(),
            patch_confidence=0.8,
            original_finding={},
        )
        breakdown = result["score_breakdown"]
        expected = [
            "vuln_eliminated_contribution",
            "confidence_contribution",
            "tool_reliability_contribution",
            "clean_patch_contribution",
            "new_findings_penalty",
            "imports_penalty",
            "diff_size_penalty",
        ]
        for key in expected:
            assert key in breakdown, f"Missing breakdown key: {key}"

    def test_bandit_skipped_counts_as_clean(self):
        dual = {**self._perfect_dual(), "bandit_skipped": True, "new_bandit_findings": []}
        result = compute_ris(
            diff_summary=self._perfect_diff(),
            dual_scan_result=dual,
            patch_confidence=1.0,
            original_finding={},
        )
        # bandit_clean=True because skipped, so clean_patch_contrib = 0.15
        assert result["score_breakdown"]["clean_patch_contribution"] == 0.15

    def test_semgrep_tool_error_reduces_tool_reliability(self):
        dual = {**self._perfect_dual(), "semgrep_tool_error": True}
        result = compute_ris(
            diff_summary=self._perfect_diff(),
            dual_scan_result=dual,
            patch_confidence=1.0,
            original_finding={},
        )
        # tool_reliability_contrib = 0 when error
        assert result["score_breakdown"]["tool_reliability_contribution"] == 0.0

    def test_confidence_contrib_proportional(self):
        result = compute_ris(
            diff_summary=self._perfect_diff(),
            dual_scan_result=self._perfect_dual(),
            patch_confidence=0.5,
            original_finding={},
        )
        assert result["score_breakdown"]["confidence_contribution"] == round(0.25 * 0.5, 4)

    def test_base_score_and_penalty_sum_to_ris(self):
        result = compute_ris(
            diff_summary={"imports_added": ["import x"], "lines_changed_total": 60},
            dual_scan_result={**self._perfect_dual(), "new_semgrep_findings": ["a"]},
            patch_confidence=0.8,
            original_finding={},
        )
        expected = round(
            max(0.0, min(1.0, result["base_score"] - result["penalty_applied"])),
            4,
        )
        assert result["ris_score"] == expected
