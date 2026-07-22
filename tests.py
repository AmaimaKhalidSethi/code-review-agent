"""
Tests for the Code Review Agent -- Project 2-I-B.

Coverage:
  - Pydantic model validation (correctness + intentional failure cases)
  - Risk score computation and severity ordering
  - pylint subprocess wrapper (happy path + graceful-degradation paths)
  - Agent prompt construction (not the LLM's output -- that needs an API key)

Run: python -m pytest tests.py -v
"""
from __future__ import annotations

import json
import shutil
import subprocess
import textwrap
import unittest
from unittest.mock import MagicMock, patch

from pydantic import ValidationError

from models import (
    SEVERITY_ORDER,
    CodeFinding,
    CodeReviewReport,
    PylintFinding,
    PylintResult,
    ReviewPass,
)
from agent import run_llm_review, run_pylint, _build_pass_prompt


# ============================================================
# SECTION 1 — Pydantic model tests
# ============================================================

class TestCodeFinding(unittest.TestCase):

    def _valid_finding(self, **overrides) -> dict:
        base = dict(
            line_number=5,
            severity="MEDIUM",
            category="bug",
            title="Off-by-one in range",
            description="Loop uses len(x) + 1 causing an IndexError on the last iteration",
            suggested_fix="Change range(len(x) + 1) to range(len(x))",
        )
        base.update(overrides)
        return base

    def test_valid_medium_bug_finding(self):
        f = CodeFinding(**self._valid_finding())
        self.assertEqual(f.severity, "MEDIUM")
        self.assertIsNone(f.cwe_id)

    def test_high_security_finding_with_cwe_passes(self):
        f = CodeFinding(**self._valid_finding(
            severity="HIGH", category="security",
            title="Command injection via shell=True",
            description="subprocess.run called with untrusted user input and shell=True",
            suggested_fix="Pass arguments as a list, set shell=False",
            cwe_id="CWE-78",
        ))
        self.assertEqual(f.cwe_id, "CWE-78")

    def test_critical_security_finding_without_cwe_raises(self):
        with self.assertRaises(ValidationError) as ctx:
            CodeFinding(**self._valid_finding(
                severity="CRITICAL", category="security",
                title="Hardcoded credential",
                description="API key committed directly in source file",
                suggested_fix="Move to environment variable",
                cwe_id=None,
            ))
        self.assertIn("cwe_id", str(ctx.exception))

    def test_high_security_finding_without_cwe_raises(self):
        with self.assertRaises(ValidationError):
            CodeFinding(**self._valid_finding(
                severity="HIGH", category="security",
                title="SQL injection",
                description="Query built via f-string with user-supplied input",
                suggested_fix="Use parameterized queries",
                cwe_id=None,
            ))

    def test_medium_security_finding_without_cwe_is_fine(self):
        # Only HIGH and CRITICAL security findings require a CWE -- MEDIUM is
        # accepted without one.
        f = CodeFinding(**self._valid_finding(
            severity="MEDIUM", category="security",
            title="Weak password hashing",
            description="MD5 used for password hashing -- not considered cryptographically secure",
            suggested_fix="Use bcrypt or argon2",
        ))
        self.assertIsNone(f.cwe_id)

    def test_line_number_must_be_positive(self):
        with self.assertRaises(ValidationError):
            CodeFinding(**self._valid_finding(line_number=0))

    def test_description_too_short_raises(self):
        with self.assertRaises(ValidationError):
            CodeFinding(**self._valid_finding(description="bad"))

    def test_extra_fields_forbidden(self):
        with self.assertRaises(ValidationError):
            CodeFinding(**self._valid_finding(unknown_field="oops"))


class TestCodeReviewReport(unittest.TestCase):

    def _make_report(self, findings_by_severity: list[str]) -> CodeReviewReport:
        passes = []
        for i, sev in enumerate(findings_by_severity):
            category = "security" if sev in ("HIGH", "CRITICAL") else "bug"
            cwe = "CWE-89" if category == "security" else None
            passes.append(ReviewPass(
                category=category,
                findings=[CodeFinding(
                    line_number=i + 1,
                    severity=sev,
                    category=category,
                    title=f"Finding {i + 1}",
                    description=f"This is a description long enough to pass validation for finding {i + 1}",
                    suggested_fix="Fix it",
                    cwe_id=cwe,
                )],
            ))
        return CodeReviewReport(filename="test.py", lines_reviewed=50, passes=passes)

    def test_severity_counts_correct(self):
        report = self._make_report(["CRITICAL", "HIGH", "HIGH", "LOW"])
        counts = report.severity_counts
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["LOW"], 1)
        self.assertEqual(counts["MEDIUM"], 0)

    def test_all_findings_sorted_worst_first(self):
        report = self._make_report(["LOW", "CRITICAL", "HIGH", "MEDIUM"])
        severities = [f.severity for f in report.all_findings]
        self.assertEqual(severities, ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_risk_score_clean_code_is_100(self):
        report = CodeReviewReport(
            filename="clean.py", lines_reviewed=10,
            passes=[ReviewPass(category="bug", findings=[])],
        )
        self.assertEqual(report.overall_risk_score, 100)

    def test_risk_score_dominated_by_critical(self):
        report = self._make_report(["CRITICAL"])
        # One CRITICAL (40 points) should pull the score well below 70
        self.assertLess(report.overall_risk_score, 70)

    def test_risk_score_many_lows_still_ok(self):
        # 5 LOW findings (3 points each = 15 total penalty) should still
        # leave a respectable score
        report = self._make_report(["LOW", "LOW", "LOW", "LOW", "LOW"])
        self.assertGreater(report.overall_risk_score, 70)

    def test_risk_score_floored_at_zero(self):
        # Many CRITICALs should floor at 0, not go negative
        report = self._make_report(["CRITICAL"] * 5)
        self.assertEqual(report.overall_risk_score, 0)


class TestSeverityOrder(unittest.TestCase):
    def test_critical_is_worst(self):
        self.assertEqual(SEVERITY_ORDER["CRITICAL"], 0)

    def test_low_is_best(self):
        self.assertEqual(SEVERITY_ORDER["LOW"], 3)

    def test_ordering_is_consistent(self):
        order = [SEVERITY_ORDER[s] for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]]
        self.assertEqual(order, sorted(order))


# ============================================================
# SECTION 2 — pylint wrapper tests
# ============================================================

class TestRunPylint(unittest.TestCase):

    BUGGY_CODE = textwrap.dedent('''\
        import os

        def add(a,b):
            return a+b

        password = "hardcoded123"
    ''')

    CLEAN_CODE = textwrap.dedent('''\
        """Clean module."""


        def add(a: int, b: int) -> int:
            """Add two numbers."""
            return a + b
    ''')

    def test_real_pylint_runs_on_buggy_code(self):
        if shutil.which("pylint") is None:
            self.skipTest("pylint not installed")
        result = run_pylint(self.BUGGY_CODE)
        self.assertTrue(result.ran_successfully)
        self.assertGreater(len(result.findings), 0)

    def test_real_pylint_clean_code_has_no_findings(self):
        if shutil.which("pylint") is None:
            self.skipTest("pylint not installed")
        result = run_pylint(self.CLEAN_CODE)
        self.assertTrue(result.ran_successfully)
        self.assertEqual(len(result.findings), 0)

    def test_graceful_degradation_when_pylint_missing(self):
        with patch("agent.shutil.which", return_value=None):
            result = run_pylint("x = 1")
        self.assertFalse(result.ran_successfully)
        self.assertIsNotNone(result.error_detail)
        self.assertIn("not installed", result.error_detail)

    def test_graceful_degradation_on_timeout(self):
        with patch("agent.shutil.which", return_value="/usr/bin/pylint"), \
             patch("agent.subprocess.run", side_effect=subprocess.TimeoutExpired("pylint", 20)):
            result = run_pylint("x = 1")
        self.assertFalse(result.ran_successfully)
        self.assertIn("timed out", result.error_detail)

    def test_graceful_degradation_when_pylint_cannot_be_executed(self):
        with patch("agent.shutil.which", return_value="/usr/bin/pylint"), \
             patch("agent.subprocess.run", side_effect=FileNotFoundError("pylint")):
            result = run_pylint("x = 1")
        self.assertFalse(result.ran_successfully)
        self.assertIn("could not be executed", result.error_detail)

    def test_graceful_degradation_on_malformed_json(self):
        mock_proc = MagicMock()
        mock_proc.stdout = "this is not json{"
        mock_proc.stderr = ""
        with patch("agent.shutil.which", return_value="/usr/bin/pylint"), \
             patch("agent.subprocess.run", return_value=mock_proc):
            result = run_pylint("x = 1")
        self.assertFalse(result.ran_successfully)
        self.assertIn("unexpected format", result.error_detail)

    def test_empty_output_with_stderr_is_failure(self):
        mock_proc = MagicMock()
        mock_proc.stdout = ""
        mock_proc.stderr = "some error from pylint"
        with patch("agent.shutil.which", return_value="/usr/bin/pylint"), \
             patch("agent.subprocess.run", return_value=mock_proc):
            result = run_pylint("x = 1")
        self.assertFalse(result.ran_successfully)

    def test_pylint_findings_are_validated_into_pydantic_objects(self):
        """Confirms PylintFinding.model_validate correctly parses pylint's
        actual JSON field names -- specifically the hyphenated 'message-id'
        field which maps to the `message_id` attribute via AliasChoices.
        """
        raw = [{"type": "convention", "line": 1, "column": 0,
                "symbol": "missing-module-docstring",
                "message": "Missing module docstring",
                "message-id": "C0114"}]
        mock_proc = MagicMock()
        mock_proc.stdout = json.dumps(raw)
        mock_proc.stderr = ""
        with patch("agent.shutil.which", return_value="/usr/bin/pylint"), \
             patch("agent.subprocess.run", return_value=mock_proc):
            result = run_pylint("x = 1")
        self.assertTrue(result.ran_successfully)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].symbol, "missing-module-docstring")
        self.assertEqual(result.findings[0].message_id, "C0114")


# ============================================================
# SECTION 3 — agent prompt construction (no API key needed)
# ============================================================

class TestRunLlmReview(unittest.TestCase):

    def test_structured_output_uses_json_mode(self):
        fake_llm = MagicMock()
        fake_structured = MagicMock()
        fake_structured.invoke.return_value = ReviewPass(category="bug", findings=[])
        fake_llm.with_structured_output.return_value = fake_structured

        with patch("agent.ChatGroq", return_value=fake_llm):
            run_llm_review("x = 1", "f.py", "test-key", ["bug"])

        fake_llm.with_structured_output.assert_called_once_with(ReviewPass, method="function_calling")


class TestBuildPassPrompt(unittest.TestCase):

    def test_bug_prompt_includes_code_and_filename(self):
        prompt = _build_pass_prompt("bug", "x = 1", "myfile.py")
        self.assertIn("myfile.py", prompt)
        self.assertIn("x = 1", prompt)

    def test_bug_prompt_excludes_security_scope(self):
        # The bug-pass prompt must explicitly exclude security/style/perf
        # so the model doesn't bleed topic across passes.
        prompt = _build_pass_prompt("bug", "x = 1", "f.py")
        self.assertIn("Do NOT report", prompt)

    def test_security_prompt_mentions_cwe(self):
        prompt = _build_pass_prompt("security", "x = 1", "f.py")
        self.assertIn("CWE", prompt)

    def test_style_prompt_discourages_critical_severity(self):
        prompt = _build_pass_prompt("style", "x = 1", "f.py")
        self.assertIn("CRITICAL", prompt)
        self.assertIn("MEDIUM", prompt)

    def test_performance_prompt_allows_empty_findings(self):
        prompt = _build_pass_prompt("performance", "x = 1", "f.py")
        self.assertIn("zero findings", prompt)

    def test_all_four_categories_have_prompts(self):
        for cat in ("bug", "security", "style", "performance"):
            prompt = _build_pass_prompt(cat, "x = 1", "f.py")
            self.assertGreater(len(prompt), 100)


# ============================================================
# SECTION 4 — new validator and security fixes added by auto-audit
# ============================================================

class TestPylintResultValidator(unittest.TestCase):

    def test_successful_result_with_findings_is_valid(self):
        r = PylintResult(
            ran_successfully=True,
            findings=[PylintFinding(line=1, column=0, type="convention",
                                    symbol="missing-docstring", message="Missing docstring",
                                    **{"message-id": "C0114"})],
        )
        self.assertTrue(r.ran_successfully)
        self.assertEqual(len(r.findings), 1)

    def test_failed_result_with_error_detail_is_valid(self):
        r = PylintResult(ran_successfully=False, error_detail="pylint not installed")
        self.assertFalse(r.ran_successfully)
        self.assertEqual(r.error_detail, "pylint not installed")

    def test_failed_result_without_error_detail_raises(self):
        with self.assertRaises(ValidationError) as ctx:
            PylintResult(ran_successfully=False)  # missing error_detail
        self.assertIn("error_detail", str(ctx.exception))

    def test_failed_result_with_findings_raises(self):
        with self.assertRaises(ValidationError):
            PylintResult(
                ran_successfully=False,
                error_detail="something went wrong",
                findings=[PylintFinding(line=1, column=0, type="convention",
                                         symbol="x", message="y",
                                         **{"message-id": "C0001"})],
            )


class TestHtmlEscaping(unittest.TestCase):
    """Verifies the XSS fix: LLM-generated strings are escaped before
    injection into unsafe_allow_html HTML blocks.
    """

    def test_html_escape_neutralises_script_tag(self):
        import html
        malicious = "<script>alert('xss')</script>"
        escaped = html.escape(malicious)
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)

    def test_html_escape_neutralises_event_handler(self):
        import html
        malicious = '" onmouseover="alert(1)'
        escaped = html.escape(malicious)
        self.assertNotIn('"', escaped)
        self.assertIn("&quot;", escaped)

    def test_html_escape_preserves_normal_text(self):
        import html
        normal = "Use parameterized queries instead of f-strings"
        self.assertEqual(html.escape(normal), normal)


if __name__ == "__main__":
    unittest.main()
