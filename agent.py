"""
Code Review Agent: multi-pass LLM review (bugs, security, style,
performance) plus an optional pylint comparison pass.

Design notes:
- Each LLM pass is a SEPARATE call with a narrowly-scoped prompt (Day 1's
  prompt-chaining: one job per link, not one mega-prompt asking for
  everything at once). This keeps each pass's output easier to validate
  and means a single weak pass doesn't drag down the others.
- with_structured_output() is used per pass (Day 2 pattern), so a
  malformed pass fails LOUDLY with a ValidationError at the call site,
  not silently with a missing/wrong-shaped finding three steps downstream.
- pylint runs as a real subprocess (Day 4's "real external tool, real
  failure modes" pattern) but is wrapped so its absence or a crash never
  takes down the LLM review -- it's presented as a comparison, not a
  dependency.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from pydantic import ValidationError
from langchain_groq import ChatGroq

from models import CodeFinding, CodeReviewReport, ReviewPass, PylintFinding, PylintResult

MODEL_NAME = "openai/gpt-oss-120b"

PASS_PROMPTS: dict[str, str] = {
    "bug": (
        "Review this Python code SPECIFICALLY for logic bugs: incorrect "
        "conditionals, off-by-one errors, mishandled edge cases (None, "
        "empty collections, zero/negative numbers), wrong variable usage, "
        "and unhandled exceptions that should be caught. Do NOT report "
        "style, security, or performance issues in this pass -- those are "
        "reviewed separately. Only report genuine logic defects, not "
        "stylistic preferences."
    ),
    "security": (
        "Review this Python code SPECIFICALLY for security vulnerabilities: "
        "injection risks (SQL, command, path traversal), hardcoded secrets "
        "or credentials, insecure deserialization, missing input validation "
        "on untrusted data, weak/broken cryptography, and insecure defaults. "
        "For any HIGH or CRITICAL finding, include the relevant CWE "
        "identifier. Do NOT report bugs, style, or performance issues in "
        "this pass."
    ),
    "style": (
        "Review this Python code SPECIFICALLY for style and maintainability: "
        "naming conventions, missing type hints, missing docstrings on "
        "public functions, overly long functions doing too many things, "
        "and PEP 8 violations. Do NOT report bugs, security, or performance "
        "issues in this pass. Severity should rarely exceed MEDIUM for pure "
        "style issues -- style problems are not CRITICAL by nature."
    ),
    "performance": (
        "Review this Python code SPECIFICALLY for performance issues: "
        "unnecessary O(n^2) patterns where O(n) is achievable, repeated "
        "redundant computation inside loops, inefficient data structure "
        "choices (e.g. list membership-checking in a hot loop instead of "
        "a set), and unnecessary I/O inside loops. Do NOT report bugs, "
        "security, or style issues in this pass. If the code is short "
        "enough that performance is genuinely a non-issue, return zero "
        "findings rather than inventing marginal ones."
    ),
}


def _build_pass_prompt(category: str, code: str, filename: str) -> str:
    instructions = PASS_PROMPTS[category]
    return (
        f"{instructions}\n\n"
        f"File: {filename}\n"
        f"```python\n{code}\n```\n\n"
        f"Report every line number relative to the code block above, "
        f"starting at line 1. If you find nothing in this category, "
        f"return an empty findings list -- do not invent findings to "
        f"avoid returning an empty result."
    )


def run_llm_review(code: str, filename: str, api_key: str, categories: list[str] | None = None) -> CodeReviewReport:
    """Runs one structured-output call per review category and assembles
    the results into a CodeReviewReport. Raises ValidationError upward if
    a pass produces output that violates CodeFinding's schema (e.g. a
    HIGH security finding with no cwe_id) -- callers should catch this
    explicitly rather than letting a malformed report through silently.
    """
    categories = categories or list(PASS_PROMPTS.keys())
    llm = ChatGroq(model=MODEL_NAME, api_key=api_key, temperature=0)
    structured_llm = llm.with_structured_output(ReviewPass, method="function_calling")

    passes: list[ReviewPass] = []
    for category in categories:
        prompt = _build_pass_prompt(category, code, filename)
        result = structured_llm.invoke(prompt)
        # Defensive: force category to what we requested rather than
        # trusting the model's self-report. Use model_copy(update=...)
        # instead of direct field assignment -- direct mutation bypasses
        # validation and triggers a deprecation warning in pydantic 2.13+.
        result = result.model_copy(update={"category": category})
        passes.append(result)

    return CodeReviewReport(
        filename=filename,
        lines_reviewed=len(code.splitlines()),
        passes=passes,
    )


def run_pylint(code: str) -> PylintResult:
    """Runs pylint as a real subprocess against the submitted code,
    written to a temp file. Returns ran_successfully=False (never raises)
    if pylint isn't installed, times out, or its output can't be parsed --
    this comparison is explicitly optional per the project's design, and
    its absence must never break the LLM review path.
    """
    if shutil.which("pylint") is None:
        return PylintResult(
            ran_successfully=False,
            error_detail="pylint is not installed in this environment. "
                          "The LLM review above is unaffected.",
        )

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / "submitted_code.py"
            tmp_path.write_text(code, encoding="utf-8")

            proc = subprocess.run(
                ["pylint", "--output-format=json", str(tmp_path)],
                capture_output=True,
                text=True,
                timeout=20,
            )

            # IMPORTANT: pylint's exit code is a bitmask of finding
            # categories, NOT a success/failure signal -- a nonzero
            # returncode here usually just means "pylint found things,"
            # which is the expected, successful case. We only treat this
            # as a real failure if stdout is empty AND stderr has content,
            # which indicates pylint itself couldn't run (vs. ran and
            # reported findings).
            if not proc.stdout.strip() and proc.stderr.strip():
                return PylintResult(
                    ran_successfully=False,
                    error_detail=f"pylint did not produce output: {proc.stderr[:300]}",
                )

            raw_findings = json.loads(proc.stdout) if proc.stdout.strip() else []
            findings = [PylintFinding.model_validate(f) for f in raw_findings]
            return PylintResult(ran_successfully=True, findings=findings)

    except subprocess.TimeoutExpired:
        return PylintResult(
            ran_successfully=False,
            error_detail="pylint timed out after 20s. The LLM review above is unaffected.",
        )
    except OSError as e:
        return PylintResult(
            ran_successfully=False,
            error_detail=f"pylint could not be executed: {e}",
        )
    except (json.JSONDecodeError, ValidationError) as e:
        return PylintResult(
            ran_successfully=False,
            error_detail=f"pylint returned output in an unexpected format: {e}",
        )
