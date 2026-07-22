"""
Pydantic v2 schemas for the Code Review Agent.

Severity is tied to category via a cross-field validator: a HIGH/CRITICAL
security finding without a CWE reference is treated as under-specified for
a production audit report and rejected at the schema boundary, not caught
three steps downstream in a report generator.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

Severity = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Category = Literal["bug", "security", "style", "performance"]

# Ordered worst-to-best, used for sorting findings and computing a single
# overall score without re-deriving the ordering in multiple places.
SEVERITY_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class CodeFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    line_number: int = Field(gt=0, description="1-indexed line number in the reviewed file")
    severity: Severity
    category: Category
    title: str = Field(min_length=3, max_length=80, description="Short finding title, e.g. 'SQL injection via string concatenation'")
    description: str = Field(min_length=10, description="What's wrong and why it matters, at least 10 chars to reject lazy one-word findings")
    suggested_fix: str = Field(min_length=5, description="A concrete, actionable fix -- not just 'be more careful'")
    cwe_id: str | None = Field(default=None, description="CWE identifier if category is 'security' and severity is HIGH/CRITICAL, e.g. 'CWE-89'")

    @model_validator(mode="after")
    def security_findings_need_cwe(self) -> "CodeFinding":
        if self.category == "security" and self.severity in ("HIGH", "CRITICAL") and not self.cwe_id:
            raise ValueError(
                "HIGH/CRITICAL security findings must include a cwe_id -- "
                "a severity claim without a CWE reference is under-specified "
                "for a production audit report"
            )
        return self


class ReviewPass(BaseModel):
    """One multi-pass reviewer's output -- bugs, security, style, or
    performance -- kept separate so each pass's prompt stays scoped to one
    job (Day 1's prompt-chaining principle: separation of concerns, one
    link does one thing, failures are localized to a specific pass).
    """
    model_config = ConfigDict(extra="forbid")

    category: Category
    findings: list[CodeFinding] = Field(default_factory=list)


class CodeReviewReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    filename: str
    language: str = Field(default="python")
    lines_reviewed: int = Field(gt=0)
    passes: list[ReviewPass]

    @property
    def all_findings(self) -> list[CodeFinding]:
        findings = [f for p in self.passes for f in p.findings]
        return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.line_number))

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in self.all_findings:
            counts[f.severity] += 1
        return counts

    @property
    def overall_risk_score(self) -> int:
        """A single 0-100 score: 100 = clean, 0 = severe. Weighted so that
        even one CRITICAL finding dominates the score -- a file with one
        SQL injection and zero style nits should NOT score better than a
        file with ten style nits and nothing else, and a naive average
        would get this backwards.
        """
        weights = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "LOW": 3}
        counts = self.severity_counts
        penalty = sum(weights[sev] * n for sev, n in counts.items())
        return max(0, 100 - penalty)


class PylintFinding(BaseModel):
    """Normalized representation of one pylint JSON finding -- maps
    pylint's own type taxonomy (convention/refactor/warning/error/fatal)
    onto a flat severity-like string for display purposes only. This is
    NOT validated as strictly as CodeFinding because it's parsing a tool's
    output we don't control, not an LLM's -- the failure mode here is a
    pylint version changing its output schema, not a model hallucinating.
    """
    model_config = ConfigDict(extra="ignore")

    line: int
    column: int
    type: str
    symbol: str
    message: str
    message_id: str = Field(validation_alias="message-id")


class PylintResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ran_successfully: bool
    findings: list[PylintFinding] = Field(default_factory=list)
    error_detail: str | None = Field(default=None, description="Set when ran_successfully is False -- why pylint couldn't run, not a finding")

    @model_validator(mode="after")
    def consistency_check(self) -> "PylintResult":
        if not self.ran_successfully and self.findings:
            raise ValueError(
                "ran_successfully=False but findings is non-empty -- "
                "these states are mutually exclusive"
            )
        if not self.ran_successfully and self.error_detail is None:
            raise ValueError(
                "ran_successfully=False requires error_detail to explain why"
            )
        return self
