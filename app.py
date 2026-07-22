"""
Code Review Agent -- Streamlit front-end with dual theme mode.

Run with: streamlit run app.py
Requires GROQ_API_KEY in a .env file in the same directory.
"""
from __future__ import annotations

import html
import os

import streamlit as st
from dotenv import load_dotenv
from pydantic import ValidationError

from agent import run_llm_review, run_pylint
from models import CodeReviewReport, PylintResult

load_dotenv()

st.set_page_config(
    page_title="Code Review Agent",
    page_icon=":material/policy:",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ----------------------------------------------------------------------
# THEME SYSTEM
#
# Streamlit's native theming (.streamlit/config.toml) only supports ONE
# theme at app-launch time -- it can't be toggled live by the user without
# a restart. To get a real in-session light/dark toggle, theme tokens are
# defined here as two dicts and injected as CSS custom properties, which
# every other piece of custom HTML in this app reads from. This is the one
# piece of real engineering "dual theme mode" requires beyond Streamlit's
# defaults.
#
# Signature element: the "severity spine" -- a 4px color bar down the left
# edge of every finding card. Severity is the single most important fact
# about a finding, so it's the one thing rendered as pure, instant color,
# no reading required. Both themes share the exact same severity ramp
# (one hue family, increasing in alarm) so a CRITICAL finding looks
# unambiguous in light or dark mode.
# ----------------------------------------------------------------------

THEMES = {
    "dark": {
        "bg": "#0E1116",
        "surface": "#161B22",
        "surface_raised": "#1C2129",
        "border": "#2A313C",
        "text": "#E6EDF3",
        "text_muted": "#8B949E",
        "accent": "#58A6FF",
    },
    "light": {
        "bg": "#F7F5F2",
        "surface": "#FFFFFF",
        "surface_raised": "#FBFAF8",
        "border": "#E2DED7",
        "text": "#1A1D23",
        "text_muted": "#6B6459",
        "accent": "#2563EB",
    },
}

# Single severity ramp shared across both themes -- deliberately one hue
# family (red, increasing in saturation/alarm toward CRITICAL) rather than
# the generic four-unrelated-colors traffic-light cliche. LOW is closer to
# the muted/neutral end; CRITICAL is unmistakable.
SEVERITY_COLORS = {
    "CRITICAL": "#E5484D",
    "HIGH": "#F2994A",
    "MEDIUM": "#E8B339",
    "LOW": "#6B9BD1",
}

CATEGORY_LABELS = {
    "bug": "Bug",
    "security": "Security",
    "style": "Style",
    "performance": "Performance",
}


def inject_theme_css(theme_name: str) -> None:
    t = THEMES[theme_name]
    st.markdown(
        f"""
        <style>
        :root {{
            --cra-bg: {t['bg']};
            --cra-surface: {t['surface']};
            --cra-surface-raised: {t['surface_raised']};
            --cra-border: {t['border']};
            --cra-text: {t['text']};
            --cra-text-muted: {t['text_muted']};
            --cra-accent: {t['accent']};
        }}

        .stApp {{
            background-color: var(--cra-bg);
        }}

        [data-testid="stSidebar"] {{
            background-color: var(--cra-surface);
            border-right: 1px solid var(--cra-border);
        }}

        .cra-finding-card {{
            background-color: var(--cra-surface);
            border: 1px solid var(--cra-border);
            border-left: 4px solid var(--cra-sev-color);
            border-radius: 6px;
            padding: 14px 16px;
            margin-bottom: 10px;
        }}

        .cra-finding-title {{
            color: var(--cra-text);
            font-weight: 600;
            font-size: 0.95rem;
            margin-bottom: 4px;
        }}

        .cra-finding-meta {{
            color: var(--cra-text-muted);
            font-size: 0.78rem;
            font-family: ui-monospace, "SF Mono", "JetBrains Mono", monospace;
            margin-bottom: 8px;
        }}

        .cra-finding-desc {{
            color: var(--cra-text);
            font-size: 0.88rem;
            line-height: 1.5;
            margin-bottom: 8px;
        }}

        .cra-finding-fix {{
            color: var(--cra-text-muted);
            font-size: 0.85rem;
            line-height: 1.5;
            border-top: 1px solid var(--cra-border);
            padding-top: 8px;
            margin-top: 4px;
        }}

        .cra-badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.03em;
            color: #0E1116;
        }}

        .cra-score-ring {{
            text-align: center;
            padding: 18px 0;
        }}

        .cra-score-number {{
            font-size: 2.6rem;
            font-weight: 700;
            color: var(--cra-text);
            line-height: 1;
        }}

        .cra-score-label {{
            color: var(--cra-text-muted);
            font-size: 0.8rem;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            margin-top: 4px;
        }}

        .cra-empty-state {{
            color: var(--cra-text-muted);
            text-align: center;
            padding: 32px 16px;
            border: 1px dashed var(--cra-border);
            border-radius: 8px;
            font-size: 0.9rem;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_finding_card(finding) -> None:
    color = SEVERITY_COLORS[finding.severity]
    # Escape all LLM-generated strings before injecting into raw HTML --
    # the model returning '<script>...</script>' in a title or description
    # is low-probability but non-zero, and unsafe_allow_html=True won't
    # save you if the injected content itself contains script tags.
    safe_title = html.escape(finding.title)
    safe_desc = html.escape(finding.description)
    safe_fix = html.escape(finding.suggested_fix)
    safe_cwe = html.escape(finding.cwe_id) if finding.cwe_id else None
    cwe_html = f'<span class="cra-badge" style="background-color:var(--cra-border);color:var(--cra-text);">{safe_cwe}</span>' if safe_cwe else ""
    st.markdown(
        f"""
        <div class="cra-finding-card" style="--cra-sev-color:{color};">
            <span class="cra-badge" style="background-color:{color};">{finding.severity}</span>
            &nbsp;
            <span class="cra-badge" style="background-color:var(--cra-border);color:var(--cra-text);">{CATEGORY_LABELS[finding.category]}</span>
            {f"&nbsp;{cwe_html}" if cwe_html else ""}
            <div class="cra-finding-title" style="margin-top:8px;">{safe_title}</div>
            <div class="cra-finding-meta">line {finding.line_number}</div>
            <div class="cra-finding-desc">{safe_desc}</div>
            <div class="cra-finding-fix"><strong>Fix:</strong> {safe_fix}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_score(report: CodeReviewReport) -> None:
    score = report.overall_risk_score
    score_color = "#3FB950" if score >= 80 else "#E8B339" if score >= 50 else "#E5484D"
    st.markdown(
        f"""
        <div class="cra-score-ring">
            <div class="cra-score-number" style="color:{score_color};">{score}</div>
            <div class="cra-score-label">Risk Score / 100</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_pylint_comparison(pylint_result: PylintResult) -> None:
    if not pylint_result.ran_successfully:
        st.info(
            f":material/info: pylint comparison unavailable -- {pylint_result.error_detail}"
        )
        return

    if not pylint_result.findings:
        st.success(":material/check_circle: pylint reported zero findings.")
        return

    st.caption(f"{len(pylint_result.findings)} pylint findings (separate tool, separate methodology -- not cross-validated against the LLM review above)")
    for f in pylint_result.findings:
        safe_symbol = html.escape(f.symbol)
        safe_message = html.escape(f.message)
        st.markdown(
            f"<div class='cra-finding-meta'>line {f.line} &nbsp;·&nbsp; "
            f"<code>{safe_symbol}</code> &nbsp;·&nbsp; {safe_message}</div>",
            unsafe_allow_html=True,
        )


# ----------------------------------------------------------------------
# SIDEBAR -- theme toggle, input mode, run controls
# ----------------------------------------------------------------------

if "theme" not in st.session_state:
    st.session_state.theme = "dark"
if "report" not in st.session_state:
    st.session_state.report = None
if "pylint_result" not in st.session_state:
    st.session_state.pylint_result = None
if "submitted_code" not in st.session_state:
    st.session_state.submitted_code = ""
if "submitted_filename" not in st.session_state:
    st.session_state.submitted_filename = "submission.py"

with st.sidebar:
    st.markdown("### Code Review Agent")
    st.caption("Multi-pass LLM review + optional pylint comparison")

    theme_choice = st.radio(
        "Theme",
        options=["dark", "light"],
        index=0 if st.session_state.theme == "dark" else 1,
        horizontal=True,
        label_visibility="collapsed",
    )
    st.session_state.theme = theme_choice

    st.divider()

    input_mode = st.radio("Input method", options=["Paste code", "Upload file"], label_visibility="collapsed")

    code_input = ""
    filename_input = "submission.py"

    if input_mode == "Paste code":
        code_input = st.text_area("Paste Python code", height=280, label_visibility="collapsed",
                                    placeholder="def example():\n    pass")
    else:
        uploaded = st.file_uploader("Upload a .py file", type=["py"])
        if uploaded is not None:
            MAX_UPLOAD_BYTES = 100_000  # 100KB -- a .py file larger than this is almost certainly not intended for review
            raw_bytes = uploaded.read(MAX_UPLOAD_BYTES + 1)
            if len(raw_bytes) > MAX_UPLOAD_BYTES:
                st.error(f"File too large -- max {MAX_UPLOAD_BYTES // 1000}KB. Upload a single Python module, not a whole project.")
            else:
                code_input = raw_bytes.decode("utf-8", errors="replace")
                filename_input = uploaded.name

    categories = st.multiselect(
        "Review passes",
        options=["bug", "security", "style", "performance"],
        default=["bug", "security", "style", "performance"],
        format_func=lambda c: CATEGORY_LABELS[c],
    )

    run_pylint_too = st.checkbox("Also run pylint comparison", value=True)

    run_clicked = st.button(":material/play_arrow: Run Review", type="primary", use_container_width=True)


inject_theme_css(st.session_state.theme)

# ----------------------------------------------------------------------
# MAIN AREA
# ----------------------------------------------------------------------

st.title("Code Review")
st.caption("Paste or upload Python code. Each category below runs as its own scoped review pass.")

if run_clicked:
    if not code_input.strip():
        st.warning("No code submitted -- paste code or upload a file first.")
    elif not categories:
        st.warning("Select at least one review pass.")
    else:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            st.error("GROQ_API_KEY not found. Add it to a .env file next to this app.")
            st.stop()

        with st.spinner("Running review passes..."):
            try:
                report = run_llm_review(code_input, filename_input, api_key, categories)
                st.session_state.report = report
                st.session_state.submitted_code = code_input
                st.session_state.submitted_filename = filename_input
            except ValidationError as e:
                st.error(f"The review agent produced an output that failed validation: {e}")
                st.session_state.report = None
            except Exception as e:
                st.error(
                    "The review failed due to an unexpected API or model response. "
                    "Please verify your GROQ_API_KEY and try again."
                )
                st.error(f"{type(e).__name__}: {e}")
                st.session_state.report = None

        if run_pylint_too and st.session_state.report is not None:
            with st.spinner("Running pylint..."):
                st.session_state.pylint_result = run_pylint(code_input)
        else:
            st.session_state.pylint_result = None


report: CodeReviewReport | None = st.session_state.report

if report is None:
    st.markdown(
        '<div class="cra-empty-state">No review yet. Paste or upload code in the sidebar, then run a review.</div>',
        unsafe_allow_html=True,
    )
else:
    overview_col, findings_col = st.columns([1, 2.4], gap="large")

    with overview_col:
        render_score(report)
        st.divider()
        st.markdown("**Findings by severity**")
        for sev, count in report.severity_counts.items():
            if count > 0:
                st.markdown(
                    f'<span class="cra-badge" style="background-color:{SEVERITY_COLORS[sev]};">{sev}</span> &nbsp; {count}',
                    unsafe_allow_html=True,
                )
        st.divider()
        st.markdown(f"**File:** `{report.filename}`")
        st.markdown(f"**Lines reviewed:** {report.lines_reviewed}")

        if st.session_state.pylint_result is not None:
            st.divider()
            st.markdown("**pylint comparison**")
            render_pylint_comparison(st.session_state.pylint_result)

    with findings_col:
        if not report.all_findings:
            st.markdown(
                '<div class="cra-empty-state">No findings across the selected review passes.</div>',
                unsafe_allow_html=True,
            )
        else:
            tabs = st.tabs(["All"] + [CATEGORY_LABELS[c] for c in categories])

            with tabs[0]:
                for finding in report.all_findings:
                    render_finding_card(finding)

            for i, cat in enumerate(categories, start=1):
                with tabs[i]:
                    cat_findings = [f for f in report.all_findings if f.category == cat]
                    if not cat_findings:
                        st.markdown(
                            '<div class="cra-empty-state">No findings in this category.</div>',
                            unsafe_allow_html=True,
                        )
                    for finding in cat_findings:
                        render_finding_card(finding)

    with st.expander("View submitted code"):
        st.code(st.session_state.submitted_code, language="python", line_numbers=True)
