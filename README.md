# Code Review Agent — Project 2-I-B

Multi-pass AI code reviewer with a live Streamlit UI, optional pylint comparison, and dual light/dark theme support.

Each review category (bugs, security, style, performance) runs as a separate, narrowly-scoped LLM call rather than a single mega-prompt — so a weak style pass doesn't dilute a sharp security finding, and failures are localized to the specific pass that produced them.

## Features

- **Four independent review passes** — bugs, security, style, performance, each individually selectable
- **Structured output via Pydantic v2** — every finding is a validated `CodeFinding` object; HIGH/CRITICAL security findings require a CWE identifier or the schema rejects them outright
- **Risk score** — a single 0–100 score that weights CRITICAL findings heavily enough that one SQL injection can't be averaged away by ten clean style checks
- **pylint comparison** — runs the real pylint binary as a subprocess alongside the LLM review; degrades gracefully to a soft warning if pylint isn't available, never crashes the LLM review path
- **Dual theme** — toggle between dark (`#0E1116`) and light (`#F7F5F2`) in-session via the sidebar radio button, no restart required
- **Both paste and upload** — code can be submitted by pasting directly or uploading a `.py` file

## Architecture

```
app.py                   Streamlit UI (theme system, finding cards, tabs)
├── agent.py             Multi-pass review logic + pylint subprocess wrapper
│   ├── run_llm_review() LangChain with_structured_output() per pass
│   └── run_pylint()     subprocess → JSON parse → PylintResult
└── models.py            Pydantic v2 schemas
    ├── CodeFinding       Validated finding with CWE enforcement
    ├── ReviewPass        One category's findings
    ├── CodeReviewReport  Full report with risk score and sorting
    └── PylintResult      Pylint output, graceful on all failure modes
```

## Setup

**Requirements:** Python 3.12+, a Groq API key.

```bash
git clone <your-repo-url>
cd code-review-agent

pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
GROQ_API_KEY=gsk_...
```

Add `.env` to your `.gitignore` before the first commit — the template below does this automatically.

```bash
echo ".env" >> .gitignore
```

Run:

```bash
streamlit run app.py
```

Opens at `http://localhost:8501`.

## Running tests

```bash
python -m pytest tests.py -v
```

30 tests, no API key required. Tests cover:
- Pydantic model validation including intentional failure cases (CWE enforcement, line number bounds, description length, extra fields)
- Risk score computation and severity ordering
- pylint wrapper happy path (real subprocess)
- pylint graceful degradation (missing binary, timeout, malformed JSON, empty output)
- Prompt construction for each review category

## Model

Uses `openai/gpt-oss-120b` via Groq (replaces the deprecated `llama-3.1-8b-instant`/`llama-3.3-70b-versatile` pair as of June 2026). Change `MODEL_NAME` in `agent.py` to switch.

## Deployment

The project is a single Streamlit process with no external state (no database, no separate API layer) — deploy directly to Streamlit Community Cloud:

1. Push to a public GitHub repo
2. Go to [share.streamlit.io](https://share.streamlit.io), connect the repo, set `app.py` as the entry point
3. Add `GROQ_API_KEY` as a secret in the Streamlit Cloud settings panel (not in `requirements.txt` or any committed file)
4. pylint is included in `requirements.txt` — Streamlit Cloud will install it automatically

## Brief evaluation criteria

| Criterion | How this project satisfies it |
|---|---|
| Identifies real bugs | Four independent LLM passes, each scoped to one category so bugs aren't crowded out by style findings |
| Output is consistently structured | `with_structured_output(ReviewPass)` enforces schema on every pass; `CodeFinding` validates every field including cross-field CWE enforcement |
| Severity ratings are reasonable | CRITICAL/HIGH security findings require a CWE reference or are rejected; style findings are explicitly prompted away from CRITICAL; performance findings are instructed to return zero rather than invent marginal issues |
| Comparison with pylint | Real subprocess, real JSON parsing, real `PylintFinding` objects; shown alongside LLM findings in the UI |
| 5 example reviews | See `examples/` directory |
