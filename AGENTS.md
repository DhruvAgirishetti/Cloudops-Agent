# CloudOps Agent Repository Guide

## Project Overview

CloudOps Agent is a local Streamlit application for reviewing AWS IAM policy JSON,
CloudTrail-style JSON, and Terraform HCL files. Uploads are validated and analyzed
locally using deterministic rules. The application does not connect to AWS, execute
uploaded content, or currently use AI.

Analysis results use the shared `Finding` model. A standalone correlation engine
currently supports one narrow action overlap between an IAM finding and a CloudTrail
finding. A correlation does not establish shared identity, authorization, or causation.

## Project Structure

- `app.py` — Streamlit uploads, explicit analysis actions, result display, and
  correlation presentation.
- `src/cloudops_agent/models.py` — shared `Finding`, `SourceType`, and `Severity`
  types and evidence validation.
- `src/cloudops_agent/uploads.py` — upload validation and parsed input summaries.
- `src/cloudops_agent/iam_analyzer.py` — deterministic checks for a supported subset
  of AWS IAM identity policies.
- `src/cloudops_agent/cloudtrail_analyzer.py` — deterministic checks for selected
  CloudTrail event patterns.
- `src/cloudops_agent/terraform_analyzer.py` — parser-backed static checks for
  supported literal Terraform patterns; Terraform is never executed.
- `src/cloudops_agent/correlation.py` — deterministic, conservative relationships
  between artifact-scoped findings.
- `src/cloudops_agent/analysis_state.py` — content-based result keys, stale-result
  cleanup, and collection of current findings for correlation.
- `tests/` — standard-library `unittest` tests.
- `test_samples/` — synthetic input examples.

Keep feature logic in focused modules under `src/cloudops_agent/`, and tests under
`tests/`. Avoid unrelated UI changes, generated files, dependency caches, and local
environment files in version control.

## Development Commands

Run the app from the repository root:

```powershell
streamlit run app.py
```

Run the full test suite with the project virtual environment:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Use Python 3.10 or newer. Install the project and its declared dependencies in
`.venv` before running the app or tests.

## Architecture and Data Flow

- Deterministic analyzers own input-specific parsing and security detection.
- The dashboard validates uploads, invokes analyzers only through explicit user
  actions, stores results in Streamlit session state, and presents findings.
- Analysis result keys include analyzer, upload position, and a hash of the uploaded
  content. Use active keys to ensure replaced or removed uploads cannot contribute
  stale results.
- Correlation consumes `Finding` objects and artifact IDs. It does not inspect
  uploaded source files or infer a common account, identity, policy attachment,
  authorization, or cause.
- Keep analyzers, correlation, state management, and presentation logic modular.
  Avoid unnecessary dependencies and multi-agent complexity.

## AI Investigation Direction

No AI provider, model, API, or integration has been selected. Do not add one until
the architecture and data contract have been designed and approved.

When AI investigation work is approved:

1. AI consumes structured `Finding` and `Correlation` objects supplied by the
   application. It does not independently analyze uploaded source files or replace
   deterministic analyzers.
2. AI must not invent findings, AWS identities, accounts, resources, relationships,
   or other missing context.
3. Every factual security claim in an AI response must reference one or more
   supplied Finding IDs or Correlation IDs. Do not present general security
   knowledge, assumptions, or inferred context as facts about the user's uploaded
   environment. State missing information and uncertainty explicitly.
4. Treat correlations as evidence overlap only. They do not prove authorization,
   shared identity, or causation.
5. AI recommendations are advisory. Do not automatically remediate, execute
   commands, or change infrastructure.
6. Include only fields necessary for the investigation in AI context. Do not pass
   raw uploaded files, unrelated findings, unnecessary evidence fields, or unrelated
   application/session data. Do not enrich investigation context with external
   information unless explicitly approved.
7. Do not add AWS integration, credentials, or infrastructure deployment.

## Security and Scope

- Deterministic analyzers remain responsible for parsing and detecting security
  issues.
- Do not execute uploaded Terraform or other uploaded scripts.
- Do not add AWS calls, credentials, or automatic remediation.
- Preserve existing analyzer workflows, correlation behavior, upload validation,
  and stale-result protections.
- Static-analysis no-match results are not claims that an input or environment is
  safe.
- Terraform checks do not resolve variables, modules, provider defaults, plans,
  state, or deployed AWS state unless a separately approved feature changes that
  scope.

## Testing Expectations

Add or update focused tests for behavior changes, including relevant malformed,
missing, ambiguous, and stale-result cases. Before handing off code changes, run
the full suite using `.venv`:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Report the actual test result. Do not substitute a system Python interpreter that
may lack project dependencies.
