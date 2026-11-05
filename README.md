# CloudOps Agent

**Local, read-only AWS security investigation for IAM policies, CloudTrail events, and Terraform configuration.** CloudOps Agent combines deterministic static checks, cautious cross-source evidence correlation, and an optional evidence-scoped AI investigation.

Deterministic analysis runs locally. The app makes no AWS API calls and never executes uploaded files. If you explicitly request an AI investigation and configure a Meta API key, the app sends a minimized, allowlisted investigation context to Meta's API; it does not send raw uploaded files.

## What it checks

### IAM policies

The deterministic IAM analyzer supports a subset of AWS identity-policy JSON:

- An `Allow` with `Action: "*"` and `Resource: "*"`.
- `iam:*` with `Resource: "*"`.
- `Allow` statements containing known sensitive actions, including access-key creation, IAM policy attachment or editing, policy-version changes, and `ec2:AuthorizeSecurityGroupIngress`. Supported action patterns may match these known actions.

These are static policy-document findings. Conditions are not evaluated, and the analyzer does not calculate effective permissions or establish exploitability.

### CloudTrail events

The CloudTrail analyzer accepts one event object or a `Records` envelope and checks these explicit patterns:

- `StopLogging` and `DeleteTrail` events with no `errorCode`.
- `CreateAccessKey` events from `iam.amazonaws.com` with no `errorCode`.
- `AuthorizeSecurityGroupIngress` events from `ec2.amazonaws.com` with no `errorCode`, where the request permissions establish TCP port 22 or 3389 exposure to `0.0.0.0/0` or `::/0`.
- A successful `ConsoleLogin` event reporting `MFAUsed` as `No`.

An event record is evidence of the recorded event, not proof of malicious intent, exploitation, or current AWS resource state.

### Terraform configuration

The HCL2 parser-backed analyzer checks supported literal values in:

- `aws_s3_bucket_acl` configured as `public-read` or `public-read-write`.
- `aws_s3_bucket_public_access_block` settings explicitly set to `false`.
- Inline `aws_security_group` ingress that allows internet-wide SSH or RDP over TCP, or all protocols, from `0.0.0.0/0` or `::/0`.

It does not analyze standalone ingress-rule resources. Variables, locals, modules, dynamic blocks, provider defaults, plans, state, and deployed AWS settings are not resolved. Terraform is parsed only; it is never executed.

## Correlation and AI investigation

Correlations are generated from current successful analyzer results and use artifact-scoped finding references. The engine supports:

- **Action overlap:** one IAM finding matching `iam:CreateAccessKey` and one CloudTrail finding recording `iam.amazonaws.com` / `CreateAccessKey`.
- **Configuration-pattern overlap:** one IAM finding with the exact allowed `ec2:AuthorizeSecurityGroupIngress` action, one successful CloudTrail public SSH/RDP ingress event, and one Terraform public SSH/RDP ingress finding with an overlapping port and public CIDR pattern.

For the three-source relationship, Terraform evidence does not identify the deployed security group changed by the CloudTrail event. The relationship is explicitly a configuration-pattern overlap; it does not establish shared resource identity, account, actor, causation, policy attachment, or authorization. Ambiguous candidate sets do not produce a correlation.

AI investigation is a separate, optional action for one selected finding or one selected correlation and its exact referenced findings. The integration uses Meta Muse Spark 1.3 Standard mode through Meta's OpenAI-compatible Chat Completions API. The input builder sends allowlisted structured fields and request-scoped opaque references; it omits raw CloudTrail events, raw Terraform HCL, and IAM `Condition` data. The output must pass a strict JSON Schema and request-scoped citation validation before display.

Citation validation checks that references exist in the selected request scope. It does **not** prove that a cited item semantically supports an AI claim. Recommendations are advisory: CloudOps Agent does not execute, apply, or verify them. Provider-reported token counts are displayed when available.

## Architecture and data flow

1. `app.py` accepts source files, validates them, and waits for an explicit per-file **Analyze** action.
2. `uploads.py` checks extension, size, emptiness, encoding, and JSON structure. Analyzer modules produce shared `Finding` records; Terraform results also include analysis limitations.
3. `analysis_state.py` keys results by analyzer, upload position, and content hash, and removes stale results when uploads change or are removed.
4. `correlation.py` consumes only current findings and artifact identifiers. It produces deterministic pairwise or three-source `Correlation` records with supporting evidence and limitations.
5. When requested, `investigation_input.py` builds a minimal scope-specific payload with opaque references. `meta_provider.py` sends it to Meta; `investigation_output.py` validates the returned structure and citations; `investigation_workflow.py` caches validated results for the exact scope.
6. Streamlit presents findings, correlations, and optional AI investigations. Ordinary reruns do not initiate analysis or provider requests.

## Requirements and installation

- Python 3.10 or newer.
- Windows PowerShell commands are shown below; the project can also be installed on other Python-supported platforms.

From the repository root, create and install into a virtual environment:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that PowerShell window, then activate again.

## Run the application

```powershell
streamlit run app.py
```

Upload `.json` files under CloudTrail or IAM and `.tf` files under Terraform. Multiple files per source are supported; each file is limited to 5 MB. Select the matching **Analyze** button to run deterministic checks. AI investigation remains optional and is requested separately from a finding or correlation.

### Optional Meta AI configuration

Deterministic analysis and cross-source correlation work without an API key. Live AI investigations require a valid Meta Model API key. `MODEL_API_KEY` is the only supported environment variable name. Set it in the shell you use to launch the app, then run Streamlit from the project's `.venv`:

**PowerShell**

```powershell
$env:MODEL_API_KEY = "<your Meta API key>"
.\.venv\Scripts\streamlit.exe run app.py
```

**Windows Command Prompt (CMD)**

```bat
set "MODEL_API_KEY=<your Meta API key>"
.venv\Scripts\streamlit.exe run app.py
```

**macOS/Linux**

```sh
export MODEL_API_KEY="<your Meta API key>"
./.venv/bin/streamlit run app.py
```

Keep the key in an environment variable or approved secret store. Do not place it in source code, uploaded samples, or committed files. A live investigation transmits the selected, allowlisted context to Meta and may consume API credits. The integration does not automatically retry failed requests.

## Demo with the bundled samples

The `test_samples/` directory contains focused test fixtures and a three-file cross-source demonstration set. From the repository root:

1. Start the app and upload `prod_iam_policy.json` in IAM, `prod_cloudtrail_events.json` in CloudTrail, and `production_network_and_storage.tf` in Terraform.
2. Select **Analyze IAM policy**, **Analyze CloudTrail logs**, and **Analyze Terraform configuration**. For these fixtures, expect one IAM finding, two CloudTrail findings, and two Terraform findings.
3. Review the findings and overview, then inspect **Cross-source correlations**. These fixtures are designed to produce an IAM–CloudTrail CreateAccessKey action overlap and a three-source public SSH configuration-pattern overlap.
4. Optionally set `MODEL_API_KEY` before launch and select **Investigate correlation with AI** for the three-source relationship. Review its cited summary, advisory recommendations, limitations, and token usage. The AI request depends on network access and provider availability; deterministic results do not.

The `prod_` filenames are sample names, not a claim that the files represent a deployed production environment. Other `test_` fixtures cover individual matches and no-match or malformed inputs.

## Run tests

The test suite uses Python's standard-library `unittest` runner; project dependencies should be installed in `.venv` first.

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

Tests use local fixtures and fake provider clients; they do not make live Meta API requests.

## Safety guarantees and limitations

- No AWS connections, AWS credentials, infrastructure deployment, automatic remediation, or execution of uploaded content.
- Designed for local, single-user use; the app does not provide user authentication or multi-user isolation. Do not expose it on a public network without separate access controls.
- Uploaded JSON and Terraform are size-limited and validated before analysis. Terraform is parsed, never run.
- Deterministic checks cover only the documented patterns. A no-match result is not a safety assessment.
- IAM checks do not evaluate conditions or effective permissions. CloudTrail checks depend on the contents and completeness of supplied event records. Terraform checks do not establish deployed state or reachability.
- Correlations represent only the stated evidence overlap and do not establish common identity, account, resource, authorization, policy attachment, or causation.
- AI claims can be semantically unsupported even when their citations are structurally valid. AI output is advisory and is not an independently verified security assessment or remediation.
- When a re-investigation fails, the previous validated result is preserved and the failure is reported separately.
