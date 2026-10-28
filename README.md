# CloudOps Agent

CloudOps Agent is a local Streamlit application for reviewing AWS security investigation inputs. It accepts CloudTrail-style JSON, AWS IAM policy JSON, and Terraform `.tf` files, and runs a small set of deterministic local checks. It does not call an AI model, connect to AWS, or execute uploaded files.

## Requirements

- Python 3.10 or newer
- Windows PowerShell

## Set up on Windows

Open PowerShell in this repository directory and run:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that PowerShell window, then activate again. No API key or cloud credentials are needed for this milestone.

## Run the app

```powershell
streamlit run app.py
```

Upload files using the matching category. Each file must be non-empty, use the expected extension, and be no larger than 5 MB. JSON uploads are checked for valid UTF-8 JSON; IAM policy uploads must contain a `Statement` field. Select the corresponding **Analyze** button to run IAM, CloudTrail, or Terraform checks.

Terraform analysis parses HCL2 syntax and checks only explicit literal values for the configured S3 ACL, S3 public-access-block, and inline security-group ingress rules. It does not resolve variables, modules, provider defaults, Terraform plans or state, or deployed AWS settings. A result with no matching rules does not mean the configuration is safe. Terraform is parsed but never executed.

## Run tests

```powershell
python -m unittest discover -s tests -v
```
