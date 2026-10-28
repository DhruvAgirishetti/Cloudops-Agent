# CloudOps Agent

CloudOps Agent is a local Streamlit application for preparing AWS security investigation inputs. This initial milestone accepts CloudTrail-style JSON, AWS IAM policy JSON, and Terraform `.tf` files. It displays basic format and structure summaries only; it does not scan for security issues, call an AI model, connect to AWS, or execute uploaded files.

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

Upload files using the matching category. Each file must be non-empty, use the expected extension, and be no larger than 5 MB. JSON uploads are checked for valid UTF-8 JSON; IAM policy uploads must contain a `Statement` field. Summaries are descriptive and do not indicate that security analysis has occurred.

## Run tests

```powershell
python -m unittest discover -s tests -v
```
