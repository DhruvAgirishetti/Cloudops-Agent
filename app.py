"""Streamlit upload interface for CloudOps Agent."""

import streamlit as st

from cloudops_agent.uploads import UploadValidationError, process_upload


st.set_page_config(page_title="CloudOps Agent", page_icon="☁️", layout="wide")

st.title("☁️ CloudOps Agent")
st.caption("Prepare cloud investigation inputs in one place.")
st.info(
    "This foundation build only checks upload format and displays basic file summaries. "
    "It does not analyze security, connect to AWS, or execute uploaded content."
)

columns = st.columns(3)
uploaders = [
    (columns[0], "CloudTrail logs", "Upload CloudTrail-style JSON logs", ["json"]),
    (columns[1], "AWS IAM policy", "Upload AWS IAM policy JSON", ["json"]),
    (columns[2], "Terraform configuration", "Upload AWS Terraform .tf files", ["tf"]),
]

for column, input_type, label, extensions in uploaders:
    with column:
        st.subheader(input_type)
        files = st.file_uploader(
            label,
            type=extensions,
            accept_multiple_files=True,
            key=input_type,
            help="Maximum size: 5 MB per file. Uploaded content is never executed.",
        )
        for uploaded_file in files:
            try:
                result = process_upload(uploaded_file.name, uploaded_file.getvalue(), input_type)
            except UploadValidationError as error:
                st.error(f"{uploaded_file.name}: {error}")
                continue
            st.text(f"File: {result.filename} · Type: {result.input_type} · Size: {result.size_bytes:,} bytes")
            st.caption(result.summary)
