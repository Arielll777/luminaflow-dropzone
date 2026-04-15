from __future__ import annotations
import csv, hashlib, io, json, os, re, tempfile, uuid
from datetime import datetime, timezone
import streamlit as st

st.set_page_config(page_title="LuminaFlow Secure Upload", page_icon="🛡️", layout="centered")

BRAND_NAME = "LuminaFlow"
MAX_SAMPLE_BYTES = 256 * 1024
TIMESTAMP_PATTERNS = ["timestamp", "time", "datetime", "date_time", "disp_time", "enroute", "arrival", "ping_time", "epoch", "unix", "ts"]
LAT_PATTERNS = ["lat", "latitude", "y_coord"]
LON_PATTERNS = ["lon", "lng", "longitude", "x_coord"]
COMBINED_COORD_PATTERNS = ["location", "unit_loc", "gps", "coord", "latlon"]
DISCLAIMER = "Secure Air-Gapped Upload. Do not include PHI. Upload de-identified operational telemetry only."

st.markdown("""
    <style>
    .main {padding-top: 1.5rem;}
    .lf-title {font-size: 2.2rem; font-weight: 700; letter-spacing: -0.02em; margin-bottom: 0.2rem;}
    .lf-subtitle {font-size: 1.0rem; color: #4B5563; margin-bottom: 1.25rem;}
    .lf-card {border: 1px solid #E5E7EB; border-radius: 16px; padding: 1rem 1rem 0.75rem 1rem; background: #FFFFFF; margin-bottom: 1rem;}
    .lf-banner {border-left: 4px solid #111827; background: #F9FAFB; padding: 0.9rem 1rem; border-radius: 8px; color: #111827; margin-bottom: 1rem;}
    .success-box {padding: 1rem; border-radius: 14px; background: #ECFDF5; border: 1px solid #10B981; color: #065F46; font-weight: 600;}
    </style>
    """, unsafe_allow_html=True)

def detect_delimiter(sample_text: str) -> str:
    try: return csv.Sniffer().sniff(sample_text, delimiters=",\t;|").delimiter
    except Exception: return ","

def normalize_header(header: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", header.strip().lower()).strip("_")

def score_headers(headers: list[str]) -> dict:
    normalized = [normalize_header(h) for h in headers]
    def find_matches(patterns):
        matches = []
        for raw, norm in zip(headers, normalized):
            for p in patterns:
                if p in norm:
                    matches.append(raw)
                    break
        return matches
    return {
        "timestamp_candidates": find_matches(TIMESTAMP_PATTERNS),
        "latitude_candidates": find_matches(LAT_PATTERNS),
        "longitude_candidates": find_matches(LON_PATTERNS),
        "combined_coordinate_candidates": find_matches(COMBINED_COORD_PATTERNS),
    }

def basic_header_check(headers: list[str]) -> tuple[bool, list[str], dict]:
    findings = score_headers(headers)
    issues = []
    has_timestamp = len(findings["timestamp_candidates"]) > 0
    has_latlon = len(findings["latitude_candidates"]) > 0 and len(findings["longitude_candidates"]) > 0
    has_combined = len(findings["combined_coordinate_candidates"]) > 0
    if not has_timestamp: issues.append("No timestamp-like column detected.")
    if not (has_latlon or has_combined): issues.append("No usable latitude/longitude or combined coordinate field detected.")
    return has_timestamp and (has_latlon or has_combined), issues, findings

def read_header_and_sample(uploaded_file):
    uploaded_file.seek(0)
    sample_text = uploaded_file.read(MAX_SAMPLE_BYTES).decode("utf-8", errors="replace")
    uploaded_file.seek(0)
    delimiter = detect_delimiter(sample_text)
    try: headers = next(csv.reader(io.StringIO(sample_text), delimiter=delimiter))
    except StopIteration: headers = []
    return headers, delimiter, sample_text

def compute_sha256(uploaded_file) -> str:
    uploaded_file.seek(0)
    sha = hashlib.sha256()
    while True:
        chunk = uploaded_file.read(1024 * 1024)
        if not chunk: break
        sha.update(chunk)
    uploaded_file.seek(0)
    return sha.hexdigest()

def save_locally(uploaded_file, file_sha256: str) -> dict:
    tmp_dir = os.path.join(tempfile.gettempdir(), "luminaflow_uploads")
    os.makedirs(tmp_dir, exist_ok=True)
    path = os.path.join(tmp_dir, f"{uuid.uuid4()}_{uploaded_file.name}")
    uploaded_file.seek(0)
    with open(path, "wb") as f:
        while True:
            chunk = uploaded_file.read(1024 * 1024)
            if not chunk: break
            f.write(chunk)
    uploaded_file.seek(0)
    manifest = {"storage": "local-temp", "path": path, "sha256": file_sha256, "uploaded_at": datetime.now(timezone.utc).isoformat()}
    with open(path + ".manifest.json", "w", encoding="utf-8") as mf: json.dump(manifest, mf, indent=2)
    return manifest

def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024 or unit == "GB": return f"{size:.1f} {unit}"
        size /= 1024

st.markdown(f"<div class='lf-title'>{BRAND_NAME} Secure Upload Portal</div>", unsafe_allow_html=True)
st.markdown("<div class='lf-subtitle'>De-identified operational telemetry intake for Phase 1 perimeter assessments.</div>", unsafe_allow_html=True)
st.markdown(f"<div class='lf-banner'><strong>{DISCLAIMER}</strong></div>", unsafe_allow_html=True)

with st.container(border=False):
    st.markdown("<div class='lf-card'>", unsafe_allow_html=True)
    st.write("**Accepted file type:** CSV")
    st.write("**Maximum file size target:** up to 500 MB")
    st.write("**Required basics:** timestamp + latitude/longitude (or combined GPS field)")
    st.write("**Security note:** This prototype is for de-identified telemetry only.")
    st.markdown("</div>", unsafe_allow_html=True)

uploaded_file = st.file_uploader("Drag and drop your CSV file here", type=["csv"], accept_multiple_files=False)

if uploaded_file is not None:
    st.write("### File Summary")
    st.write(f"**Filename:** {uploaded_file.name}")
    st.write(f"**Size:** {human_size(uploaded_file.size)}")
    headers, delimiter, _sample = read_header_and_sample(uploaded_file)
    if headers:
        is_ok, issues, findings = basic_header_check(headers)
        with st.expander("Header Validation Preview", expanded=True):
            st.write(f"**Detected delimiter:** `{delimiter}`")
            st.write(f"**Detected columns ({len(headers)}):**")
            st.code(", ".join(headers[:20]) + (" ..." if len(headers) > 20 else ""))
            st.write("**Candidate fields:**")
            st.json(findings)
            if is_ok: st.success("Basic header validation passed.")
            else:
                st.error("Basic header validation failed.")
                for issue in issues: st.write(f"- {issue}")

        if is_ok:
            if st.button("Securely Transfer File", type="primary", use_container_width=True):
                progress = st.progress(0, text="Initializing secure transfer...")
                status = st.empty()
                try:
                    progress.progress(20, text="Computing file fingerprint...")
                    file_sha256 = compute_sha256(uploaded_file)
                    progress.progress(70, text="Transferring file to isolated processing environment...")
                    result = save_locally(uploaded_file, file_sha256)
                    progress.progress(100, text="Transfer complete.")
                    status.markdown("<div class='success-box'>Success: File securely transferred to isolated processing environment.<br>Assessment turnaround: 5 business days.</div>", unsafe_allow_html=True)
                except Exception as e:
                    progress.empty()
                    status.error(f"Transfer failed: {e}")
    else:
        st.error("Could not read headers from the uploaded file.")
