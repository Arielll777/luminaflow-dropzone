import os
import re
import random
from datetime import datetime

import pandas as pd
import requests
import streamlit as st


# -----------------------------
# Page configuration
# -----------------------------
st.set_page_config(
    page_title="VitalSeconds Telemetry Dropzone",
    page_icon="📊",
    layout="wide"
)


# -----------------------------
# Hide Streamlit chrome where possible
# -----------------------------
st.markdown(
    """
    <style>
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        header {visibility: hidden;}

        [data-testid="stToolbar"] {
            visibility: hidden;
            height: 0%;
            position: fixed;
        }

        [data-testid="stDecoration"] {
            display: none;
        }

        [data-testid="stStatusWidget"] {
            visibility: hidden;
        }

        .block-container {
            padding-top: 3rem;
            padding-bottom: 3rem;
            max-width: 1280px;
        }

        .vs-hero {
            padding: 1.25rem 0 1.5rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.16);
            margin-bottom: 1.5rem;
        }

        .vs-title {
            font-size: 2.4rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            margin-bottom: 0.4rem;
        }

        .vs-subtitle {
            font-size: 1.05rem;
            color: rgba(255,255,255,0.72);
            max-width: 880px;
        }

        .vs-trust-row {
            display: flex;
            gap: 0.75rem;
            flex-wrap: wrap;
            margin-top: 1rem;
        }

        .vs-pill {
            border: 1px solid rgba(255,255,255,0.18);
            border-radius: 999px;
            padding: 0.35rem 0.75rem;
            color: rgba(255,255,255,0.82);
            font-size: 0.86rem;
            background: rgba(255,255,255,0.04);
        }

        .vs-empty-card {
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.045);
            border-radius: 14px;
            padding: 1.1rem 1.2rem;
            margin-top: 1rem;
        }

        .vs-empty-title {
            font-size: 1.05rem;
            font-weight: 700;
            margin-bottom: 0.3rem;
        }

        .vs-empty-text {
            color: rgba(255,255,255,0.68);
            font-size: 0.95rem;
        }

        .vs-small-note {
            color: rgba(255,255,255,0.62);
            font-size: 0.9rem;
        }
    </style>
    """,
    unsafe_allow_html=True
)


# -----------------------------
# Helper functions
# -----------------------------
def normalize_column_name(col: str) -> str:
    """
    Converts messy column names into a normalized format.
    Example: ' GPS Latitude ' -> 'gpslatitude'
    """
    return re.sub(r"[^a-z0-9]", "", str(col).strip().lower())


def detect_coordinate_columns(df: pd.DataFrame):
    """
    Attempts to identify latitude and longitude columns even when headers are messy.
    """
    normalized = {normalize_column_name(col): col for col in df.columns}

    latitude_candidates = [
        "latitude",
        "lat",
        "gpslat",
        "gpslatitude",
        "vehiclelat",
        "vehiclelatitude",
        "ambulancelat",
        "ambulancelatitude",
        "unitlat",
        "unitlatitude",
        "y",
    ]

    longitude_candidates = [
        "longitude",
        "long",
        "lon",
        "lng",
        "gpslon",
        "gpslng",
        "gpslongitude",
        "vehiclelon",
        "vehiclelng",
        "vehiclelongitude",
        "ambulancelon",
        "ambulancelng",
        "ambulancelongitude",
        "unitlon",
        "unitlng",
        "unitlongitude",
        "x",
    ]

    lat_col = None
    lon_col = None

    for candidate in latitude_candidates:
        if candidate in normalized:
            lat_col = normalized[candidate]
            break

    for candidate in longitude_candidates:
        if candidate in normalized:
            lon_col = normalized[candidate]
            break

    return lat_col, lon_col


def build_map_dataframe(df: pd.DataFrame):
    """
    Creates a map-ready dataframe.

    If valid latitude/longitude are present, use real coordinates.
    If missing, generate synthetic NY-area demo points for visualization only.
    """
    lat_col, lon_col = detect_coordinate_columns(df)

    if lat_col and lon_col:
        map_df = df.copy()
        map_df["latitude"] = pd.to_numeric(map_df[lat_col], errors="coerce")
        map_df["longitude"] = pd.to_numeric(map_df[lon_col], errors="coerce")

        map_df = map_df.dropna(subset=["latitude", "longitude"])

        map_df = map_df[
            (map_df["latitude"].between(-90, 90)) &
            (map_df["longitude"].between(-180, 180))
        ]

        if not map_df.empty:
            return map_df, True, lat_col, lon_col

    demo_df = df.copy()

    # Demo visualization points around NYC.
    demo_df["latitude"] = [random.uniform(40.71, 40.78) for _ in range(len(demo_df))]
    demo_df["longitude"] = [random.uniform(-74.01, -73.95) for _ in range(len(demo_df))]

    return demo_df, False, None, None


def get_zapier_webhook_url():
    """
    Recommended: store your webhook in Streamlit Secrets as:
    ZAPIER_WEBHOOK_URL = "your webhook here"

    For quick local testing, you can also set it as an environment variable.
    """
    try:
        return st.secrets.get("ZAPIER_WEBHOOK_URL", "")
    except Exception:
        return os.getenv("ZAPIER_WEBHOOK_URL", "")


# -----------------------------
# Header
# -----------------------------
st.markdown(
    """
    <div class="vs-hero">
        <div class="vs-title">📊 VitalSeconds Telemetry Dropzone</div>
        <div class="vs-subtitle">
            Secure CSV intake for ambulance telemetry, perimeter movement preview,
            and downstream operational analysis.
        </div>
        <div class="vs-trust-row">
            <div class="vs-pill">No EMR access required</div>
            <div class="vs-pill">No PHI required</div>
            <div class="vs-pill">No production IT integration</div>
            <div class="vs-pill">CSV-based intake</div>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)


# -----------------------------
# File uploader
# -----------------------------
uploaded_file = st.file_uploader(
    "Upload telemetry CSV file",
    type=["csv"],
    help="Upload a CSV containing ambulance telemetry, route data, timestamps, or operational records."
)


# -----------------------------
# Main application logic
# -----------------------------
if uploaded_file is not None:
    try:
        raw_df = pd.read_csv(uploaded_file)

        st.success("✅ File uploaded successfully. Telemetry intake initialized.")

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Rows detected", f"{len(raw_df):,}")
        with col2:
            st.metric("Columns detected", f"{len(raw_df.columns):,}")
        with col3:
            st.metric("File type", "CSV")

        st.subheader("📋 Data Preview")
        st.caption("First 10 rows from the uploaded file.")
        st.dataframe(raw_df.head(10), use_container_width=True)

        st.subheader("📍 Perimeter Movement Preview")

        map_df, real_coordinates_detected, lat_col, lon_col = build_map_dataframe(raw_df)

        if real_coordinates_detected:
            st.success(
                f"✅ Coordinate columns detected: `{lat_col}` and `{lon_col}`. "
                "Rendering actual uploaded location data."
            )
        else:
            st.warning(
                "⚠️ No valid latitude/longitude columns were detected. "
                "Displaying demo visualization mode using synthetic New York-area points. "
                "These points are for interface preview only and are not treated as real telemetry."
            )

        st.map(map_df[["latitude", "longitude"]], use_container_width=True)

        st.divider()

        st.subheader("🚀 Submit for Full Perimeter Analysis")
        st.info(
            "Submit the uploaded dataset to the VitalSeconds intake pipeline. "
            "The file will be routed for downstream perimeter analysis and secure storage."
        )

        submit_disabled = raw_df.empty

        if st.button(
            "Submit for Full Perimeter Analysis",
            type="primary",
            disabled=submit_disabled
        ):
            zapier_url = get_zapier_webhook_url()

            if not zapier_url:
                st.error(
                    "Zapier webhook is not configured. Add `ZAPIER_WEBHOOK_URL` "
                    "to Streamlit Secrets or your environment variables."
                )
            else:
                metadata = {
                    "source": "VitalSeconds Telemetry Dropzone",
                    "submitted_at_utc": datetime.utcnow().isoformat(),
                    "file_name": uploaded_file.name,
                    "row_count": len(raw_df),
                    "column_count": len(raw_df.columns),
                    "columns": list(raw_df.columns),
                    "real_coordinates_detected": real_coordinates_detected,
                    "latitude_column": lat_col,
                    "longitude_column": lon_col,
                    "visualization_mode": (
                        "actual_uploaded_coordinates"
                        if real_coordinates_detected
                        else "demo_visualization_only"
                    ),
                }

                payload = {
                    "metadata": metadata,
                    "data": raw_df.to_dict(orient="records"),
                }

                with st.spinner("Routing dataset through the VitalSeconds perimeter pipeline..."):
                    try:
                        response = requests.post(
                            zapier_url,
                            json=payload,
                            timeout=15
                        )

                        if response.status_code == 200:
                            st.success(
                                "✅ Dataset transmitted successfully. "
                                "Payload captured by the intake pipeline."
                            )
                            st.balloons()
                        else:
                            st.error(
                                f"Pipeline returned error code {response.status_code}. "
                                "Please retry or verify the Zapier webhook."
                            )

                    except Exception as e:
                        st.error(
                            f"Communication failure with intake endpoint: {str(e)}"
                        )

    except Exception as e:
        st.error(
            f"Error parsing the file. Please confirm it is a valid CSV. Details: {str(e)}"
        )

else:
    st.markdown(
        """
        <div class="vs-empty-card">
            <div class="vs-empty-title">Awaiting telemetry file</div>
            <div class="vs-empty-text">
                Upload a CSV to initialize the perimeter movement preview.
                Files with latitude and longitude will render actual location data.
                Files without coordinates will enter clearly labeled demo visualization mode.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    st.info("📥 Ready for CSV upload.")
