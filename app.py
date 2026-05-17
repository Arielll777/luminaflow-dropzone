import streamlit as st
import pandas as pd
import requests

# Page configuration
st.set_page_config(page_title="VitalSeconds - Data Analysis", layout="wide")

# Main Title
st.title("📊 VitalSeconds - Data Analysis System")
st.markdown("---")

# File Uploader Section
uploaded_file = st.file_uploader(
    "Drag and drop your CSV file here or click to browse", 
    type=["csv"],
    help="Please upload a valid CSV data file only"
)

if uploaded_file is not None:
    try:
        # Read the uploaded CSV data
        df = pd.read_csv(uploaded_file)
        
        st.success("✅ File uploaded and read successfully!")
        
        # Display Data Preview
        st.subheader("📋 Data Preview")
        st.dataframe(df.head(10))
        st.subheader("📍 Live Perimeter Map")
        import random
        # יצירת קואורדינטות אוטומטיות לדמו באזור ניו יורק אם חסר בקובץ
        if 'latitude' not in df.columns:
            df['latitude'] = [random.uniform(40.71, 40.78) for _ in range(len(df))]
            df['longitude'] = [random.uniform(-74.01, -73.95) for _ in range(len(df))]
        
        st.map(df)
        st.divider()
        st.markdown("---")
        st.subheader("🚀 Trigger Automation Pipeline")
        st.info("Click the button below to route the complete dataset to the Zapier automation workflow.")

        # Submit Button
        if st.button("🚀 Submit for Full Perimeter Analysis", type="primary"):
            # Secret Zapier Webhook URL
            zapier_url = "https://hooks.zapier.com/hooks/catch/27629842/4obg4m8/"
            
            # Convert DataFrame to records payload
            payload = df.to_dict(orient="records")
            
            with st.spinner("Routing data securely through the perimeter pipeline..."):
                try:
                    # Execute the post request
                    response = requests.post(zapier_url, json={"data": payload}, timeout=10)
                    
                    if response.status_code == 200:
                        st.success("🎉 Data transmitted successfully! Payload captured by Zapier.")
                        st.balloons()  # Celebration balloons animation
                    else:
                        st.error(f"❌ Server responded with an error code: {response.status_code}. Please retry.")
                except Exception as e:
                    st.error(f"❌ Communication failure with Zapier endpoint: {str(e)}")
                    
    except Exception as e:
        st.error(f"❌ Error parsing the file. Ensure it is a valid CSV. Details: {str(e)}")

else:
    st.warning("📥 Awaiting CSV file upload to initialize perimeter mapping...")