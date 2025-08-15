import streamlit as st
import tempfile
import os
from utils.apk_analysis import analyze_apk

st.set_page_config(page_title="APK Threat Insight", layout="wide")

st.title("📱 APK Threat Insight")
st.markdown("Upload an Android `.apk` file and get a quick threat summary.")

uploaded_file = st.file_uploader("Upload APK", type=["apk"])

if uploaded_file:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_path = tmp_file.name

    with st.spinner("Analyzing APK..."):
        try:
            info, dangerous = analyze_apk(tmp_path)
            st.success("Analysis Complete!")
            
            st.subheader("📋 Basic Info")
            st.json(info)

            st.subheader("🚨 Dangerous Permissions")
            if dangerous:
                st.error(f"⚠️ Found {len(dangerous)} dangerous permissions!")
                for perm in dangerous:
                    st.code(perm)
            else:
                st.success("✅ No dangerous permissions found.")
        except Exception as e:
            st.error(f"Error analyzing APK: {e}")

    os.remove(tmp_path)