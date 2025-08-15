import streamlit as st
import concurrent.futures
import tempfile
from apk_analysis import decompile_apk
from staticanalysis import find_hardcoded_strings, analyze_permissions, analyze_manifest_exported_components

st.title("DroidInsight - APK Static Analysis")

uploaded_file = st.file_uploader("Upload APK", type=["apk"])

if uploaded_file is not None:
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
        tmp_file.write(uploaded_file.read())
        tmp_path = tmp_file.name

    # Run analysis in a thread for UI responsiveness
    with st.spinner("Analyzing APK..."):
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(decompile_apk, tmp_path)
            try:
                apk_data = future.result(timeout=60)
            except concurrent.futures.TimeoutError:
                st.error("Analysis exceeded 60 seconds; showing basic info only.")
                from apk_analysis import basic_apk_info
                apk_data = basic_apk_info(tmp_path)

    # Handle errors and warnings
    if "error" in apk_data:
        st.error(apk_data["error"])
    else:
        if "warning" in apk_data:
            st.warning(apk_data["warning"])
        st.subheader("APK Info")
        st.write(f"Package: {apk_data['package_name']}")
        st.write(f"Version: {apk_data['version_name']} ({apk_data['version_code']})")

        st.subheader("Permissions")
        st.json(apk_data["permissions"])

        st.subheader("Static Analysis Findings")

        # Permission risk
        risky_perms = analyze_permissions(apk_data["permissions"])
        if risky_perms:
            st.markdown("### ⚠️ Risky Permissions")
            for perm in risky_perms:
                st.write(f"- **{perm['permission']}**: {perm['risk']}")
        else:
            st.write("No risky permissions found.")

        # Manifest export/debug
        manifest_results = analyze_manifest_exported_components(apk_data["manifest_xml"])
        if manifest_results["exported_components"]:
            st.markdown(f"### ⚠️ Exported Components: Found {len(manifest_results['exported_components'])} exported components")
        else:
            st.write("No exported components with android:exported=true found.")

        if manifest_results["debuggable"]:
            st.markdown("### ⚠️ Application is debuggable!")
        else:
            st.write("Application is not debuggable.")

        # Hardcoded strings
        suspicious_strings = find_hardcoded_strings(apk_data["dex_strings"])
        if suspicious_strings:
            st.markdown(f"### ⚠️ Suspicious Hardcoded Strings ({len(suspicious_strings)})")
            for s in suspicious_strings[:20]:  # limit to 20 to avoid flooding UI
                st.write(f"- `{s['string']}` ({s['reason']})")
        else:
            st.write("No suspicious hardcoded strings found.")
