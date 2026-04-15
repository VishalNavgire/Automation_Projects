import streamlit as st
import pandas as pd
from main import DCHealthCheckApp # Assuming your logic is in main_script.py

st.set_page_config(page_title="AD Health Dashboard", layout="wide")

st.title("🛡️ Active Directory Health Monitor")

if st.button('Run Diagnostic Now'):
    app = DCHealthCheckApp()
    app.run() # This populates app.summary and app.parsed_data
    
    # --- Top Row: Metrics ---
    cols = st.columns(len(app.summary))
    for idx, (server, stats) in enumerate(app.summary.items()):
        with cols[idx]:
            color = "normal" if stats["Health"] == "Healthy" else "inverse"
            st.metric(label=f"Server: {server}", value=stats["Health"], 
                      delta=f"{stats['Passed']} Passed / {stats['Failed']} Failed",
                      delta_color=color)

    # --- Bottom Row: Detailed Table ---
    st.subheader("Detailed Test Results")
    
    # Convert nested dict to a flat list for Pandas
    flattened_data = []
    for server, tests in app.parsed_data.items():
        for test_name, result in tests.items():
            flattened_data.append({
                "Server": server,
                "Test Name": test_name,
                "Result": result
            })
    
    df = pd.DataFrame(flattened_data)
    st.dataframe(df, use_container_width=True)