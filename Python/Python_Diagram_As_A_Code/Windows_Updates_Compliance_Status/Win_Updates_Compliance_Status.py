from diagrams import Diagram, Cluster, Edge
from urllib.request import urlretrieve
import os

# --- Reliable Standard Imports ---
# These are core nodes that exist in almost all versions
from diagrams.azure.identity import ActiveDirectory
from diagrams.onprem.client import User
from diagrams.programming.language import Python
from diagrams.generic.storage import Storage
from diagrams.onprem.network import Internet
from diagrams.custom import Custom 

# ----------------------------
# Icon Setup (The Fix)
# ----------------------------
# We download official icons to avoid "ImportError" on specific library versions
icon_urls = {
    "intune": "https://upload.wikimedia.org/wikipedia/commons/thumb/2/24/Microsoft_Intune_Icon.png/240px-Microsoft_Intune_Icon.png",
    "autopilot": "https://upload.wikimedia.org/wikipedia/commons/f/f6/Windows_Autopilot_Icon.png",
    "entra_device": "https://upload.wikimedia.org/wikipedia/commons/thumb/3/36/Windows_Settings_app_icon.png/240px-Windows_Settings_app_icon.png"
}

# Download icons if they don't exist
for name, url in icon_urls.items():
    if not os.path.exists(f"{name}.png"):
        try:
            urlretrieve(url, f"{name}.png")
        except:
            print(f"Warning: Could not download {name} icon. Using default url {url}.")

# ----------------------------
# Global Styling
# ----------------------------
graph_attr = {
    "fontname": "Sans-Serif",
    "fontsize": "20",
    "bgcolor": "white",
    "pad": "0.6",
    "nodesep": "1.0",
    "ranksep": "1.2",
    "splines": "ortho",
    "dpi": "300",
}

node_attr = {
    "fontname": "Sans-Serif",
    "fontsize": "12",
    "shape": "box",
    "style": "rounded,filled",
    "fillcolor": "#F8FAFC",
}

edge_attr = {
    "fontname": "Sans-Serif",
    "fontsize": "10",
    "color": "#475569",
}

# ----------------------------
# Diagram Construction
# ----------------------------
with Diagram(
    "Windows Security Dashboard Architecture",
    direction="LR",
    show=False,
    outformat="png",
    filename="windows_security_dashboard_arch",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    # 1. The Operator
    admin = User("IT Engineer\n(Credentials)")

    # 2. Microsoft Cloud Tier (Data Sources)
    with Cluster("Microsoft Cloud Data Sources", graph_attr={"bgcolor": "#E0F2FE", "color": "#0369A1"}):
        
        entra_auth = ActiveDirectory("MS Entra ID\n(Auth & Token)")
        
        with Cluster("Graph API Data"):
            # Using Custom Nodes for reliability
            entra_devices = Custom("Entra Registered\nDevices", "entra_device.png")
            intune = Custom("Intune Managed\nDevices", "intune.png")
            autopilot = Custom("Windows Autopilot\n(Identities)", "autopilot.png")

    # 3. Public Web Tier
    with Cluster("Public Internet", graph_attr={"bgcolor": "#F3F4F6", "color": "#9CA3AF"}):
        ms_learn = Internet("Windows 11 Release\nHealth Blog")

    # 4. Local Execution Environment (Your Fedora Device)
    with Cluster("Local Execution", graph_attr={"bgcolor": "#F0FDF4", "color": "#16A34A"}):
        
        app_script = Python("Dashboard_Tenant_Windows_Sec.py\n(Streamlit App)")
        
        # Local Cache
        local_cache = Storage("Local Cache\n(Parquet & Delta Tokens)")
        
        # The Output (Self-referencing the Python icon as the UI representation)
        dashboard_ui = Custom("Interactive\nDashboard", "intune.png") 

    # ----------------------------
    # Data Flows (Edges)
    # ----------------------------

    # Authentication Flow
    admin >> Edge(label="Interactive Login", color="#D97706") >> app_script
    app_script >> Edge(label="Acquire Token (MSAL)", style="dashed", color="#D97706") >> entra_auth
    entra_auth >> Edge(label="Access Token", style="dashed", color="#D97706") >> app_script

    # Data Ingestion Flow (Parallel)
    # Note: Connecting all sources to the script
    intune >> Edge(color="#2563EB") >> app_script
    entra_devices >> Edge(color="#2563EB") >> app_script
    autopilot >> Edge(color="#2563EB") >> app_script

    # Web Scraping Flow
    ms_learn >> Edge(label="Web Scrape\n(BeautifulSoup)", color="#9333EA") >> app_script

    # Caching Logic
    app_script >> Edge(label="Read/Write\n(Self-Healing)", color="#16A34A") >> local_cache

    # Visualization
    app_script >> Edge(label="Render UI", penwidth="2.0") >> dashboard_ui

print("✔ Diagram generated successfully: windows_security_dashboard_arch.png")