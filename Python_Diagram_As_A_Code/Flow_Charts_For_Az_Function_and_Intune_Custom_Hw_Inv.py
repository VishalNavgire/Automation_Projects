from diagrams import Diagram, Cluster, Edge

# --- Icons / Nodes ---
from diagrams.azure.compute import CloudServices, FunctionApps
from diagrams.azure.identity import ActiveDirectory, ManagedIdentities
from diagrams.azure.monitor import LogAnalyticsWorkspaces
from diagrams.generic.os import Windows
from diagrams.azure.general import Powershell

graph_attr = {
    "splines": "ortho",
    "pad": "0.6",                
    "nodesep": "0.8",            
    "ranksep": "1.0",            
    "fontname": "Segoe UI Semibold",
    "fontsize": "24",            
    "bgcolor": "white",
    "dpi": "300",                
    "compound": "true",
}

node_attr = {
    "fontname": "Segoe UI",
    "fontsize": "13",
    "shape": "box",
    "style": "rounded,filled",
    "fillcolor": "#F8FAFC",      
}

edge_attr = {
    "fontname": "Segoe UI Semibold",
    "fontsize": "11",
    "color": "#475569",          
}

# ----------------------------
# Diagram Construction
# ----------------------------

with Diagram(
    "Secured Intune Custom Inventory Pipeline",
    direction="LR",
    show=False,
    filename="secured_intune_custom_inventory_pipeline",
    outformat="png", 
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    # =========================
    # Tier 1: Intune & Endpoint
    # =========================
    with Cluster("1. Endpoint Collection Tier", graph_attr={"bgcolor": "#E0F2FE", "color": "#0369A1"}):
        intune_cloud = CloudServices("Microsoft Intune\n(Policy Engine)")
        win_device = Windows("Windows Managed\nEndpoint")

        remediation = Powershell(
            "Remediation Script\n(Inventory Collection)"
        )
        intune_cloud >> Edge(style="dashed", color="#0369A1", label="Deploy Script") >> win_device
        win_device >> Edge(color="#0284C7", penwidth="2.5", label="[1] Run Script") >> remediation

    # =========================
    # Tier 2: Security & Logic
    # =========================
    with Cluster("2. Azure Security Boundary", graph_attr={"bgcolor": "#F1F5F9", "color": "#334155"}):
        func = FunctionApps("Azure Function\n(Logic & Validation)")

        entra = ActiveDirectory(
            "Microsoft Entra ID\n(Identity Verification)"
        )

        mi = ManagedIdentities(
            "System-Assigned\nManaged Identity"
        )

    # =========================
    # Tier 3: Data Destination
    # =========================
    with Cluster("3. Analytics Tier", graph_attr={"bgcolor": "#F0FDF4", "color": "#15803D"}):
        law = LogAnalyticsWorkspaces(
            "Log Analytics\n(Custom Inventory Table)"
        )

    # --- Flow Logic with Step Numbers ---
    
    # Step 2: Device to Function
    remediation >> Edge(
        color="#2563EB", penwidth="2.5", label="[2] POST JSON Payload"
    ) >> func

    # Step 3: Function to Entra (The Check)
    func >> Edge(
        color="#D97706", penwidth="2.5", label="[3] Verify Device/Tenant"
    ) >> entra

    # Internal Relationship: Function "is" the Identity
    func - Edge(style="dotted", color="#64748B", label="Authenticated as") - mi

    # Step 4: Function to Log Analytics
    func >> Edge(
        color="#16A34A", penwidth="2.5", label="[4] Ingest via Managed Identity"
    ) >> law

print("Image generated successfully. Check your folder for 'Secured_Intune_Managed_Win_Device_Custom_Inv.png'")
