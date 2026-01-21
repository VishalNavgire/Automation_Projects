from diagrams import Diagram, Cluster, Edge

from diagrams.azure.compute import FunctionApps
from diagrams.azure.identity import ActiveDirectory
from diagrams.azure.analytics import LogAnalyticsWorkspaces
from diagrams.azure.devops import Devops
from diagrams.azure.monitor import Logs
from diagrams.generic.blank import Blank
from diagrams.onprem.client import Users

# ----------------------------
# Global Styling (Critical)
# ----------------------------
graph_attr = {
    "fontname": "Segoe UI Semibold",
    "fontsize": "22",
    "bgcolor": "white",
    "pad": "0.6",
    "nodesep": "0.9",
    "ranksep": "1.2",
    "splines": "ortho",
    "dpi": "300",
}

node_attr = {
    "fontname": "Segoe UI",
    "fontsize": "12",
    "shape": "box",
    "style": "rounded,filled",
    "fillcolor": "#F8FAFC",
    "margin": "0.25,0.15",
}

edge_attr = {
    "fontname": "Segoe UI Semibold",
    "fontsize": "10",
    "color": "#475569",
}

# ----------------------------
# Diagram
# ----------------------------
with Diagram(
    "Azure Automation Runbook Logging Architecture",
    direction="LR",
    show=False,
    outformat="png",
    filename="azure_automation_runbook_logging_architecture",
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    # Personas / Identity
    engineers = Users("Intune Engineers")
    entra = ActiveDirectory("Microsoft Entra ID\n(Authentication)")

    # =========================
    # Automation Account Tier
    # =========================
    with Cluster(
        "Automation Account",
        graph_attr={"bgcolor": "#E0F2FE", "color": "#0369A1"},
    ):
        runbooks = Devops(
            "Azure Automation Runbooks\n(PowerShell)"
        )

        logger_fn = FunctionApps(
            "Runbook Logger\nAzure Function"
        )

        diag_settings = Logs(
            "Diagnostic Settings\n(Job Logs & Streams)"
        )

    # =========================
    # Secure Ingestion Boundary
    # =========================
    with Cluster(
        "Authentication via Managed Identity",
        graph_attr={"bgcolor": "#F1F5F9", "color": "#334155"},
    ):
        dce = Blank(
            "Data Collection Endpoint (DCE)\nLogs Ingestion API"
        )

        dcr = Blank(
            "Data Collection Rule (DCR)\nSchema Mapping & Routing"
        )

    # =========================
    # Analytics & Consumption
    # =========================
    with Cluster(
        "Analytics & Visualization",
        graph_attr={"bgcolor": "#F0FDF4", "color": "#15803D"},
    ):
        law = LogAnalyticsWorkspaces(
            "Log Analytics Workspace\n(LOG-MEM-WE-P-001)"
        )

        custom_table = Blank(
            "Custom Table\nAzRunbookLogs_CL"
        )

        dashboards = Blank(
            "Workbooks • Alerts • Queries"
        )

    # -------------------------
    # Data Flows
    # -------------------------

    # Custom logs ingestion
    runbooks >> logger_fn

    logger_fn >> Edge(
        color="#2563EB",
        penwidth="2.4",
        label="Logs Ingestion API\n(HTTPS POST)",
    ) >> dce

    dce >> Edge(
        color="#2563EB",
        penwidth="2.2",
        label="Routed per DCR",
    ) >> dcr

    dcr >> Edge(
        color="#2563EB",
        penwidth="2.2",
        label="Mapped to Custom Table",
    ) >> custom_table

    # Diagnostic export path
    runbooks >> Edge(
        color="#D97706",
        penwidth="2.2",
        label="Diagnostic Export",
    ) >> diag_settings

    diag_settings >> Edge(
        color="#D97706",
        penwidth="2.2",
        label="Platform Logs",
    ) >> law

    # Consumption
    custom_table >> Edge(
        color="#16A34A",
        penwidth="2.2",
        label="KQL Queries / Metrics",
    ) >> dashboards

    law >> Edge(
        color="#16A34A",
        style="dashed",
        label="Insights",
    ) >> dashboards

    dashboards >> Edge(
        color="#000000",
        label="Visuals & Alerts",
    ) >> engineers

    # Authentication
    logger_fn >> Edge(
        color="#7C3AED",
        style="dotted",
        label="Managed Identity\nToken Auth",
    ) >> entra

print("✔ Diagram generated successfully")
