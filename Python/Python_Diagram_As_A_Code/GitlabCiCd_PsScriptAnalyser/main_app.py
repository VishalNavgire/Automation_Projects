from diagrams import Diagram, Cluster, Edge

# ---------------------------------------------------------
# GitLab / DevOps / Generic Components
# ---------------------------------------------------------
from diagrams.onprem.vcs import Gitlab
from diagrams.onprem.ci import Gitlabci
from diagrams.onprem.client import Users
# from diagrams.programming.language import Powershell, Python
# from diagrams.programming.language import Python
# from diagrams.onprem.inmemory import Redis
from diagrams.generic.storage import Storage
# from diagrams.onprem.monitoring import Grafana
# from diagrams.generic.blank import Blank
# from diagrams.azure.compute import AutomationAccounts
from diagrams.custom import Custom

# ---------------------------------------------------------
# Global Professional Styling
# ---------------------------------------------------------
graph_attr = {
    "fontsize": "24",
    "fontname": "Segoe UI Semibold",
    "bgcolor": "white",
    "pad": "1.8",
    "nodesep": "1.2",
    "ranksep": "1.5",
    "splines": "ortho",
    "dpi": "320",
    "labelloc": "t",
}

node_attr = {
    "shape": "box",
    "style": "rounded,filled",
    "fillcolor": "#F8FAFC",
    "fontname": "Segoe UI",
    "fontsize": "12",
    "margin": "0.45,0.25",
}

edge_attr = {
    "fontname": "Segoe UI Semibold",
    "fontsize": "10",
    "color": "#475569",
    "penwidth": "2.0",
}

# ---------------------------------------------------------
# Diagram
# ---------------------------------------------------------
with Diagram(
    "GitLab CI/CD Pipeline for Intune Azure Automation Runbooks",
    filename="gitlab_ci_cd_runbook_quality_pipeline",
    outformat="jpg",
    direction="LR",
    show=False,
    graph_attr=graph_attr,
    node_attr=node_attr,
    edge_attr=edge_attr,
):

    # =====================================================
    # Engineer / Contributor Tier
    # =====================================================
    # engineers = Users(
    #     "Cloud Engineers\n& Intune Administrators"
    # )

    engineers = Custom(
        "Cloud Engineers\n& Intune Administrators",
        "./icons/Intune_Admin.png"
    )

    # =====================================================
    # GitLab Repository Tier
    # =====================================================
    with Cluster(
        "Protected GitLab Repository",
        graph_attr={
            "bgcolor": "#FFF7ED",
            "color": "#EA580C",
            "margin": "100,60",
        },
    ):

        gitlab_repo = Gitlab(
            "GitLab Repo\n(Intune-Endpoint-Management/Azure Runbooks)"
        )

        # runbooks = Powershell(
        #     "54 Azure Automation\nPowerShell Runbooks"
        # )
        runbooks = Custom(
                "Prod Azure Automation\nPowerShell Runtime",
                "./icons/azure_automation_account_and_runbook.png"
                
            )

        mr = Custom(
            "Merge Request (MR)\nSubmitted to Main Branch",
            "./icons/git_merge_request.png"
        )

    # =====================================================
    # GitLab CI/CD Pipeline Tier
    # =====================================================
    with Cluster(
        "GitLab CI/CD Pipeline",
        graph_attr={
            "bgcolor": "#EFF6FF",
            "color": "#2563EB",
            "margin": "40,40",
        },
    ):

        pipeline = Gitlabci(
            "GitLab Runner Pipeline"
        )

        pssa = Custom(
                "PSScriptAnalyzer\nCode Quality Checks",
                "./icons/PSScriptAnalyzer.png"

            )

        validation = Custom(
            "Validation Stage\nWarnings • Errors • Best Practices", 
            "./icons/Messages.png"
        )

        artifact = Storage(
            "Pipeline Artifacts\nLogs • Reports • Warnings"
        )

    # =====================================================
    # Merge Governance Tier
    # =====================================================
    with Cluster(
        "Automated Governance & Merge Control",
        graph_attr={
            "bgcolor": "#F0FDF4",
            "color": "#16A34A",
            "margin": "20,40",
        },
    ):

        # approval = Custom(
        #     "Auto Approval Logic\nIf Validation Successful", 
        #     "./icons/Approved.png"
        # )

        # merge = Custom(
        #     "Auto Merge into\nProtected Main Branch", 
        #     "./icons/Auto_Merge_Request_Into_Main_Branch.png"
        # )


        approval = Custom(
            "Pipeline Validation\nStatus: PASSED",
            "./icons/Validation_Successful.png"
        )

        reviewer = Users(
            "Approval Required for Merge to complete",
            # "./icons/Human_Approval.png"
        )

        merge = Custom(
            "Manual Merge into\nProtected Main Branch",
            "./icons/Manual_Merge_Into_Protected_Branch.png"
        )
                
        rejection = Custom(
            "MR Rejected\nIf Critical Issues Found",
            "./icons/Rejected.png"
        )

    # =====================================================
    # Monitoring / Visibility Tier
    # =====================================================
    # with Cluster(
    #     "Monitoring & Visibility",
    #     graph_attr={
    #         "bgcolor": "#F8FAFC",
    #         "color": "#475569",
    #     },
    # ):

    #     dashboard = Grafana(
    #         "CI/CD Visibility\nPipeline Status & Reporting"
    #     )

    #     audit = Python(
    #         "Audit & Troubleshooting\nReference Logs"
    #     )

    # =====================================================
    # Flow Connections
    # =====================================================

    # Engineer flow
    engineers >> Edge(
        color="#2563EB",
        label="Push Changes\nRaise Merge Request",
    ) >> gitlab_repo

    gitlab_repo >> runbooks

    runbooks >> Edge(
        color="#EA580C",
        label="Merge Request Trigger",
    ) >> mr

    # Pipeline flow
    mr >> Edge(
        color="#2563EB",
        label="Invoke CI/CD",
    ) >> pipeline

    pipeline >> Edge(
        color="#7C3AED",
        label="Invoke Ps Script Analysis",
    ) >> pssa

    pssa >> Edge(
        color="#DC2626",
        label="Run Analysis",
    ) >> validation

    validation >> Edge(
        color="#D97706",
        label="Store Reports",
    ) >> artifact

    # Success path
    validation >> Edge(
        color="#16A34A",
        label="No Critical Errors",
    ) >> approval

    # approval >> Edge(
    #     color="#16A34A",
    #     label="Merge Allowed",
    # ) >> merge

    approval >> Edge(
        color="#2563EB",
        label="Await Human Approval",
    ) >> reviewer

    reviewer >> Edge(
        color="#16A34A",
        label="Reviewer Approved",
    ) >> merge

    # Failure path
    validation >> Edge(
        color="#DC2626",
        style="dashed",
        label="Critical Warnings\nor Errors",
    ) >> rejection

    # Visibility / Reporting
    # artifact >> Edge(
    #     color="#2563EB",
    #     label="Pipeline Evidence",
    # ) >> dashboard

    # artifact >> Edge(
    #     color="#475569",
    #     style="dotted",
    #     label="Logs & Reports",
    # ) >> audit

print("✔ GitLab CI/CD Architecture Diagram Generated Successfully")