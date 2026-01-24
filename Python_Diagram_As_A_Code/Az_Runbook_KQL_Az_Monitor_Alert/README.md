☁️ Azure Automation Runbook Logging Architecture

Architecture-as-Code | Azure Monitor | Log Analytics | Logs Ingestion API

A Python-driven architecture visualization project that demonstrates a dual-path logging strategy for Azure Automation Runbooks — combining native Diagnostic Settings with custom structured log ingestion to deliver enterprise-grade observability, alerting, and Teams-based notifications.

📌 Run the script to automatically generate a high-quality architecture diagram image

🎯 Project Purpose

Native Azure Automation logging often faces key limitations:

❌ Common Challenges

Unstructured logs — difficult to query and analyze

Schema rigidity — native tables don’t always fit business needs

Limited alert routing — lack of severity-aware notification paths

✅ This Project Solves

Structured log ingestion using DCR + Logs Ingestion API

Secure authentication using Managed Identity

Severity-based alert routing to Microsoft Teams

Full observability across Automation → LAW → Azure Monitor → Action Group → Teams

🏗 High-Level Architecture Overview

This solution visualizes three logical tiers:

🔹 1. Azure Automation Tier

Automation Runbooks (PowerShell / Python)
Execute operational workloads on scheduled intervals

Diagnostic Settings
Forward Job Logs, Job Streams, and Metrics to LAW

Notification Runbook
Triggered by Azure Monitor Action Group to send Teams alerts

🔹 2. Monitoring & Alerting Tier

Log Analytics Workspace (LAW)
Centralized log repository

Azure Monitor (KQL-based Alerts)
Detects failures, warnings, and runtime anomalies

Action Group
Triggers Notification Runbook using Common Alert Schema

🔹 3. Notification & Consumption Tier

Microsoft Teams Channels

INFO

WARN

ERROR

TEST

Adaptive Cards routed dynamically based on alert severity

Engineers / Cloud Ops Teams consume actionable alerts

🔄 Data Flow Logic
Path	Purpose	Description	Flow Color
Diagnostic Path	Standard platform telemetry	Job Streams, Job Status, Metrics → LAW	🟠 Orange
Alerting Path	Real-time detection & notifications	LAW → Azure Monitor → Action Group → Runbook → Teams	🔵 Blue
🖼 Architecture Diagram Output

The Python script generates a high-resolution enterprise-grade PNG diagram that visually explains the entire flow.

Diagram File Generated:

azure_automation_teams_alerts_HQ.png

📦 Technologies Used

Microsoft Azure Automation

Azure Monitor

Azure Log Analytics Workspace (LAW)

Azure Action Groups

Microsoft Entra ID (Managed Identity)

Microsoft Teams (Adaptive Cards + Webhooks)

Python

diagrams (Graphviz-based)

Graphviz (Rendering Engine)

🚀 Getting Started
🔹 Prerequisites

Python 3.x

Graphviz (System Dependency)

Virtual Environment (Recommended)

🔹 Install Graphviz

Fedora

sudo dnf install graphviz


Ubuntu

sudo apt install graphviz


Windows

choco install graphviz

🔹 Clone Repository
git clone https://github.com/YourUsername/Azure-Automation-Logging.git
cd Azure-Automation-Logging

🔹 Create Virtual Environment & Install Dependencies
python -m venv venv
source venv/bin/activate
pip install diagrams

🔹 Generate Architecture Diagram
python Azure_Automation_Runbook_Logging_Architecture_v1.py

🧠 What This Demonstrates

✅ Azure Automation observability design
✅ Enterprise monitoring pipelines
✅ Secure alerting using Managed Identity
✅ KQL-driven detection logic
✅ Adaptive Card routing to Teams
✅ Architecture-as-Code best practices
✅ Real-world cloud automation workflows

🎯 Ideal For

Azure Architect Interviews

Automation Engineer Portfolios

GitHub Technical Showcase

LinkedIn Architecture Posts

Enterprise Solution Documentation

Microsoft Cloud Design Demonstrations

🚀 Future Enhancements

Payload schema validation

Device compliance enforcement before ingestion

Support for multiple inventory schemas

Azure Monitor Data Collection Rules (DCR) integration

KQL dashboards for inventory visualization

Live Azure API telemetry ingestion

ARM/Bicep deployment automation

👤 Author

Vishal Navgire
Cloud & Endpoint Automation Engineer
Azure | Intune | Automation | PowerShell | Python
