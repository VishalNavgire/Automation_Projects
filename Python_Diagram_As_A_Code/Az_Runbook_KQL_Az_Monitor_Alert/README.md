# ☁️ Azure Automation Runbook Logging Architecture

![Azure](https://img.shields.io/badge/azure-%230072C6.svg?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Diagrams](https://img.shields.io/badge/diagrams-as--code-success?style=for-the-badge&logo=github)
![Status](https://img.shields.io/badge/Status-POC-orange?style=for-the-badge)

> **Architecture-as-Code | Azure Monitor | Log Analytics | Logs Ingestion API**
A Python-driven architecture visualization project that demonstrates a **dual-path logging strategy** for Azure Automation Runbooks. This solution combines native **Diagnostic Settings** with **custom structured log ingestion** to deliver enterprise-grade observability, KQL-driven alerting, and automated **Microsoft Teams notifications**.
---

## 📌 Project Purpose

Native Azure Automation logging often faces critical scalability and observability limitations. This project bridges the gap between basic execution logs and enterprise-grade monitoring.

| ❌ Common Challenges | ✅ This Solution Solves |
| :--- | :--- |
| **Unstructured Logs:** "Job Stream" text is messy, difficult to query, and hard to parse. |
| **Schema Rigidity:** Native tables (`AzureDiagnostics`) don't fit specific business reporting needs.
| **Alert Fatigue:** No severity-aware routing; everything is just an "email." | **Smart Routing:** Routes alerts to specific **Teams Channels** (Info, Warn, Error) based on severity. 
|**Zero Trust:** Uses **Managed Identity** for secure authentication across all hops.

---

## 🏗 High-Level Architecture

This solution visualizes three logical operational tiers:

### 🔹 1. Azure Automation Tier
* **Automation Runbooks (PowerShell/Python):** Execute operational workloads on scheduled intervals.
* **Diagnostic Settings:** Automatically forwards Job Logs, Streams, and Metrics to LAW.
* **Notification Runbook:** A specialized runbook triggered by Action Groups to format and send Adaptive Cards to Teams.

### 🔹 2. Monitoring & Alerting Tier
* **Log Analytics Workspace (LAW):** The centralized repository for both Platform and Custom logs.
* **Azure Monitor:** Runs KQL-based alert rules to detect failures, runtime anomalies, or specific business logic triggers.
* **Action Group:** Triggers the Notification Runbook using the standard **Common Alert Schema**.

### 🔹 3. Notification & Consumption Tier
* **Microsoft Teams Channels:** Alerts are routed dynamically:
    * 🟢 `INFO` Channel
    * 🟡 `WARN` Channel
    * 🔴 `ERROR` Channel
    * 🧪 `TEST` Channel
* **Adaptive Cards:** Rich, interactive alert cards for Engineers & Cloud Ops teams.

---

## 🔄 Data Flow Logic

| Path | Purpose | Description | Flow Color |
| :--- | :--- | :--- | :--- |
| **Diagnostic Path** | Standard platform telemetry | Job Streams, Job Status, Metrics → LAW | 🟠 **Orange** |
| **Alerting Path** | Real-time detection & notifications | LAW → Azure Monitor → Action Group → Runbook → Teams | 🔵 **Blue** |

---

## 🖼 Architecture Diagram Output

> 📌 **Note:** Run the included Python script to automatically generate this high-resolution diagram.

**Diagram File Generated:** `azure_automation_teams_alerts.png`

![Azure Automation Architecture](azure_automation_teams_alerts.png)

*(If the image does not render, ensure the script has been run and the file exists in the directory)*
---

## 📦 Technologies Used

* **Cloud Platform:** Microsoft Azure Automation, Azure Monitor, Log Analytics, Action Groups
* **Identity:** Microsoft Entra ID (Managed Identity)
* **Collaboration:** Microsoft Teams (Webhooks + Adaptive Cards)
* **Development:** Python 3.x
* **Libraries:** `diagrams` (Graphviz-based)
* **Rendering:** Graphviz Engine

---
## 🧠 What This Demonstrates

This project serves as a technical showcase for:
* ✅ **Azure Observability Design:** Moving beyond default logs to custom telemetry.
* ✅ **Secure Alerting Pipelines:** Using Managed Identities instead of shared keys.
* ✅ **KQL-Driven Detection:** leveraging Azure Monitor's query language for logic.
* ✅ **Real-world Automation:** Solving the "Alert Fatigue" problem with severity-based routing.
---
## 👤 Author
Vishal Navgire
Cloud & Endpoint Automation Engineer
