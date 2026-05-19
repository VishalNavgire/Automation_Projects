# 🚀 GitLab CI/CD Pipeline Governance for Azure Automation Runbooks

![GitLab](https://img.shields.io/badge/GitLab-CI%2FCD-FC6D26?style=for-the-badge&logo=gitlab&logoColor=white)
![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Diagrams](https://img.shields.io/badge/Diagrams-as--Code-success?style=for-the-badge&logo=github)
![Graphviz](https://img.shields.io/badge/Graphviz-Visualization-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Enterprise%20POC-orange?style=for-the-badge)

> **Architecture-as-Code | GitLab Governance | PSScriptAnalyzer | Protected Branch Approval | HITL (Human-In-The-Loop)**

A professional Python-driven **Diagram-as-Code** project that demonstrates an enterprise-grade **GitLab CI/CD governance pipeline** for Azure Automation PowerShell Runbooks.

This project showcases how organizations can implement:

- Protected branch governance
- Human-In-The-Loop (HITL) approvals
- PowerShell code quality validation
- Merge Request review workflows
- Automated validation pipelines
- Secure production merge controls

using Python, Graphviz, and enterprise architecture visualization principles.

---

# 📌 Project Purpose

Enterprise automation repositories require strong governance and quality validation before production deployment.

This project demonstrates a realistic CI/CD governance workflow where:

- Engineers submit Merge Requests
- GitLab pipelines validate PowerShell code
- PSScriptAnalyzer enforces standards
- Pipeline artifacts store evidence and reports
- Human reviewers manually approve production merges
- Protected branches remain secured

---

# ✅ Key Features

| Capability | Description |
|---|---|
| 🔐 Protected Branch Governance | Prevents unauthorized production merges |
| 👨‍💻 HITL Approval | Human approval required before merge completion |
| 🧪 PSScriptAnalyzer Validation | Automated PowerShell code quality checks |
| 📦 Pipeline Artifact Storage | Stores warnings, logs, and validation evidence |
| 🎨 Diagram-as-Code | Entire architecture generated using Python |
| 🏗 Enterprise Visualization | Professional clusters, icons, and governance flows |
| 🔄 CI/CD Workflow Modeling | Realistic DevOps merge governance pipeline |

---

# 🏗 High-Level Architecture

This project visualizes four enterprise operational tiers.

---

## 🔹 1. Engineer / Contributor Tier

### Components
- Cloud Engineers
- Intune Administrators
- Merge Request Contributors

### Responsibilities
- Push code changes
- Submit Merge Requests
- Contribute Azure Automation Runbooks

---

## 🔹 2. Protected GitLab Repository Tier

### Components
- GitLab Repository
- Azure Automation Runbooks
- Merge Request Governance

### Responsibilities
- Secure source control
- Protected branch enforcement
- Merge Request validation trigger

---

## 🔹 3. GitLab CI/CD Pipeline Tier

### Components
- GitLab Runner Pipeline
- PSScriptAnalyzer
- Validation Stage
- Artifact Storage

### Responsibilities
- Static PowerShell code analysis
- Detect warnings/errors
- Store validation reports
- Generate governance evidence

---

## 🔹 4. Governance & Protected Branch Approval Tier

### Components
- Validation Success State
- Human Reviewer Approval (HITL)
- Manual Protected Branch Merge
- Merge Rejection Logic

### Responsibilities
- Human approval enforcement
- Manual production merge governance
- Critical validation rejection handling

---

# 🔄 Pipeline Workflow Logic

| Workflow Stage | Purpose |
|---|---|
| Engineer → GitLab Repo | Push automation changes |
| GitLab Repo → Merge Request | Trigger governance workflow |
| Merge Request → CI/CD Pipeline | Start validation pipeline |
| Pipeline → PSScriptAnalyzer | Run PowerShell analysis |
| Validation → Artifacts | Store reports and warnings |
| Validation PASSED → HITL Reviewer | Await manual approval |
| Reviewer Approved → Manual Merge | Merge into protected branch |
| Validation FAILED → Rejection | Reject Merge Request |

---

# 🖼 Architecture Diagram Output

> 📌 Run the included Python script to generate the high-resolution architecture diagram automatically.

### Generated File

```bash
gitlab_ci_cd_runbook_quality_pipeline.jpg
```

### Example

```markdown
gitlab_ci_cd_runbook_quality_pipeline.jpg
```

---

# 📂 Project Structure

```bash
GitlabCiCd_PsScriptAnalyser/
│
├── icons/
│   ├── Intune_Admin.png
│   ├── git_merge_request.png
│   ├── azure_automation_account_and_runbook.png
│   ├── PSScriptAnalyzer.png
│   ├── Messages.png
│   ├── Validation_Successful.png
│   ├── Manual_Merge_Into_Protected_Branch.png
│   ├── Rejected.png
│   └── ...
│
├── main_app.py
├── gitlab_ci_cd_runbook_quality_pipeline.jpg
├── .gitignore
├── README.md
└── venv/
```

---

# 📦 Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.x | Diagram generation |
| Diagrams Library | Architecture-as-Code |
| Graphviz | Rendering engine |
| GitLab CI/CD | Pipeline orchestration |
| PowerShell | Runtime for Azure Automation Runbooks |
| PSScriptAnalyzer | Static code analysis |
| Custom PNG Icons | Enterprise visualization |

---

# ⚙️ Prerequisites

Before running the project, install:

- Python 3.10+
- Graphviz
- pip
- Virtual Environment support

---

# 🐧 Fedora / Linux Setup

## 🔹 Step 1 — Install Graphviz

```bash
sudo dnf install graphviz -y
```

Verify installation:

```bash
dot -V
```

---

## 🔹 Step 2 — Create Virtual Environment

```bash
python3 -m venv venv
```

Activate virtual environment:

```bash
source venv/bin/activate
```

---

## 🔹 Step 3 — Install Python Packages

```bash
pip install diagrams
```

Optional:

```bash
pip install pillow
```

---


# ▶️ Running the Application

Execute:

```bash
python3 main_app.py
```

Expected output:

```bash
✔ GitLab CI/CD Architecture Diagram Generated Successfully
```

---

# 👨‍💻 Human-In-The-Loop (HITL) Governance

One major enhancement in this architecture is the introduction of:

## ✅ Manual Protected Branch Approval

Instead of fully automated merges:

```text
Validation → Auto Merge
```

this architecture enforces:

```text
Validation → Human Approval → Manual Protected Branch Merge
```

### Benefits

- Better production governance
- Reduced deployment risk
- Segregation of duties
- Compliance readiness
- Enterprise security alignment

This mirrors real-world enterprise DevOps governance models.

---

# 🧠 What This Project Demonstrates

This project serves as a practical showcase for:

- Diagram-as-Code Engineering
- Enterprise CI/CD Governance
- Protected Branch Security
- GitLab Merge Request Workflows
- HITL Approval Architecture
- PowerShell Quality Enforcement
---

# ⚠️ Common Errors

---

## ❌ Graphviz Not Installed

### Error

```bash
ExecutableNotFound: failed to execute ['dot']
```

### Fix

```bash
sudo dnf install graphviz -y
```

---

## ❌ Missing PNG Icons

### Error

```bash
FileNotFoundError
```

### Fix

- Ensure PNG files exist in `./icons/`
- Verify filenames exactly match Python code

---

# 👨‍💻 Author

### Vishal Navgire

Cloud & Endpoint Automation Engineer

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge\&logo=microsoftazure\&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge\&logo=microsoft\&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge\&logo=python\&logoColor=ffdd54)