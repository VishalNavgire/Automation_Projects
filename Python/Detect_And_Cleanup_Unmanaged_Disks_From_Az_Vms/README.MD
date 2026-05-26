<div align="center">

# 🧹 Azure Managed Disk Cleanup Python Automation

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Azure](https://img.shields.io/badge/Azure-SDK-0072C6?logo=microsoftazure&logoColor=white)](https://azure.microsoft.com/)
[![Automation](https://img.shields.io/badge/Automation-Disk--Cleanup-green)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**A professional-grade, cross-platform Azure automation utility designed to identify and remove orphaned Managed Disks, helping optimize cloud storage costs and maintain infrastructure hygiene.**

[Overview](#-overview) • [Business Value](#-business-value) • [Key Features](#-key-features) • [Architecture](#-architecture) • [Prerequisites](#-prerequisites) • [Execution Guide](#-execution-guide) • [Author](#-author)

</div>

---

# 📖 Overview

In large-scale Azure environments, Managed Disks often become "orphaned" when Virtual Machines are deleted without removing their associated disks. These "zombie resources" continue to accrue charges indefinitely.

The **Azure Managed Disk Cleanup Automation** script provides a safe, repeatable, and well-logged solution to scan all subscriptions, identify unattached disks, and prune them.

---

# 💼 Business Value



This solution directly addresses three critical pillars of Cloud Operations (CloudOps):

* **Cloud Cost Governance (OpEx Reduction):** Unattached Managed Disks are billed at the same rate as attached disks. This script mitigates "Cloud Sprawl," preventing organizations from paying for storage that no longer serves any business purpose.
* **Automated Operational Efficiency:** Manual audit processes for finding unattached disks are time-consuming and prone to human error. This automation runs at scale, across all subscriptions, in minutes rather than hours.
* **Audit & Compliance Readiness:** By maintaining a clean infrastructure and providing structured, rotating logs, the organization remains audit-ready.
* **Safe-by-Design Automation:** 
  Implements Dry-Run execution mode to validate cleanup operations before performing live deletions, reducing operational risk and human errors.
* **Cloud-Native Automation Architecture:** 
  Built using Azure SDKs, Managed Identity authentication, and environment-aware execution patterns aligned with modern cloud engineering best security practices.
---

# ✨ Key Features

| Feature | Description |
| :--- | :--- |
| **Safety First** | Implements a "Dry-Run" flag to prevent accidental deletion. |
| **Dual Logging** | Writes to local rotating logs for audit trails & streams to Azure Logs for real-time monitoring. |
| **Flexible Auth** | Supports `InteractiveBrowserCredential` for local dev and `DefaultAzureCredential` for Azure Automation. |
| **Cross-Environment** | Detects local vs. Cloud execution context automatically. |
| **Variable Injection** | Integrates with Azure Automation Variable store and OS Environment Variables. |
| **Audit Ready** | Detailed logging of subscription processing, disk discovery, and deletion status. |

---

# 🏗️ Architecture

The script utilizes a modular structure designed for cloud-native orchestration:

    main.py
    │
    ├── Identity Layer
    │   ├── InteractiveBrowserCredential (Local Dev)
    │   └── DefaultAzureCredential (Azure Automation / Managed Identity)
    │
    ├── Configuration Layer
    │   ├── get_az_automation_variable (Azure Assets / OS Env Fallback)
    │   └── str_to_bool (Data Sanitization)
    │
    ├── Logging Layer
    │   ├── RotatingFileHandler (Local Persistence)
    │   └── StreamHandler (Azure Job Stream)
    │
    └── Core Logic
    ├── Subscription Iterator
    ├── ComputeManagementClient
    └── Unmanaged Disk Identity and Deletion Service

---

# 🛠 Prerequisites

Ensure the following are installed:

### Python
* Version: **3.8 or above**
* Install dependencies:

    pip install -r requirements.txt
---

# Required Libraries
    azure-identity, azure-mgmt-compute, azure-mgmt-resource, tzlocal

---

# ⚙️ Configuration

The script dynamically retrieves configuration values from:

- **Azure Automation Variables** (Cloud Execution)
- **Operating System Environment Variables** (Local Execution)

This design enables seamless portability between local development, Azure Automation Accounts, CI/CD pipelines, and scheduled cloud execution.

| Variable | Type | Description |
| :--- | :--- | :--- |
| **DiskCleanup_DryRun** | Boolean | Controls execution mode. `True` performs a safe simulation without deleting disks, while `False` enables actual deletion of unattached Managed Disks. |
| **DiskCleanup_RetentionDays** | Integer | Defines the retention threshold (in days) before a disk becomes eligible for cleanup operations. |
| **run_locally_without_managed_identity** | Boolean | Determines authentication mode. `True` uses `InteractiveBrowserCredential` for local testing, while `False` enables Managed Identity / `DefaultAzureCredential` for Azure-hosted execution. |
| **AZURE_FUNCTIONS_ENVIRONMENT** | Environment Variable | Used to detect Azure-hosted execution environments and automatically adjust logging behavior. |
| **WEBSITE_INSTANCE_ID** | Environment Variable | Helps identify App Service / Azure-hosted runtime environments for cloud-aware execution logic. |

---

# Example (Windows PowerShell)
    $env:DiskCleanup_DryRun="True"
    $env:DiskCleanup_RetentionDays="30"
# Example (Linux/macOS)
    export DiskCleanup_DryRun=True
    export DiskCleanup_RetentionDays=30


---

# 🚀 Execution Guide

## ▶️ Local Execution

For local development and testing:

```python
run_locally_without_managed_identity = True
```

Run the script:

```bash
python main.py
```

The script authenticates using:

```python
InteractiveBrowserCredential()
```

This launches a browser-based Microsoft authentication flow for secure local sign-in.

---

## ☁️ Azure Automation Execution

For Azure Automation Account execution:

```python
run_locally_without_managed_identity = False
```

Authentication automatically switches to:

```python
DefaultAzureCredential()
```

### ✅ Recommended Identity Type

- **System Assigned Managed Identity**

### ✅ Required RBAC Permissions

Assign either:

- **Contributor** Role

**OR**

A custom RBAC role containing:

- Read Managed Disks
- Delete Managed Disks

---


# 👨‍💻 Author

### Vishal Navgire

Cloud & Endpoint Automation Engineer

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge\&logo=microsoftazure\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge\&logo=python\&logoColor=ffdd54)
![Automation](https://img.shields.io/badge/Automation-DevOps-green?style=for-the-badge)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge\&logo=microsoft\&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)

---