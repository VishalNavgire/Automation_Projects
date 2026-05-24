<div align="center">

# 🛡️ Intune Group Assignment Reporter

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?logo=microsoft&logoColor=white)](https://developer.microsoft.com/en-us/graph)
[![Intune](https://img.shields.io/badge/Microsoft%20Intune-Management-blue?logo=microsoft&logoColor=white)](https://learn.microsoft.com/mem/intune/)
[![Automation](https://img.shields.io/badge/Automation-Endpoint%20Management-green)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**A PowerShell automation tool that analyzes and generates detailed HTML reports for Microsoft Intune policy and application assignments targeting specific Entra ID groups.**

[Overview](#-overview) • [Key Features](#-key-features) • [Architecture](#-architecture) • [Prerequisites](#-prerequisites) • [Installation](#-installation) • [Execution Guide](#-execution-guide) • [Report Output](#-report-output) • [Troubleshooting](#-troubleshooting)

</div>

---

# 📖 Overview

Managing **Microsoft Intune environments** at scale often requires visibility into how policies, applications, scripts, and compliance configurations are assigned to **Azure AD (Entra ID) groups**.

The **Intune Group Assignment Reporter** automates the process of retrieving assignment data across multiple Intune workloads and generates a **structured HTML report** for easy analysis.

This tool queries **Microsoft Graph API** endpoints and compiles assignments for:

- 📦 Win32 Applications
- ⚙️ Device Configuration Profiles
- 🛡️ Device Compliance Policies
- 🧩 Settings Catalog Policies
- 🗂 Administrative Templates
- 📜 Platform Scripts
- 🔧 Proactive Remediation Scripts

The result is a **centralized report that provides administrators with complete visibility into how a specific group is targeted within Intune**.

---

# ✨ Key Features

| Feature | Description |
|-------|-------------|
| **Group Assignment Discovery** | Analyze how a specific Azure AD group is targeted across Intune |
| **Multi-Workload Coverage** | Supports apps, compliance policies, configuration profiles, scripts, and more |
| **Interactive Group Selection** | Uses PowerShell `Out-GridView` to allow administrators to select a group interactively |
| **Assignment Type Detection** | Detects inclusion vs exclusion assignments |
| **Assignment Filter Resolution** | Retrieves filter display names associated with assignments |
| **Graph Pagination Handling** | Automatically processes paginated Graph API responses |
| **HTML Reporting Engine** | Generates a styled HTML report for easy consumption |
| **Automated Report Storage** | Saves reports with timestamps for historical tracking |
| **Enterprise Friendly** | Built for real-world Intune environments and automation workflows |

---

# 🏗️ Architecture

The script is organized into logical sections that handle authentication, Graph queries, assignment processing, and report generation.

```
Intune-Group-Assignment-Reporter.ps1
│
├── Console Setup
│ └── Set-HostBackgroundColor
│
├── Authentication
│ └── Install-MSGraphIntuneModule
│
├── Group Discovery
│ └── Retrieve Azure AD Groups
│
├── Intune Workload Queries
│ ├── Win32 Applications
│ ├── Device Configuration Profiles
│ ├── Device Compliance Policies
│ ├── Settings Catalog Policies
│ ├── Administrative Templates
│ ├── Platform Scripts
│ └── Proactive Remediation Scripts
│
├── Graph Pagination Engine
│ └── @odata.nextLink handling
│
├── Assignment Processing
│ ├── Inclusion detection
│ ├── Exclusion detection
│ └── Assignment filter resolution
│
└── HTML Report Generator
└── ConvertTo-HTML output
```
---

# 🛠 Prerequisites
Before running the script ensure the following requirements are met.
---
## 1️⃣ PowerShell
Recommended: PowerShell 5.1 
---
## 2️⃣ Microsoft Graph Intune Module
The script automatically installs the required module if not present:
Microsoft.Graph.Intune
---

## 3️⃣ Required Permissions

The user running the script must have sufficient Microsoft Graph permissions such as:

- `DeviceManagementApps.Read.All`
- `DeviceManagementConfiguration.Read.All`
- `DeviceManagementManagedDevices.Read.All`
- `Group.Read.All`
- `Directory.Read.All`

⚠️ Tenant's Global Administrator consent may be required.

---

# 👨‍💻 Author

### Vishal Navgire

Cloud & Endpoint Automation Engineer

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge\&logo=microsoftazure\&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge\&logo=microsoft\&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge\&logo=python\&logoColor=ffdd54)

---
