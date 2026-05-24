<div align="center">

# Microsoft Graph Module Installer with Network Usage Tracking

[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?logo=microsoft&logoColor=white)](https://developer.microsoft.com/en-us/graph)
[![Automation](https://img.shields.io/badge/Automation-Endpoint%20Administration-green)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**A PowerShell automation utility that installs the Microsoft Graph PowerShell SDK, tracks network consumption during installation, and authenticates administrators to Microsoft Graph.**

[Overview](#-overview) • [Key Features](#-key-features) • [Architecture](#-architecture) • [Prerequisites](#-prerequisites) • [Installed Modules](#-installed-modules) • [Execution Guide](#-execution-guide) • [Security Notes](#-security-notes)

</div>

---

## 📖 Overview

Microsoft 365 administrators frequently rely on **Microsoft Graph PowerShell modules** to interact with services such as:

- Microsoft Intune
- Microsoft Entra ID
- Microsoft Teams
- Microsoft Security
- Microsoft Exchange Online (Graph-based operations)

Installing and maintaining these modules manually can sometimes lead to **version inconsistencies or unnecessary bandwidth consumption**.

This script simplifies the process by automatically:

- Installing or updating the **Microsoft Graph PowerShell SDK**
- Measuring **network bandwidth usage during installation**
- Authenticating administrators to **Microsoft Graph API**
- Validating successful authentication

The script is designed for:

- **Microsoft Intune Administrators**
- **Microsoft Entra ID Administrators**
- **Microsoft 365 Administrators**
- **Cloud Automation Engineers**

---

## ✨ Key Features

| Feature | Description |
|------|-------------|
| **Automated Module Installation** | Installs the Microsoft Graph PowerShell SDK automatically. |
| **Version Comparison** | Checks installed vs. online module versions before installing. |
| **Network Usage Tracking** | Calculates total bandwidth used during installation. |
| **Administrator Validation** | Ensures the script runs with elevated privileges. |
| **Secure Authentication** | Uses Microsoft Graph delegated authentication. |
| **Error Handling** | Detects authentication failures and displays clear messages. |

---

## 🏗️ Architecture

The script follows a structured execution flow:

```text
Install-MgGraph-WithUsageTracking.ps1
│
├── Parameter Input
│   ├── Tenant ID
│   └── Enterprise App ID
│
├── Administrator Validation
│   └── Ensure script runs with elevated privileges
│
├── Network Usage Tracking
│   └── Capture adapter statistics before installation
│
├── Module Version Check
│   ├── Get Installed Version
│   └── Get Online Version
│
├── Module Installation
│   └── Install-Module Microsoft.Graph
│
├── Network Consumption Calculation
│   └── Display MB / GB used
│
├── Microsoft Graph Authentication
│   └── Connect-MgGraph
│
└── Authentication Validation
    └── Return True / False
