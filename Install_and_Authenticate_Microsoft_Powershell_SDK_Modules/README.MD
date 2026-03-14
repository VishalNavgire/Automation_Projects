<div align="center">

# 🔧 Microsoft Graph Module Installer with Network Usage Tracking

[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?logo=microsoft&logoColor=white)](https://developer.microsoft.com/en-us/graph)
[![Automation](https://img.shields.io/badge/Automation-Endpoint%20Administration-green)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**A PowerShell automation utility that installs the Microsoft Graph PowerShell SDK, tracks network consumption during installation, and authenticates administrators to Microsoft Graph.**

[Overview](#-overview) • [Key Features](#-key-features) • [Architecture](#-architecture) • [Prerequisites](#-prerequisites) • [Installed Modules](#-installed-modules) • [Execution Guide](#-execution-guide) • [Security Notes](#-security-notes)

</div>

---

# 📖 Overview

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

# ✨ Key Features

| Feature | Description |
|------|-------------|
| **Automated Module Installation** | Installs the Microsoft Graph PowerShell SDK automatically |
| **Version Comparison** | Checks installed vs online module versions before installing |
| **Network Usage Tracking** | Calculates total bandwidth used during installation |
| **Administrator Validation** | Ensures the script runs with elevated privileges |
| **Secure Authentication** | Uses Microsoft Graph delegated authentication |
| **Error Handling** | Detects authentication failures and displays clear messages |

---

# 🏗️ Architecture

The script follows a structured execution flow.


Install-MgGraph-WithUsageTracking.ps1
│
├── Parameter Input
│ ├── Tenant ID
│ └── Enterprise App ID
│
├── Administrator Validation
│ └── Ensure script runs with elevated privileges
│
├── Network Usage Tracking
│ └── Capture adapter statistics before installation
│
├── Module Version Check
│ ├── Get Installed Version
│ └── Get Online Version
│
├── Module Installation
│ └── Install-Module Microsoft.Graph
│
├── Network Consumption Calculation
│ └── Display MB / GB used
│
├── Microsoft Graph Authentication
│ └── Connect-MgGraph
│
└── Authentication Validation
└── Return True / False


---

# 🛠 Prerequisites

Before running the script ensure the following requirements are met.

---

## 1️⃣ PowerShell Version

⚠️ **This script only supports PowerShell 7 or newer**

Check your PowerShell version:

```powershell
$PSVersionTable.PSVersion

Download PowerShell 7:

https://learn.microsoft.com/powershell/scripting/install/installing-powershell

2️⃣ Administrator Privileges

The script must be executed using Run as Administrator.

3️⃣ Microsoft Entra App Registration

Create an Enterprise Application in your Microsoft Entra tenant.

Assign the following Delegated Permission:

DeviceManagementManagedDevices.Read.All

You will need the following values:

Parameter	Description
Tenant ID	Azure Tenant ID
Enterprise App ID	Application (Client) ID
📦 Installed Modules

Running this script installs the Microsoft Graph PowerShell SDK, which includes the following modules:

Microsoft.Graph
Microsoft.Graph.Applications
Microsoft.Graph.Authentication
Microsoft.Graph.BackupRestore
Microsoft.Graph.Beta.DeviceManagement
Microsoft.Graph.Bookings
Microsoft.Graph.Calendar
Microsoft.Graph.ChangeNotifications
Microsoft.Graph.CloudCommunications
Microsoft.Graph.Compliance
Microsoft.Graph.CrossDeviceExperiences
Microsoft.Graph.DeviceManagement
Microsoft.Graph.DeviceManagement.Administration
Microsoft.Graph.DeviceManagement.Enrollment
Microsoft.Graph.DeviceManagement.Functions
Microsoft.Graph.Devices.CloudPrint
Microsoft.Graph.Devices.CorporateManagement
Microsoft.Graph.Devices.ServiceAnnouncement
Microsoft.Graph.DirectoryObjects
Microsoft.Graph.Education
Microsoft.Graph.Files
Microsoft.Graph.Groups
Microsoft.Graph.Identity.DirectoryManagement
Microsoft.Graph.Identity.Governance
Microsoft.Graph.Identity.Partner
Microsoft.Graph.Identity.SignIns
Microsoft.Graph.Mail
Microsoft.Graph.Notes
Microsoft.Graph.People
Microsoft.Graph.PersonalContacts
Microsoft.Graph.Planner
Microsoft.Graph.Reports
Microsoft.Graph.SchemaExtensions
Microsoft.Graph.Search
Microsoft.Graph.Security
Microsoft.Graph.Sites
Microsoft.Graph.Teams
Microsoft.Graph.Users
Microsoft.Graph.Users.Actions
Microsoft.Graph.Users.Functions

These modules enable administrators to interact with various Microsoft 365 services via Microsoft Graph API.

🚀 Execution Guide
Step 1 — Open PowerShell as Administrator

Search for PowerShell 7 and select:

Run as Administrator
Step 2 — Execute the Script
.\Install-MgGraph-WithUsageTracking.ps1
Step 3 — Provide Required Parameters

The script will prompt for:

Tenant ID
Enterprise App ID

Example:

Enter your Tenant ID
Enter your Enterprise App ID
Step 4 — Authentication

The script will initiate Microsoft Graph authentication.

After successful authentication the script returns:

True

If authentication fails:

Failed to connect to Microsoft Graph.
📊 Example Output
Installing or updating Microsoft.Graph module...

Data consumed for Microsoft.Graph module installation:
54.21 MB / 0.05 GB

Authentication with Microsoft Graph is in progress...
🔐 Security Notes

This script uses Delegated Authentication via Microsoft Graph.

This means:

Access is performed on behalf of the authenticated user

The script cannot exceed the user's permissions

Conditional Access and MFA policies remain enforced

No credentials are stored locally.
