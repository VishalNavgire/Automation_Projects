<div align="center">

# 🔍 Microsoft Entra ID Group Membership Comparator

![PowerShell](https://img.shields.io/badge/PowerShell-Automation-5391FE?logo=powershell\&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?logo=microsoft\&logoColor=white)
![Intune](https://img.shields.io/badge/Microsoft%20Intune-Endpoint%20Management-blue?logo=microsoft\&logoColor=white)
![Azure AD](https://img.shields.io/badge/Microsoft%20Entra%20ID-Identity%20Platform-512BD4?logo=microsoft\&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)

**Enterprise-grade PowerShell automation tool for comparing Microsoft Entra ID group memberships between two users or two Intune managed devices and generating a structured HTML analysis report.**

</div>

---

# 📖 Overview

In modern enterprise environments, **Microsoft Entra ID groups control nearly every aspect of access and configuration**, including:

* Microsoft Intune policies
* Conditional Access policies
* Application deployments
* Security configurations
* RBAC permissions
* Licensing assignments

Troubleshooting configuration issues often requires identifying **differences in group memberships between two identities or devices**.

Manually reviewing dozens or hundreds of groups can be time-consuming and error-prone.

This automation tool solves that problem by:

1️⃣ Querying **Microsoft Graph API**
2️⃣ Retrieving **transitive group memberships**
3️⃣ Comparing memberships between two selected entities
4️⃣ Generating a **clean HTML report highlighting**

* Common groups
* Groups unique to entity #1
* Groups unique to entity #2

---

# 🎯 Key Capabilities

| Feature                                     | Description                                                |
| ------------------------------------------- | ---------------------------------------------------------- |
| 🔎 **User Group Comparison**                | Compare Azure AD groups between two users                  |
| 💻 **Device Group Comparison**              | Compare Azure AD groups between two Intune managed devices |
| 🔁 **Transitive Group Membership Analysis** | Detect nested group memberships automatically              |
| 📊 **HTML Reporting Engine**                | Generates structured visual reports                        |
| 🎨 **Professional CSS Styling**             | Reports include formatted tables and color indicators      |
| 🧠 **Interactive Object Selection**         | Uses `Out-GridView` to search and select users or devices  |
| ⚡ **Microsoft Graph Integration**           | Retrieves data directly from the tenant                    |
| 🛠 **Automated Module Installation**        | Installs required Graph modules automatically              |
| 📁 **Automatic Report Storage**             | Saves reports to a predefined local directory              |

---

# 🏗 Architecture Overview

The script follows a modular PowerShell design with dedicated functions for authentication, Graph queries, comparison logic, and report generation.

```
Compare-EntraID-Groups.ps1
│
├── UI Configuration
│   └── Console appearance & menu system
│
├── Authentication Layer
│   ├── Microsoft Graph module validation
│   └── Graph authentication
│
├── Data Retrieval (Microsoft Graph API)
│   ├── Get-AllMSEntraIDUserDetails
│   ├── Get-AllMSEntraIDGroupsOfUser
│   ├── Get-AllIntuneManagedDevices
│   ├── Get-ADObjectIdOfAnIntuneManagedDevice
│   └── Get-AllGroupsOfAnIntuneManagedDevice
│
├── Comparison Engine
│   └── Compare-Object logic for group differences
│
├── Reporting Engine
│   ├── HTML formatting
│   ├── CSS styling
│   └── Report generation
│
└── Output
    └── Interactive HTML report
```

---

# ⚙️ Technology Stack

### ☁️ Identity & Cloud

* Microsoft Entra ID
* Microsoft Graph API
* Microsoft Intune

### 💻 Automation

* PowerShell
* Microsoft Graph PowerShell SDK

### 📊 Reporting

* HTML
* CSS styling
* PowerShell `ConvertTo-Html`

---

# 🛠 Prerequisites

Before running the script ensure the following requirements are met.

---

## 1️⃣ PowerShell Version

Recommended:

```
PowerShell 5.1 or later
```

PowerShell 7+ is also supported.

---

## 2️⃣ Microsoft Entra App Registration

An **App Registration must be created** in your tenant.

Required configuration:

| Setting             | Value                           |
| ------------------- | ------------------------------- |
| Authentication Type | Delegated                       |
| Redirect URI        | http://localhost                |
| API Permission      | `DeviceManagementApps.Read.All` |

After registration, update the script:

```powershell
$Registered_Entra_App_ID = "YOUR_APP_ID"
```

Microsoft documentation:

https://learn.microsoft.com/en-us/graph/auth-register-app-v2

---

## 3️⃣ Required Microsoft Graph Permissions

The signed-in account must have sufficient permissions.

Recommended permissions:

* `DeviceManagementApps.Read.All`
* `DeviceManagementConfiguration.Read.All`
* `Directory.Read.All`
* `Group.Read.All`

---

# 🚀 How the Script Works

### Step 1 — Authenticate

The script installs and loads the **Microsoft Graph Intune module** and prompts for authentication.

---

### Step 2 — Choose Comparison Mode

The interactive menu appears:

```
1. Compare Users
2. Compare Devices
3. Exit
```

---

### Step 3 — Select Objects

Using `Out-GridView`, the administrator selects:

* Two **users** OR
* Two **Intune managed devices**

---

### Step 4 — Graph Data Retrieval

The script retrieves:

* Transitive group memberships
* Azure AD group metadata
* Group types
* Dynamic membership rules

---

### Step 5 — Group Comparison

PowerShell's `Compare-Object` is used to categorize groups into:

| Category           | Description                           |
| ------------------ | ------------------------------------- |
| Common Groups      | Both entities share these groups      |
| Unique to Entity 1 | Groups only assigned to first entity  |
| Unique to Entity 2 | Groups only assigned to second entity |

---

### Step 6 — Report Generation

A structured HTML report is created with:

* Styled tables
* Membership rule information
* Group type indicators
* Timestamp and author details

---

# 📊 Example Report Structure

The generated HTML report contains three sections:

### 1️⃣ Common Groups

Groups both entities belong to.

```
User A ∩ User B
```

---

### 2️⃣ Unique Groups — Entity 1

Groups only assigned to the first user/device.

```
User A − User B
```

---

### 3️⃣ Unique Groups — Entity 2

Groups only assigned to the second user/device.

```
User B − User A
```

---

# 📁 Report Storage Location

Reports are automatically saved to:

```
C:\Temp\Compare_AAD_Groups
```

Example report file:

```
Compare_AAD_Groups_For_USERS_06_Feb_2025_10_15_PM.html
```

The report automatically opens in the default browser.

---

# 🧠 Real-World Troubleshooting Scenarios

This tool dramatically reduces troubleshooting time in enterprise environments.

### 🔐 Intune Policy Not Applying

Compare a working user with a non-working user to identify **missing policy groups**.

---

### 📦 Application Access Issues

Detect missing application assignment groups.

---

### 💻 Device Configuration Differences

Compare two Intune devices to find missing configuration groups.

---

### 🧑‍💼 RBAC Permission Problems

Identify missing admin role groups for IT staff.

---

### 🔑 Conditional Access Troubleshooting

Find differences in access control groups.

---

### 🌐 VPN / Network Access Issues

Verify whether the user belongs to required network access groups.

---

# 🔐 Security Design

This tool follows secure operational practices:

* No hardcoded credentials
* Delegated authentication
* Direct Microsoft Graph queries
* No tenant data stored locally except generated reports

---

# 🚀 Future Enhancements

Potential improvements for upcoming versions:

* CSV / Excel report export
* Multi-user comparison
* Graph SDK migration
* Azure Automation support
* CI/CD integration
* Device compliance comparison
* Conditional Access analysis
* Visual group dependency graph

---

# 👨‍💻 Author

### Vishal Navgire

Cloud & Endpoint Automation Engineer

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge\&logo=microsoftazure\&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge\&logo=microsoft\&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge\&logo=python\&logoColor=ffdd54)

---

<div align="center">

### ⭐ Built for Microsoft Endpoint Managers, Cloud Engineers, and Identity Administrators

</div>
