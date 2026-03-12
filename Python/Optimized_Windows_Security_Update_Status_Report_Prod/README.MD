<div align="center">

# 📊 Intune Managed Windows Security Updates Dashboard

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python\&logoColor=white)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.28%2B-FF4B4B?logo=streamlit\&logoColor=white)](https://streamlit.io)
[![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-0078D4?logo=microsoft-azure\&logoColor=white)](https://developer.microsoft.com/en-us/graph)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

**An interactive analytics dashboard for Infrastructure Engineers to evaluate Windows security update status across Microsoft Intune managed devices.**

</div>

---

# 📖 Overview

Fetching patch compliance data across large enterprise environments can be complex and time-consuming.

This project provides a **Python-powered analytics dashboard** that collects device information from:

* Microsoft Intune
* Microsoft Entra ID (Azure AD)
* Windows Autopilot
* Windows Release Health data

The application correlates device inventory with official **Windows build release information** to determine:

* Windows security update status
* OS build distribution
* Devices missing security updates
* Autopilot enrollment insights

All insights are presented through an **interactive Streamlit dashboard** designed for infrastructure and cloud engineers.

---

# 🧠 Architecture Overview

```
User Authentication (MSAL)
        │
        ▼
Microsoft Graph API
(Intune / Entra / Autopilot)
        │
        ▼
Parallel Data Collection
(ThreadPoolExecutor)
        │
        ▼
Local Cache (.parquet)
        │
        ▼
Data Normalization
(Pandas DataFrames)
        │
        ▼
Windows Release Health Correlation
        │
        ▼
Security Update Evaluation
        │
        ▼
Streamlit Dashboard
```

---

# ✨ Key Features

| Feature                        | Description                                                |
| ------------------------------ | ---------------------------------------------------------- |
| Unified Device Inventory       | Combines Intune and Entra ID device data                   |
| Windows Patch Analysis         | Evaluates Windows security update status                   |
| Delta Sync                     | Fetches only incremental changes after the first full sync |
| Multi-threaded Graph API Calls | Faster data retrieval using parallel processing            |
| Smart Local Cache              | Uses `.parquet` storage to reduce API calls                |
| Autopilot Analytics            | Displays Autopilot enrollment and Group Tag distribution   |
| Secure Authentication          | Uses Microsoft Authentication Library (MSAL)               |

---

# 🛠 Prerequisites

## Python

Install **Python 3.9 or newer**

Check installed version:

```bash
python --version
```

### Install Python (if required)

| Operating System | Installation               |
| ---------------- | -------------------------- |
| Windows          | https://www.python.org     |
| macOS            | `brew install python`      |
| Ubuntu / Debian  | `sudo apt install python3` |
| Fedora           | `sudo dnf install python3` |

---

## Azure App Registration

Create an **Azure App Registration** and assign the following **Delegated Permissions**:
Delegated type Permissions allow the application to access Microsoft Graph on behalf of the signed-in user. The permissions granted to the application are therefore limited to the privileges of the authenticated user account.

```
User.Read
User.Read.All
Device.Read.All
DeviceManagementManagedDevices.Read.All
DeviceManagementServiceConfig.Read.All
```

Record the following values:

* **Client ID**
* **Tenant ID**

---

# 📦 Installation

## Clone the Repository

```bash
git clone https://github.com/<your-username>/intune-dashboard.git
cd intune-dashboard
```

---

## Create Virtual Environment (Recommended)

```bash
python -m venv venv
```

Activate the environment:

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not available:

```bash
pip install streamlit pandas plotly requests beautifulsoup4 msal tzlocal pyarrow
```

---

# 🚀 Running the Dashboard

Start the Streamlit application:

```bash
streamlit run Optimized_Windows_Security_Update_Status_Report_Prod.py
```

Open the dashboard in your browser:

```
http://localhost:8501
```

---

# ⚙️ First Time Configuration

When the application starts, enter the following details in the **Streamlit sidebar**.

| Parameter | Description                                |
| --------- | ------------------------------------------ |
| Client ID | Application ID from Azure App Registration |
| Tenant ID | Directory ID of your Azure tenant          |
| User UPN  | Your login email address                   |

Authentication uses **Microsoft Authentication Library (MSAL)**.

Credentials are **never stored in the source code**.

---

# 📊 Dashboard Insights

The dashboard provides multiple analytics views.

## Device Inventory

* Total managed devices
* Azure AD join types
* Device ownership information

## Windows Patch Status

* Windows build distribution
* Days since last update
* Devices missing latest security updates

## Autopilot Devices

* Enrollment status
* Group Tag distribution

## Security Insights

* Non-compliant devices
* OS lifecycle status

---

# 📂 Project Directory Structure

```
intune-dashboard
│
├── Optimized_Windows_Security_Update_Status_Report_Prod.py
├── requirements.txt
├── README.md
│
├── logs
│   └── Win_Sec_Updates_Status.log
│
├── .cache
│   ├── intune_devices.parquet
│   ├── aad_devices.parquet
│   └── delta_tokens.json
```

---

# ⚠️ Troubleshooting

## Cache Issues

If charts appear empty or errors occur:

1. Stop the application
2. Delete the `.cache` folder
3. Restart the application

This forces a **full synchronization**.

---

## Initial Load is Slow

The first run performs a **Full Sync** of all devices.

Subsequent runs use **Delta Sync**, which loads significantly faster.

---

## Microsoft Graph API Throttling

The application automatically handles:

```
HTTP 429 Too Many Requests
```

Using **exponential backoff with jitter**.

---

# 🔒 Security Notes

* OAuth tokens are stored **only in memory**
* Credentials are **never committed to the repository**
* `.cache` stores **device metadata only**

---

## 👤 Author
### **Vishal Navgire**  
**Cloud & Endpoint Automation Engineer**

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge&logo=microsoft&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Azure%20Functions](https://img.shields.io/badge/Azure%20Functions-0062AD?style=for-the-badge&logo=azurefunctions&logoColor=white)
![Azure%20Automation](https://img.shields.io/badge/Azure%20Automation-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)

---

<div align="center">

Built with ❤️ using Python and Microsoft Graph

</div>
