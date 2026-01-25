# ☁️ Windows Security Dashboard Architecture

This **project** generates a **high‑resolution architectural visualization** for a **Windows Security & Device Posture Dashboard** built on Microsoft Entra identity, Intune, Autopilot, Microsoft Graph API, & Python.

This project transforms a real-world security data flow into a **version‑controlled and architecture diagram** ideal for **Cloud Engineers, Endpoint Engineers, Intune Engineers, and Security Architects**.

---

## 📌 Project Purpose

Windows security dashboard rely on multiple Microsoft data sources — including **MS Entra ID, Intune, Windows Autopilot, Microsoft Graph API**, and external intelligence sources.

This project visualizes:

* How identity authentication occurs using **MSAL & Entra ID**
* How device inventory and management data is pulled via **Microsoft Graph API**
* How Intune Managed Windows Enpoints health intelligence is collected via **web scraping**
* How data is cached locally for **performance & resiliency**
* How the final **Dashboard UI** is rendered

The diagram is generated using Python and the **Diagrams** library, ensuring:

✅ Reproducibility
✅ Offline generation
✅ Version-controlled architecture

---

## 🏗 Architecture Overview

The diagram models **four primary layers**:

### 1️⃣ Operator Layer

* **Intune Engineer** authenticates interactively
* Secure token-based authentication via **MSAL**

### 2️⃣ Microsoft Cloud Data Sources

**Identity & Authentication**

* MS Entra ID (Azure AD) issues access tokens

**Graph API Data Feeds**

* Entra Registered Devices
* Intune Managed Devices
* Windows Autopilot Identities

### 3️⃣ Public Intelligence Layer

* Windows 11 Release Health data collected via **web scraping (BeautifulSoup)**

### 4️⃣ Local Execution & Visualization Layer

* Python + Streamlit dashboard engine
* Local caching (Parquet / Delta Tokens)
* Interactive UI rendering

---

## 🔄 Data Flow Breakdown

### 🔐 Authentication Flow

| Step          | Action                        |
| ------------- | ----------------------------- |
| User login    | Interactive sign-in           |
| Token request | MSAL token acquisition        |
| Token issued  | Entra ID returns access token |

---

### 📊 Data Ingestion Flow (Parallel Sources)

| Source       | Data Type           |
| ------------ | ------------------- |
| Entra ID     | Registered Devices  |
| Intune       | Managed Devices     |
| Autopilot    | Provisioned Devices |
| Windows Blog | Release Health      |

---

### 💾 Caching & Optimization

* Local cache prevents redundant API calls
* Improves **dashboard performance**
* Enables **self‑healing retry logic**

---

### 🖥 Visualization Layer

* Streamlit-based **Interactive Dashboard UI**
* Real-time device & OS posture insights

---

## 🧩 Key Technologies Used

| Category          | Tools                  |
| ----------------- | ---------------------- |
| Language          | Python                 |
| Diagram Engine    | Diagrams               |
| Identity          | MS Entra ID (Azure AD) |
| Device Management | Microsoft Intune       |
| Provisioning      | Windows Autopilot      |
| API               | Microsoft Graph        |
| Web Scraping      | BeautifulSoup          |
| UI                | Streamlit              |
| Storage           | Local Parquet Cache    |

---

## 🖼 Generated Output

Running the script generates a **high‑resolution PNG architecture diagram**:

```
windows_security_dashboard_arch.png
```

## 🎯 Use Cases

* Intune & Endpoint Architecture Documentation
* Windows Security Posture Reporting
* Identity & Access Flow Visualization

---
## ⭐ Future Enhancements (Optional)

* Replace external icon downloads with native diagram icons
* Make use of cloud storage
  
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
