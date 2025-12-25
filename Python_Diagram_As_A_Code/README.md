# 🔐 Secured Intune Custom Inventory Pipeline (POC)

> **Architecture-as-Code | Zero Trust | Identity-First Design**

A proof-of-concept demonstrating a **secure, identity-validated pipeline** for collecting **custom inventory from Intune-managed Windows endpoints** and ingesting it into **Azure Log Analytics**, without using shared keys or device-side secrets.

---

## 📌 Why This Project Exists

 Ingestion custom device inventory using:
- Shared workspace keys
- Blind trust in client-side scripts
- Direct endpoint-to-Log Analytics access

⚠️ These approaches increase the risk of **data spoofing** and **unauthorized ingestion**.

This project demonstrates a **secure, enterprise-ready alternative** using:
- Microsoft Intune
- Azure Functions
- Microsoft Entra ID
- Managed Identities

---

## 🎯 Key Objectives

✔ Ensure **only legitimate Intune-managed devices** can submit data  
✔ Enforce **tenant and device identity validation**  
✔ Eliminate **shared secrets and ingestion keys**  
✔ Apply **Zero Trust and least-privilege principles**  
✔ Represent architecture using **code-driven diagrams**

---

## 🏗 High-Level Architecture

**Trust boundaries are clearly enforced across three tiers:**

1. **Endpoint Collection Tier**  
   Intune-managed Windows devices collect inventory using remediation scripts.

2. **Azure Security Boundary**  
   Azure Function validates device and tenant identity via Microsoft Entra ID.

3. **Analytics Tier**  
   Log Analytics ingests data using Managed Identity — never directly from devices.

📌 The architecture is rendered programmatically using Python (`diagrams`).

---

## 🔄 End-to-End Flow

| Step | Description |
|-----:|------------|
| **1** | Intune deploys and executes a PowerShell remediation script |
| **2** | Device sends inventory data via HTTPS to Azure Function |
| **3** | Azure Function validates Device ID & Tenant ID using Entra ID |
| **4** | Function ingests data into Log Analytics using Managed Identity |

---

## 🔐 Security Principles Applied

- **Zero Trust Architecture**
- **Identity-first validation**
- **Least-privilege access**
- **No secrets on endpoints**
- **No direct device access to analytics services**

> Devices never write directly to Log Analytics.

---

## 📦🚀 Technologies Used
* **Endpoint Management:** Microsoft Intune (Remediation Scripts)
* **Serverless:** Azure Functions (PowerShell Runtime)
* **Identity:** Microsoft Entra ID & Managed Identities
* **Analytics:** Azure Log Analytics (Log Ingestion API / DCR)
* **Visualization:** Python `diagrams` (Graphviz-based)
---
## 👤 Author
Vishal Navgire
Cloud & Endpoint Automation Engineer
