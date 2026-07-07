<div align="center">

# 🏗️ Azure Windows Image Factory
### Enterprise Automated Golden Image Pipeline using Packer, Ansible & GitHub Actions

![Azure](https://img.shields.io/badge/Microsoft-Azure-0078D4?style=for-the-badge&logo=microsoftazure&logoColor=white)
![Packer](https://img.shields.io/badge/Packer-v1.10+-02A8F3?style=for-the-badge&logo=packer&logoColor=white)
![Ansible](https://img.shields.io/badge/Ansible-Core_2.15+-EE0000?style=for-the-badge&logo=ansible&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-7+-5391FE?style=for-the-badge&logo=powershell&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub-Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Windows Server](https://img.shields.io/badge/Windows-Server_2022-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

**Enterprise-grade Infrastructure-as-Code (IaC) solution for building, hardening, validating, and publishing reusable Windows Server Golden Images into Azure Compute Gallery using HashiCorp Packer, Ansible, GitHub Actions, and Azure OpenID Connect (OIDC).**

---

**Infrastructure as Code • Immutable Infrastructure • DevSecOps • Azure Automation**

</div>

---

# 📑 Table of Contents

- [Overview](#-overview)
- [Why This Project?](#-why-this-project)
- [Solution Overview](#-solution-overview)
- [Key Features](#-key-features)
- [Architecture Principles](#-architecture-principles)
- [Repository Structure](#-repository-structure)
- [Technology Stack](#-technology-stack)
- [Pipeline Workflow](#-pipeline-workflow)
- [Build Process Explained](#-build-process-explained)
- [Security Considerations](#-security-considerations)
- [Compliance & Logging](#-compliance--logging)
- [Prerequisites](#-prerequisites)
- [Future Enhancements](#-future-enhancements)
- [Author](#-author)

---

# 📖 Overview

Provisioning Windows virtual machines manually often leads to configuration drift, inconsistent security baselines, lengthy deployment times, and operational overhead. As environments scale, maintaining identical server configurations becomes increasingly difficult, making compliance and security auditing significantly more challenging.

This project demonstrates an **enterprise-grade automated image factory** that creates standardized Windows Server Golden Images for Microsoft Azure.

Instead of configuring every virtual machine individually after deployment, this solution shifts configuration, security hardening, and operating system customization into the image creation process.

Each generated image becomes:

- Fully repeatable
- Version controlled
- Immutable
- Security hardened
- Ready for production deployment

The complete workflow is implemented using Infrastructure as Code (IaC), enabling consistent image creation across development, testing, and production environments.

---

# ❓ Why This Project?

Traditional server provisioning commonly introduces several operational challenges:

- Manual operating system configuration
- Configuration drift between servers
- Inconsistent security settings
- Slow deployment times
- Difficult compliance validation
- Human error during provisioning
- High operational maintenance costs

By adopting immutable infrastructure principles, organizations deploy infrastructure from pre-built images rather than repeatedly configuring servers after deployment.

This approach significantly improves:

- Security
- Repeatability
- Reliability
- Deployment speed
- Compliance
- Disaster recovery

---

# 💡 Solution Overview

This repository automates the complete lifecycle of Azure Windows image creation.

The pipeline performs the following high-level tasks:

1. Validate Infrastructure-as-Code templates.
2. Authenticate securely to Azure using OpenID Connect (OIDC).
3. Retrieve runtime secrets from Azure Key Vault.
4. Provision a temporary Azure Virtual Machine.
5. Configure secure WinRM connectivity.
6. Apply operating system configuration using Ansible.
7. Execute Windows security hardening tasks.
8. Run Sysprep to generalize the operating system.
9. Publish the image to Azure Compute Gallery.
10. Destroy temporary infrastructure automatically.

The result is a reusable, production-ready Windows image that can be consumed by Virtual Machines, Virtual Machine Scale Sets (VMSS), Azure Virtual Desktop (AVD), or enterprise provisioning platforms.

---

# ⭐ Key Features

| Feature | Description |
|----------|-------------|
| 🛡 Image-Time Security Hardening | Applies operating system security configuration during image creation. |
| 🔐 Passwordless Azure Authentication | Uses Azure OpenID Connect (OIDC) instead of long-lived service principal secrets. |
| 🔑 Secure Secret Management | Retrieves runtime credentials securely from Azure Key Vault. |
| 🏗 Immutable Infrastructure | Every deployment originates from a standardized image. |
| 📦 Azure Compute Gallery Integration | Publishes reusable image versions for enterprise-wide deployments. |
| 🚀 Automated Image Pipeline | Fully orchestrated using GitHub Actions. |
| 🧹 Automatic Resource Cleanup | Deletes temporary build resources immediately after image capture. |
| 📜 Build Audit Logging | Stores execution logs as pipeline artifacts for troubleshooting and auditing. |
| 🔄 Repeatable Deployments | Eliminates manual server configuration and configuration drift. |

---

# 🏛 Architecture Principles

This project follows several modern cloud engineering best practices.

- Infrastructure as Code (IaC)
- Immutable Infrastructure
- Least Privilege Access
- Passwordless Authentication
- Security by Default
- Idempotent Configuration Management
- Automated Image Versioning
- Ephemeral Build Infrastructure
- Reusable Enterprise Images
- CI/CD Driven Operations

---

# 🗂 Repository Structure

The repository is organized to separate infrastructure definitions, configuration management, automation scripts, documentation, and CI/CD workflows.

```text
azure-custom-windows-image-capture/
│
├── .github/
│   └── workflows/
│       └── config_and_build_az_win_vm_image.yml  # GHA Orchestration Pipeline
│
├── HLD/                                          # High-Level Design Diagrams & Flowcharts
│
├── packer/
│   ├── azure-windows.pkr.hcl                    # Core Packer Template & Builders
│   └── variables.pkr.hcl                        # Variable Contract Schema Declarations
│
├── ansible/
│   ├── playbooks/
│   │   └── configure-windows.yml                # Main Configuration Entry Point
│   ├── roles/
│   │   └── OS-Hardening/                        # Targeted Security Sub-tasks
│   │       └── tasks/
│   │           └── main.yml                     # Registry Hardening Operations
│   └── ansible.cfg                              # WinRM Connection Adjustments
│
├── scripts/
│   └── Setup-WinRM.ps1                          # Guest OS Provisioning Bootstrap Payload
│
├── .gitignore                                   # Local Workspace Ignore Targets
└── README.md 
```

## Directory Overview

| Folder | Purpose |
|----------|----------|
| **.github/workflows** | GitHub Actions workflow responsible for validating, building, capturing, and publishing images. |
| **packer** | Contains Azure Packer templates and variable definitions used to build Windows images. |
| **ansible** | Configuration management playbooks and reusable hardening roles executed after WinRM becomes available. |
| **scripts** | PowerShell bootstrap scripts executed during the build process. |
| **HLD** | Architecture diagrams, flowcharts, and supporting design documentation. |
| **README.md** | Project documentation. |

---

# 🛠 Technology Stack

## ☁️ Microsoft Azure

- Azure Virtual Machines
- Azure Compute Gallery
- Azure Key Vault
- Azure Virtual Network
- Azure Resource Groups
- Azure Entra ID
- Azure Managed Identities
- Azure ARM API

---

## ⚙️ Image Creation

- HashiCorp Packer
- Azure ARM Builder
- Windows Server
- Sysprep
- Windows WinRM

---

## ⚡ Configuration Management

- Ansible Core
- Ansible Windows Collection
- PowerShell
- Windows Registry
- WinRM over HTTPS

---

## 🚀 CI/CD & DevSecOps

- GitHub Actions
- OpenID Connect (OIDC)
- GitHub Secrets
- GitHub Artifacts
- Infrastructure as Code (IaC)

---

# 🔄 Pipeline Workflow

The pipeline begins whenever code changes are committed to the repository or when manually triggered from GitHub Actions.

```text
Developer Push
        │
        ▼
GitHub Actions Workflow
        │
        ▼
Authenticate using Azure OIDC
        │
        ▼
Retrieve Administrator Password
        │
        ▼
Packer Init
        │
        ▼
Packer Validate
        │
        ▼
Create Temporary Azure Resources
        │
        ▼
Deploy Windows Server VM
        │
        ▼
Execute Setup-WinRM.ps1 
        │
        ▼
Enable WinRM over HTTPS ──> (Opens Secure Port 5986)
        │
        ▼
Run Ansible Playbook
        │
        ▼
Apply OS Configuration
        │
        ▼
Apply Security Hardening
        │
        ▼
Execute Sysprep
        │
        ▼
Capture Managed Image
        │
        ▼
Publish to Azure Compute Gallery
        │
        ▼
Destroy Temporary Infrastructure
```

---

# ⚙ Build Process Explained

## Step 1 — Pipeline Initialization

The GitHub Actions workflow is triggered either manually or automatically after code changes are pushed to the repository.

The workflow performs initial validation before interacting with Azure resources.

Activities performed:

- Checkout repository
- Install Packer
- Install Ansible
- Install Azure CLI
- Initialize workflow variables
- Validate required secrets

---

## Step 2 — Azure Authentication

Instead of authenticating with a traditional Service Principal secret, GitHub Actions establishes trust with Azure using OpenID Connect (OIDC).

Benefits include:

- No stored passwords
- Short-lived authentication tokens
- Reduced credential exposure
- Simplified secret management

After authentication, Azure Key Vault securely provides runtime secrets required during image creation.

---

## Step 3 — Packer Validation

Before infrastructure deployment begins, Packer validates the template files.

Validation includes:

- HCL syntax
- Variable definitions
- Azure ARM builder configuration
- Plugin availability
- Template integrity

Only validated templates continue to the build phase.

---

## Step 4 — Temporary Azure Infrastructure

Packer provisions temporary Azure resources required for image creation.

Typical resources include:

- Resource Group
- Virtual Network
- Network Security Group
- Public IP
- Network Interface
- Windows Server Virtual Machine

These resources exist only for the duration of the build.

---

## Step 5 — Bootstrap WinRM

After the VM is deployed, Packer executes the `Setup-WinRM.ps1` bootstrap script.

The script performs tasks such as:

- Enable WinRM
- Configure HTTPS listener
- Generate a self-signed certificate
- Configure firewall rules
- Restart the WinRM service

Once completed, Ansible can securely communicate with the Windows virtual machine.


##  Step 6 — Windows Configuration with Ansible

Ansible connects to the Windows virtual machine over WinRM HTTPS and applies operating system configuration.

The playbook is designed to be:
- Idempotent
- Repeatable
- Version controlled
- Environment agnostic
- Typical tasks include:
- Registry configuration
- Service configuration
- Feature installation
- Security baseline enforcement
- PowerShell execution
- System customization
- Example hardening task:

    - name: Enable TLS 1.3 ansible.windows.win_regedit: path: HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server name: Enabled data: 1 type: dword

## Step 7 — Sysprep & Generalization

After configuration completes, Packer executes Sysprep.

Typical command:
- Sysprep.exe /generalize /oobe /shutdown

This process:
- Removes machine-specific identifiers
- Resets SIDs
- Generalizes the operating system
- Prepares the image for reuse
- The VM shuts down automatically after Sysprep completes.

## Step 8 — Automatic Cleanup

After successful publication, all temporary build resources are deleted automatically.

This includes:

- Temporary resource groups
- Virtual machines
- Disks
- Network interfaces
- Public IP addresses
- Networking components
- Only the finalized image remains.

# 📜 Compliance & Logging

Build artifacts are retained to support troubleshooting, auditing, and operational visibility while minimizing long-term storage costs.

| Artifact | Purpose | Retention |
|-----------|---------|-----------|
| **Packer Logs** | Capture image build execution details for troubleshooting and debugging. | **3 days** |
| **GitHub Actions Logs** | Record CI/CD workflow execution, job outputs, and pipeline events. | **GitHub default retention** |
| **Build Artifacts** | Store deployment evidence, generated reports, and build outputs for auditing. | **3 days** |

> **Note:** The logging strategy balances operational visibility with cost efficiency by retaining artifacts only for the period necessary to support troubleshooting and compliance requirements.


# 📋 Prerequisites

Before using this project, ensure the following prerequisites are in place.

## ☁️ Microsoft Azure

The following Azure resources and permissions are required:

- Azure Subscription
- Azure Resource Group
- Azure Compute Gallery
- Azure Key Vault
- Azure Entra ID Application (App Registration)
- OpenID Connect (OIDC) Federated Credential
- Service Principal or Managed Identity (if not using OIDC)
- Contributor or equivalent RBAC permissions to:
  - Create and manage Virtual Machines
  - Create Managed Images
  - Publish image versions to Azure Compute Gallery
  - Access Azure Key Vault secrets

---

## 💻 Local Development Tools

Install the following tools if you plan to build or test the solution locally.

| Tool | Recommended Version |
|------|----------------------|
| Git | Latest |
| HashiCorp Packer | v1.10+ |
| Ansible Core | v2.15+ |
| Azure CLI | Latest |
| PowerShell | 7.x or later |

---

## 🚀 GitHub Requirements

Your GitHub repository should have the following configured:

- GitHub Actions enabled
- GitHub-hosted or self-hosted runner
- OpenID Connect (OIDC) trust configured with Azure
- Repository Variables (non-sensitive configuration)
- Repository Secrets (if required for your implementation)

---

## 🔑 Azure Key Vault

Store sensitive values securely in Azure Key Vault instead of the repository.

Typical secrets include:

- Local Administrator Password
- Additional application credentials (if applicable)
- Build-time secrets required by the image customization process

---

## 📦 Azure Permissions

The identity executing the pipeline should have sufficient permissions to:

- Authenticate with Azure
- Read secrets from Azure Key Vault
- Create and delete Azure Resource Groups
- Provision Azure Virtual Machines
- Create Managed Images
- Publish image versions to Azure Compute Gallery
- Remove temporary build resources after completion


---
# 👨‍💻 Author

### Vishal Navgire

Cloud & Endpoint Automation Engineer

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge\&logo=microsoftazure\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge\&logo=python\&logoColor=ffdd54)
![Automation](https://img.shields.io/badge/Automation-DevOps-green?style=for-the-badge)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge\&logo=microsoft\&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white) ![Ansible](https://img.shields.io/badge/Ansible-EE0000?style=for-the-badge&logo=ansible&logoColor=white)
