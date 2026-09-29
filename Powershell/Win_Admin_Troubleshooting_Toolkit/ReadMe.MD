<div align="center">

# 🖥️ Windows Server & Endpoint Troubleshooting & Automation Toolkit via Powershell

**A hands-on learning and reference repository for Windows Server, Windows Endpoint, PowerShell administration, troubleshooting, diagnostics, and automation.**

<br>

[![PowerShell](https://img.shields.io/badge/PowerShell-7%2B-5391FE?logo=powershell\&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Windows Server](https://img.shields.io/badge/Windows%20Server-Administration-0078D4?logo=windows\&logoColor=white)](https://learn.microsoft.com/windows-server/)
[![Windows](https://img.shields.io/badge/Windows-Endpoint-0078D4?logo=windows\&logoColor=white)](https://learn.microsoft.com/windows/)
[![Active Directory](https://img.shields.io/badge/Active%20Directory-Administration-0078D4?logo=microsoft\&logoColor=white)](https://learn.microsoft.com/windows-server/identity/ad-ds/)
[![Intune](https://img.shields.io/badge/Microsoft-Intune-0078D4?logo=microsoft\&logoColor=white)](https://learn.microsoft.com/mem/intune/)
[![Entra ID](https://img.shields.io/badge/Microsoft-Entra%20ID-5E5CE6?logo=microsoft\&logoColor=white)](https://learn.microsoft.com/entra/)

<br>

**Symptom → Evidence → Analysis → Root Cause → Remediation → Verification**

</div>

---

# 📖 Overview

Windows administration involves much more than knowing individual PowerShell commands.

When a Windows Server or Endpoint has a problem, an administrator needs to determine:

* What is actually failing?
* What evidence should be collected?
* Which command or diagnostic tool should be used?
* What does the output mean?
* What should be investigated next?
* What is the likely root cause?
* How can the issue be remediated?
* How can the result be verified?

This repository is designed to build that troubleshooting mindset.

Rather than functioning as a simple **PowerShell command cheat sheet**, each command is studied in the context of a real administration or troubleshooting scenario.

The repository covers both traditional Windows administration and modern Microsoft endpoint technologies, including:

* Windows Server
* Windows Endpoint
* PowerShell
* Networking
* DNS
* Processes and performance
* Windows Services
* Event Logs
* Storage
* Files and permissions
* Users and groups
* Active Directory
* Group Policy
* Windows Update
* Windows Security and Defender
* Registry
* Scheduled Tasks
* Remote Management
* Drivers and Devices
* Microsoft Entra ID
* Microsoft Intune
* Windows Autopilot

---

# 🧠 Learning Methodology

Every command documented in this repository follows a consistent four-question learning model.

### 1️⃣ What does it show?

Understand what information the command provides and what each important property or value represents.

### 2️⃣ What problem would make me run it?

Connect the command to a real Windows administration or troubleshooting scenario.

### 3️⃣ How do I interpret the output?

Identify the important values, states, errors, counters, IDs, relationships, and patterns in the output.

### 4️⃣ What would I run next based on the result?

Use the result of the current command to determine the next diagnostic step.

This creates a troubleshooting chain rather than isolated command memorization.

---

# 🔍 Troubleshooting Philosophy

The overall approach used throughout this repository is:

```text
                         User / System Symptom
                                  │
                                  ▼
                           Collect Evidence
                                  │
                                  ▼
                         Analyze the Evidence
                                  │
                                  ▼
                         Form a Hypothesis
                                  │
                                  ▼
                         Run Next Diagnostic
                                  │
                                  ▼
                            Root Cause
                                  │
                                  ▼
                             Remediate
                                  │
                                  ▼
                              Verify
```

The goal is to develop the ability to move from:

> **"I know this command."**

to:

> **"I know why I need this command, what its output means, and what I should investigate next."**

---

# 📂 Repository Structure

```text
Windows-PowerShell-Troubleshooting-Playbook/
│
├── README.md
│
├── 01-System-Information/
│   ├── Get-ComputerInfo.md
│   ├── Get-CimInstance.md
│   ├── Get-Win32-OperatingSystem.md
│   └── Get-Win32-ComputerSystem.md
│
├── 02-Processes-CPU-Memory/
│   ├── Get-Process.md
│   ├── Get-Counter.md
│   ├── Get-CimInstance-Processor.md
│   └── Get-CimInstance-Memory.md
│
├── 03-Services/
│   ├── Get-Service.md
│   ├── Start-Service.md
│   ├── Stop-Service.md
│   └── Restart-Service.md
│
├── 04-Event-Logs/
│   ├── Get-WinEvent.md
│   ├── System-Events.md
│   ├── Application-Events.md
│   └── Security-Events.md
│
├── 05-Networking/
│   ├── Get-NetIPConfiguration.md
│   ├── Get-NetAdapter.md
│   ├── Get-NetTCPConnection.md
│   ├── Test-NetConnection.md
│   ├── Resolve-DnsName.md
│   └── Get-NetRoute.md
│
├── 06-DNS/
│   ├── Resolve-DnsName.md
│   ├── ipconfig.md
│   └── nslookup.md
│
├── 07-Disk-Storage/
│   ├── Get-Disk.md
│   ├── Get-Partition.md
│   ├── Get-Volume.md
│   ├── Get-PhysicalDisk.md
│   └── Get-PSDrive.md
│
├── 08-Files-Permissions/
│   ├── Get-ChildItem.md
│   ├── Get-Acl.md
│   ├── Get-FileHash.md
│   └── icacls.md
│
├── 09-Users-Groups/
│   ├── Get-LocalUser.md
│   ├── Get-LocalGroup.md
│   ├── Get-LocalGroupMember.md
│   └── whoami.md
│
├── 10-Active-Directory/
│   ├── Get-ADUser.md
│   ├── Get-ADComputer.md
│   ├── Get-ADGroupMember.md
│   ├── Get-ADReplication.md
│   └── gpresult.md
│
├── 11-Group-Policy/
│   ├── gpupdate.md
│   ├── gpresult.md
│   └── rsop.md
│
├── 12-Windows-Update/
│   ├── Get-WindowsUpdateLog.md
│   ├── Get-HotFix.md
│   └── Windows-Update-Troubleshooting.md
│
├── 13-Windows-Security/
│   ├── Get-MpComputerStatus.md
│   ├── Get-MpThreatDetection.md
│   ├── Get-NetFirewallProfile.md
│   └── Get-NetFirewallRule.md
│
├── 14-Registry/
│   ├── Get-ItemProperty.md
│   ├── Get-ChildItem-Registry.md
│   └── Registry-Troubleshooting.md
│
├── 15-Scheduled-Tasks/
│   ├── Get-ScheduledTask.md
│   ├── Get-ScheduledTaskInfo.md
│   └── Scheduled-Task-Troubleshooting.md
│
├── 16-Remote-Management/
│   ├── Test-WSMan.md
│   ├── Invoke-Command.md
│   ├── Enter-PSSession.md
│   └── New-PSSession.md
│
├── 17-Drivers-Devices/
│   ├── Get-PnpDevice.md
│   ├── Get-CimInstance-Pnp.md
│   └── Driver-Troubleshooting.md
│
├── 18-Entra-ID/
│   ├── dsregcmd.md
│   └── Entra-Device-Troubleshooting.md
│
├── 19-Intune-Endpoint/
│   ├── Intune-Management-Extension.md
│   ├── IME-Logs.md
│   ├── MDM-Diagnostics.md
│   └── Endpoint-Troubleshooting.md
│
├── 20-Autopilot/
│   ├── Autopilot-Diagnostics.md
│   ├── ESP-Troubleshooting.md
│   └── Enrollment-Troubleshooting.md
│
├── 21-Performance-Monitoring/
│   ├── Get-Counter.md
│   ├── perfmon.md
│   └── Performance-Troubleshooting.md
│
└── 22-Incident-Playbooks/
    ├── High-CPU.md
    ├── High-Memory.md
    ├── Disk-Full.md
    ├── Service-Failure.md
    ├── DNS-Failure.md
    ├── Network-Connectivity.md
    ├── Windows-Update-Failure.md
    ├── GPO-Not-Applying.md
    ├── Application-Crash.md
    ├── Intune-App-Failure.md
    └── Device-Not-Communicating.md
```

---

# 🛠️ Core Learning Areas

| #  | Area                     | Primary Focus                                  |
| -- | ------------------------ | ---------------------------------------------- |
| 01 | System Information       | OS, hardware and system configuration          |
| 02 | Processes / CPU / Memory | Resource utilization and process investigation |
| 03 | Services                 | Service state, dependencies and failures       |
| 04 | Event Logs               | System, application and security events        |
| 05 | Networking               | Adapters, IP configuration, TCP and routing    |
| 06 | DNS                      | Name resolution and DNS troubleshooting        |
| 07 | Disk / Storage           | Disks, partitions, volumes and capacity        |
| 08 | Files / Permissions      | Filesystem access and ACLs                     |
| 09 | Users / Groups           | Local identity and authorization               |
| 10 | Active Directory         | Users, computers, groups and directory health  |
| 11 | Group Policy             | Policy processing and troubleshooting          |
| 12 | Windows Update           | Update state and servicing issues              |
| 13 | Security                 | Defender, firewall and security state          |
| 14 | Registry                 | Configuration and troubleshooting              |
| 15 | Scheduled Tasks          | Task execution and failures                    |
| 16 | Remote Management        | WinRM and PowerShell remoting                  |
| 17 | Drivers / Devices        | Device and driver investigation                |
| 18 | Entra ID                 | Device registration and identity               |
| 19 | Intune                   | MDM, IME and endpoint management               |
| 20 | Autopilot                | Enrollment and ESP troubleshooting             |
| 21 | Performance Monitoring   | Counters and deeper performance analysis       |
| 22 | Incident Playbooks       | End-to-end troubleshooting scenarios           |

---

# 🔗 From Commands to Troubleshooting

Individual commands are useful, but their real value comes from combining them.

For example:

```text
Application is slow
        │
        ▼
Get-Process
        │
        ▼
Is CPU / memory unusually high?
        │
        ├── Yes ──► Investigate process
        │
        └── No
              │
              ▼
        Get-Counter
              │
              ▼
        Check system performance
              │
              ▼
        Get-WinEvent
              │
              ▼
        Investigate application/system errors
```

The repository will gradually transform individual commands into reusable troubleshooting workflows.

---

# 🚨 Incident Playbooks

The final stage of the learning process is to apply individual commands to realistic incidents.

Examples include:

### Windows Server

* High CPU
* High memory
* Disk space exhaustion
* Service failure
* Application crash
* Network connectivity failure
* DNS failure
* Port connectivity problem
* Windows Update failure
* Group Policy not applying
* Authentication failure

### Windows Endpoint

* Device not communicating
* Application deployment failure
* Intune Management Extension issue
* Entra device registration problem
* Windows Update issue
* Autopilot enrollment failure
* ESP failure

Each playbook will follow:

```text
Problem
   ↓
Initial Checks
   ↓
Evidence Collection
   ↓
Diagnostic Commands
   ↓
Output Interpretation
   ↓
Decision Points
   ↓
Root Cause
   ↓
Remediation
   ↓
Verification
```

---

# 🔄 Windows and Linux Comparison

Where useful, Windows concepts will be compared with Linux equivalents.

| Windows                | Linux                 |
| ---------------------- | --------------------- |
| `Get-Process`          | `ps`, `top`           |
| `Get-Service`          | `systemctl`           |
| `Get-WinEvent`         | `journalctl`          |
| `Get-NetTCPConnection` | `ss`                  |
| `Test-NetConnection`   | `nc`, `curl`          |
| `Resolve-DnsName`      | `dig`                 |
| `Get-Disk`             | `lsblk`               |
| `Get-Volume`           | `df`                  |
| `Get-Acl`              | `getfacl`, `ls -l`    |
| PowerShell pipeline    | Bash pipeline         |
| Task Scheduler         | cron / systemd timers |
| Windows Services       | systemd               |
| Event Viewer           | journald / log files  |
| Windows Firewall       | firewalld / nftables  |

These comparisons are intended to build transferable operating-system troubleshooting concepts rather than imply that the technologies are identical.

---

# ⚡ PowerShell and Automation

PowerShell is not treated only as a command-line interface in this repository.

The learning path will gradually progress from:

```text
Execute a command
       ↓
Understand objects
       ↓
Filter and select data
       ↓
Combine commands
       ↓
Build diagnostic workflows
       ↓
Automate repetitive tasks
```

For example:

```powershell
Get-Service |
    Where-Object Status -eq 'Stopped'
```

The goal is to understand how PowerShell objects can be:

* Filtered
* Sorted
* Selected
* Grouped
* Exported
* Passed between commands
* Used in automation

---

# 🟢 Command Safety

Commands will be considered according to their potential impact.

### 🟢 Read-only

Primarily collects information.

```powershell
Get-Process
Get-Service
Get-WinEvent
Get-Disk
Get-NetIPConfiguration
```

### 🟡 State-changing

Changes system state.

```powershell
Restart-Service
Stop-Process
Restart-Computer
Clear-DnsClientCache
```

### 🔴 Potentially destructive

May remove data or significantly alter system configuration.

```powershell
Remove-Item
Remove-LocalUser
Remove-ADUser
Format-Volume
```

> **Always understand the command, parameters, scope and potential impact before executing it on a production system.**

---

# 🧪 Hands-On Learning

This repository is designed to be used with a Windows lab environment.

For every command:

```text
1. Read
   ↓
2. Execute
   ↓
3. Observe
   ↓
4. Interpret
   ↓
5. Answer the four questions
   ↓
6. Try variations
   ↓
7. Determine the next diagnostic step
   ↓
8. Verify
```

A command is considered **learned** when its purpose, output and place in a troubleshooting workflow are understood—not simply because it has been executed once.

---

# 📈 Learning Roadmap

The repository will be developed incrementally.

| Phase    | Focus                                    |
| -------- | ---------------------------------------- |
| Phase 1  | Windows system information and discovery |
| Phase 2  | Processes, CPU and memory                |
| Phase 3  | Services and Event Logs                  |
| Phase 4  | Networking and DNS                       |
| Phase 5  | Storage, files and permissions           |
| Phase 6  | Users, groups and Group Policy           |
| Phase 7  | Active Directory                         |
| Phase 8  | Windows Update and Security              |
| Phase 9  | Remote Management                        |
| Phase 10 | Entra ID                                 |
| Phase 11 | Intune and Endpoint Management           |
| Phase 12 | Windows Autopilot                        |
| Phase 13 | Performance Monitoring                   |
| Phase 14 | Incident Playbooks                       |
| Phase 15 | Automation and advanced troubleshooting  |

---

# 🎯 End Goal

The ultimate objective is to develop the ability to move from:

> **"I know this PowerShell command."**

to:

> **"I understand the symptom, know what evidence to collect, can select the right diagnostic command, interpret the result, determine the next troubleshooting step, identify the root cause, remediate the problem, and verify the outcome."**

This repository is therefore intended to become more than a command reference.

It is a **hands-on Windows troubleshooting and automation learning playbook**.

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

## ⚠️ Disclaimer

This repository is intended for **learning, lab practice and technical reference**.

Commands and troubleshooting procedures should be validated in an appropriate non-production environment before being used in production.

Some commands require administrative privileges and some can modify system state or cause data loss. Always understand the command, its parameters and its impact before execution.
