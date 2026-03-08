
<div align="center">

# 🔄 Windows Device Mandatory Reboot Notifier

[![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python\&logoColor=white)](https://python.org)
[![PowerShell](https://img.shields.io/badge/PowerShell-Automation-5391FE?logo=powershell\&logoColor=white)](https://learn.microsoft.com/powershell/)
[![Microsoft Intune](https://img.shields.io/badge/Microsoft%20Intune-Endpoint%20Management-blue?logo=microsoft\&logoColor=white)](https://learn.microsoft.com/mem/intune/)
[![Windows](https://img.shields.io/badge/Windows-Device%20Management-0078D6?logo=windows\&logoColor=white)](https://learn.microsoft.com/windows/)
[![Automation](https://img.shields.io/badge/Automation-Enterprise-green)]()

**Enterprise endpoint automation solution that detects long-running Windows devices and forces users to reboot through a controlled GUI notification system.**

</div>

---

# 📖 Overview

In enterprise environments, **long-running Windows devices that are not rebooted regularly can cause serious issues**, including:

* Delayed Windows Updates
* Intune policy failures
* Security patching delays
* System performance degradation
* Application instability

To solve this problem, this project provides an **automated reboot reminder system** deployed through **Microsoft Intune**.

The solution works by:

1️⃣ Detecting when a Windows machine has not rebooted in **10 days or more**
2️⃣ Triggering a **scheduled task** on the endpoint
3️⃣ Displaying a **custom Python GUI notification** to the user
4️⃣ Allowing limited snooze attempts before enforcing a **mandatory reboot**

This approach ensures **compliance, security, and device stability** across enterprise-managed Windows environments.

---

# ✨ Key Features

| Feature                             | Description                                         |
| ----------------------------------- | --------------------------------------------------- |
| 🔍 **Reboot Detection Engine**      | Detects last reboot time from Windows Event Logs    |
| ⏰ **Automated Scheduling**          | Uses Windows Task Scheduler for periodic monitoring |
| 🖥 **Interactive GUI Notification** | Python-based reboot reminder with countdown timer   |
| ⏳ **Controlled Snooze System**      | Allows limited postponement attempts                |
| 🔒 **Forced Reboot Enforcement**    | Device automatically restarts when timer expires    |
| 🧠 **User Context Awareness**       | Displays logged-in username and hostname            |
| 🎨 **Custom Branded UI**            | Supports company branding with logos                |
| 📦 **Intune Deployment Ready**      | Designed as a Win32 application package             |
| 🧹 **Clean Uninstall Process**      | Removes tasks, files, and configuration             |

---

# 🏗️ Architecture

The solution consists of **PowerShell automation, scheduled task orchestration, and a Python-based GUI application**.

```
Windows-Device-Reboot-Notifier
│
├── Deployment Automation
│   ├── Copy&CreateTaskSchd.ps1
│   │   └── Copies required files to endpoint
│   │   └── Registers Windows Scheduled Task
│
├── Scheduled Task Configuration
│   └── Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd.xml
│       └── Defines triggers and execution schedule
│
├── Reboot Detection Engine
│   └── Detect_Pending_Win_Device_Reboot_Status.ps1
│       ├── Reads Windows Event Logs
│       ├── Determines last reboot timestamp
│       └── Writes status to log file
│
├── User Notification Engine
│   └── Windows_Device_Reboot_Prompt_Python_GUI.exe
│       ├── Displays reboot alert GUI
│       ├── Countdown timer
│       ├── Restart Now / Restart Later options
│       └── Forced reboot enforcement
│
└── Uninstall Process
    └── Delete&RemoveTaskSchd.ps1
        ├── Deletes scheduled task
        ├── Removes deployed files
        └── Cleans installation directory
```

---

# ⚙️ Technology Stack

### Endpoint Automation

* PowerShell
* Windows Task Scheduler

### GUI Application

* Python
* Tkinter
* Pillow (PIL)

### Endpoint Management

* Microsoft Intune
* Win32 App Deployment

---

# 📁 Project Structure

This repository contains the following files:

| File                                                 | Purpose                                                                            |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------- |
| **Copy&CreateTaskSchd.ps1**                          | Master deployment script that copies files to endpoints and creates scheduled task |
| **Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd.xml** | Scheduled task configuration with triggers                                         |
| **Detect_Pending_Win_Device_Reboot_Status.ps1**      | Detects last reboot time using Windows event logs                                  |
| **Windows_Device_Reboot_Prompt_Python_GUI.exe**      | Python-based GUI prompt displayed to end users                                     |
| **Delete&RemoveTaskSchd.ps1**                        | Uninstall script that removes files and scheduled tasks                            |

---

# 🚀 How the Solution Works

### Step 1 — Deployment via Intune

The project is deployed as a **Win32 App through Microsoft Intune**.

The deployment script:

```
Copy&CreateTaskSchd.ps1
```

performs the following actions:

* Creates a working directory
* Copies required files
* Registers the scheduled task

---

### Step 2 — Scheduled Task Execution

The task scheduler configuration:

```
Custom_Win_Device_Reboot_GUI_Prompt_TaskSchd.xml
```

runs periodically and executes the reboot detection script.

---

### Step 3 — Reboot Detection

The script:

```
Detect_Pending_Win_Device_Reboot_Status.ps1
```

checks Windows **Event Logs** to determine:

* Last reboot timestamp
* If reboot threshold (10 days) is exceeded

---

### Step 4 — User Notification

If reboot is required, the system launches:

```
Windows_Device_Reboot_Prompt_Python_GUI.exe
```

The GUI displays:

* Logged-in user name
* Device hostname
* Countdown timer
* Restart options

---

### Step 5 — Controlled Reboot Enforcement

Users can:

* Restart immediately
* Snooze (limited attempts)

If the countdown reaches zero:

```
Forced reboot is triggered automatically
```

---

# 🖥 GUI Features

The Python GUI application provides:

* Countdown timer
* Restart now option
* Restart later option (limited)
* Corporate branding support
* Always-on-top window
* Disabled close button

This ensures **users cannot bypass the reboot notification**.

---

# 📊 Example Workflow

```
Device uptime exceeds 10 days
        │
        ▼
Scheduled Task triggers detection script
        │
        ▼
Reboot status confirmed
        │
        ▼
Python GUI launched
        │
        ▼
User chooses:
   ├─ Restart Now
   └─ Restart Later (limited)
        │
        ▼
Timer expires → Forced Reboot
```

---

# 🔐 Security Considerations

The solution follows enterprise security practices:

* No hardcoded credentials
* Local execution only
* No external network calls
* Uses Windows native logging
* Works under enterprise device management policies

---

# 🛠 Troubleshooting

### GUI does not appear

Check:

* Scheduled task status
* Python GUI executable location
* Log output from detection script

---

### Scheduled task not created

Verify:

* Script execution policy
* Administrative privileges
* Task scheduler XML configuration

---

### Reboot detection incorrect

Confirm:

* Event log access permissions
* Windows system log availability

---

# 🚀 Future Enhancements

Potential improvements for future versions:

* Intune compliance reporting
* Centralized logging
* Custom reboot policies per device group
* Toast notification support
* Multi-language GUI
* Azure Monitor integration

---

# 👨‍💻 Author

**Vishal Navgire**

Cloud & Endpoint Automation Engineer

---

<div align="center">

### ⭐ Built for Enterprise Endpoint Engineers & Intune Administrators

</div>

