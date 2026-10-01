# systeminfo

## 🎯 Purpose

`systeminfo` is a native Windows command-line utility that displays detailed configuration information about a computer and its operating system.

It provides information about:

* Operating system configuration
* Windows version
* Security information
* Product information
* Hardware
* Memory
* Network adapters
* System configuration

It is especially useful as a **native CLI fallback** when PowerShell/CIM-based investigation is unavailable, inconvenient, or needs to be cross-checked.

---

## 📌 Command Type

**Native Windows command-line utility**

Executable:

```text
systeminfo.exe
```

It can be executed from:

* Command Prompt
* PowerShell
* Windows Terminal
* Scripts

---

# 🧾 Syntax

```cmd
systeminfo
```

Remote computer:

```cmd
systeminfo /s SERVER01
```

List format:

```cmd
systeminfo /fo LIST
```

CSV format:

```cmd
systeminfo /fo CSV
```

Table format:

```cmd
systeminfo /fo TABLE
```

---

# 1️⃣ What does it show?

`systeminfo` provides a broad system configuration snapshot.

Typical information includes:

* Host name
* OS name
* OS version
* OS build
* OS manufacturer
* OS configuration
* OS installation date
* System boot time
* System manufacturer
* System model
* System type
* Processor information
* BIOS version
* Windows directory
* System directory
* Boot device
* System locale
* Time zone
* Physical memory
* Network cards
* Hotfix information
* Domain/workgroup information
* Windows security information

---

# 2️⃣ What problem would make me run it?

### Scenario 1 — PowerShell/CIM investigation is unavailable

If you cannot use your normal PowerShell/CIM workflow, try:

```cmd
systeminfo
```

It provides a broad system snapshot without requiring you to remember several CIM classes.

---

### Scenario 2 — Need a quick machine baseline

```cmd
systeminfo
```

This is useful during an initial support or troubleshooting session.

---

### Scenario 3 — Need information from a remote computer

```cmd
systeminfo /s SERVER01
```

This can be useful when you need a quick remote system information query.

---

### Scenario 4 — Need machine-readable output

For CSV:

```cmd
systeminfo /fo CSV
```

This is useful when the output needs to be consumed by another process or stored for later analysis.

---

# 3️⃣ How do I interpret the output?

Example:

```text
Host Name:                 WIN11-CLIENT01
OS Name:                   Microsoft Windows 11 Enterprise
OS Version:                10.0.26100 N/A Build 26100
System Manufacturer:       Dell Inc.
System Model:              Latitude 7450
System Type:               x64-based PC
Total Physical Memory:     16,192 MB
Domain:                    CONTOSO
```

Interpret the output according to the troubleshooting question.

### OS investigation

Look at:

```text
OS Name
OS Version
OS Configuration
OS Build
```

### Hardware investigation

Look at:

```text
System Manufacturer
System Model
System Type
Processor(s)
Total Physical Memory
```

### Identity/domain investigation

Look at:

```text
Host Name
Domain
Logon Server
```

### Update investigation

Review:

```text
Hotfix(s)
```

However, use dedicated Windows Update and servicing tools when performing a deeper update investigation.

---

# 4️⃣ What would I run next based on the result?

`systeminfo` is primarily a **discovery command**.

Use its results to choose a more focused diagnostic tool.

| Finding             | Next investigation                                    |
| ------------------- | ----------------------------------------------------- |
| OS build issue      | Windows Update investigation                          |
| Hardware issue      | `Get-Win32-ComputerSystem`                            |
| BIOS issue          | `Get-Win32-BIOS`                                      |
| Unexpected reboot   | `Get-WinEvent`                                        |
| Network issue       | `Get-NetIPConfiguration`                              |
| Domain issue        | `Get-Win32-ComputerSystem` / identity tools           |
| Performance issue   | `Get-Counter`                                         |
| Device/driver issue | `Get-PnpDevice`                                       |
| No obvious issue    | Move to the subsystem related to the reported symptom |

The troubleshooting pattern becomes:

```text
systeminfo
    ↓
Establish system baseline
    ↓
Identify suspicious / relevant information
    ↓
Select a focused diagnostic command
    ↓
Investigate
```

---

# 🧪 Practical Examples

### Basic system information

```cmd
systeminfo
```

### List format

```cmd
systeminfo /fo LIST
```

List format can be easier to read when investigating individual properties.

### CSV output

```cmd
systeminfo /fo CSV
```

Useful for collecting information programmatically.

### Remote computer

```cmd
systeminfo /s SERVER01
```

### Remote computer with explicit credentials

```cmd
systeminfo /s SERVER01 /u CONTOSO\AdminUser
```

Avoid placing passwords directly into command history or scripts.

---

# 🔄 PowerShell Comparison

A common PowerShell equivalent for broad system discovery is:

```powershell
Get-ComputerInfo
```

CIM-based alternatives include:

```powershell
Get-CimInstance Win32_OperatingSystem
```

```powershell
Get-CimInstance Win32_ComputerSystem
```

```powershell
Get-CimInstance Win32_BIOS
```

Conceptually:

```text
systeminfo
   │
   └── Broad native Windows system snapshot


Get-ComputerInfo
   │
   └── Broad PowerShell system snapshot


Get-CimInstance
   │
   ├── Win32_OperatingSystem
   ├── Win32_ComputerSystem
   ├── Win32_BIOS
   └── Other CIM classes
```

---

# 🐧 Linux Equivalent

There is no single exact equivalent.

Common Linux discovery commands include:

```bash
hostnamectl
```

```bash
uname -a
```

```bash
lscpu
```

```bash
free -h
```

```bash
lsblk
```

---

# ⚠️ Risk Level

🟢 **Read-only**

`systeminfo` retrieves system information and does not modify the system configuration.

---

# 🧠 Troubleshooting Takeaway

> **Use `systeminfo` as a broad native Windows discovery tool and as a useful fallback or cross-check when you need system information outside a PowerShell/CIM workflow.**