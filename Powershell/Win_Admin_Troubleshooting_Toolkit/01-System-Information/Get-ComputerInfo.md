# Get-ComputerInfo

## 🎯 Purpose

`Get-ComputerInfo` retrieves a consolidated set of system and operating system properties from a Windows computer.

It is useful as a **first-level system discovery command** when you need a broad overview of a Windows Server or Endpoint before investigating a specific problem.

---

## 📌 Command Type

**PowerShell cmdlet**

**Module:** `Microsoft.PowerShell.Management`

**Output:** `Microsoft.PowerShell.Management.ComputerInfo`

---

## 🧾 Syntax

```powershell
Get-ComputerInfo
```

To retrieve only selected properties:

```powershell
Get-ComputerInfo -Property "WindowsProductName", "WindowsVersion", "OsBuildNumber", "CsName"
```

---

# 1️⃣ What does it show?

`Get-ComputerInfo` returns a consolidated object containing information about the operating system and computer.

Examples of useful information include:

| Property                | What it tells you            |
| ----------------------- | ---------------------------- |
| `WindowsProductName`    | Windows edition/product name |
| `WindowsVersion`        | Windows version              |
| `OsBuildNumber`         | Windows OS build             |
| `OsArchitecture`        | OS architecture              |
| `CsName`                | Computer name                |
| `CsManufacturer`        | System manufacturer          |
| `CsModel`               | System model                 |
| `CsTotalPhysicalMemory` | Installed physical memory    |
| `BiosManufacturer`      | BIOS manufacturer            |
| `BiosVersion`           | BIOS version                 |
| `OsInstallDate`         | OS installation date         |
| `OsLastBootUpTime`      | Last system boot time        |

The command is particularly useful when you need a **quick baseline of the machine** rather than information about only one subsystem.

---

# 2️⃣ What problem would make me run it?

Run `Get-ComputerInfo` when you need to establish the basic identity and configuration of a Windows machine.

### Example scenarios

#### Scenario 1 — Application behaves differently on two machines

You can compare:

* Windows edition
* Windows version
* OS build
* Architecture
* Manufacturer
* Model
* BIOS information

```powershell
Get-ComputerInfo
```

#### Scenario 2 — Troubleshooting a Windows update issue

First establish:

```text
What Windows version is installed?
        ↓
What OS build is installed?
        ↓
When was the OS installed?
        ↓
When was the machine last rebooted?
```

#### Scenario 3 — Unknown machine

You have remote access to a machine but do not yet know its configuration.

```powershell
Get-ComputerInfo |
    Select-Object WindowsProductName,
                  WindowsVersion,
                  OsBuildNumber,
                  OsArchitecture,
                  CsName,
                  CsManufacturer,
                  CsModel
```

---

# 3️⃣ How do I interpret the output?

Do not attempt to interpret every property returned by the command.

Start with the properties relevant to the problem.

### Example

```powershell
Get-ComputerInfo |
    Select-Object WindowsProductName,
                  WindowsVersion,
                  OsBuildNumber,
                  CsName,
                  CsModel,
                  OsLastBootUpTime
```

Example interpretation:

```text
WindowsProductName : Microsoft Windows 11 Enterprise
WindowsVersion     : 24H2
OsBuildNumber      : 26100
CsName             : WIN11-CLIENT01
CsModel            : Latitude 7450
OsLastBootUpTime   : 10/01/2026 08:42:15
```

You can immediately establish:

* Which Windows edition is installed.
* Which Windows release is installed.
* Which OS build is running.
* Which computer you are investigating.
* Which hardware model is involved.
* When the system last booted.

### Important troubleshooting principle

A value being present does **not** automatically mean it is the cause of the problem.

Use the result to determine the **next diagnostic question**.

---

# 4️⃣ What would I run next based on the result?

The next command depends on what you discovered.

| Finding                           | Possible next command       |
| --------------------------------- | --------------------------- |
| OS build looks unexpected         | `Get-Win32-OperatingSystem` |
| Hardware information is required  | `Get-Win32-ComputerSystem`  |
| BIOS/firmware needs investigation | `Get-Win32-BIOS`            |
| Need detailed CIM information     | `Get-CimInstance`           |
| Need native Windows fallback      | `systeminfo`                |
| Need update information           | `Get-HotFix`                |
| Need performance investigation    | `Get-Counter`               |

---

# 🧪 Practical Examples

### Get complete system information

```powershell
Get-ComputerInfo
```

### Display the most useful baseline properties

```powershell
Get-ComputerInfo |
    Select-Object WindowsProductName,
                  WindowsVersion,
                  OsBuildNumber,
                  OsArchitecture,
                  CsName,
                  CsManufacturer,
                  CsModel,
                  CsTotalPhysicalMemory,
                  OsLastBootUpTime
```

### Find properties related to the operating system

```powershell
Get-ComputerInfo -Property "Os*"
```

### Find properties related to the computer system

```powershell
Get-ComputerInfo -Property "Cs*"
```

---

# 🔗 Related Commands

* `Get-CimInstance`
* `Get-Win32-OperatingSystem`
* `Get-Win32-ComputerSystem`
* `Get-Win32-BIOS`
* `systeminfo`

---

# 🐧 Linux Equivalent

There is no single exact equivalent.

A basic Linux system overview can be obtained using:

```bash
hostnamectl
```

```bash
uname -a
```

```bash
cat /etc/os-release
```

For hardware information:

```bash
sudo lshw
```

---

# ⚠️ Risk Level

🟢 **Read-only**

`Get-ComputerInfo` is intended for information gathering and does not modify system configuration.

---

# 🧠 Troubleshooting Takeaway

> **Use `Get-ComputerInfo` when you need a broad first look at a Windows machine before narrowing the investigation to a specific subsystem.**
