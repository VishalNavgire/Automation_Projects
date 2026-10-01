# Get-CimInstance

## 🎯 Purpose

`Get-CimInstance` retrieves CIM (Common Information Model) instances from a CIM server.

On Windows, it is one of the primary PowerShell mechanisms for retrieving structured system information from WMI/CIM classes.

Think of it as the **engine you use to query many Windows management classes**.

---

## 📌 Command Type

**PowerShell cmdlet**

**Module:** `CimCmdlets`

**Alias:** `gcim`

---

## 🧾 Syntax

Basic syntax:

```powershell
Get-CimInstance -ClassName <ClassName>
```

Examples:

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem
```

```powershell
Get-CimInstance -ClassName Win32_ComputerSystem
```

```powershell
Get-CimInstance -ClassName Win32_BIOS
```

---

# 1️⃣ What does it show?

The command retrieves objects representing instances of a specified CIM class.

For example:

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem
```

queries the `Win32_OperatingSystem` class.

Similarly:

```powershell
Get-CimInstance -ClassName Win32_ComputerSystem
```

queries computer-system information.

The important concept is:

```text
Get-CimInstance
       │
       ├── Win32_OperatingSystem
       │
       ├── Win32_ComputerSystem
       │
       ├── Win32_BIOS
       │
       ├── Win32_Processor
       │
       ├── Win32_PhysicalMemory
       │
       └── many other CIM classes
```

Therefore, `Get-CimInstance` itself is **not the data source/class**.

It is the PowerShell cmdlet used to retrieve information from a selected CIM class.

---

# 2️⃣ What problem would make me run it?

Use `Get-CimInstance` when the basic system overview is not enough and you need information from a specific Windows management class.

### Scenario 1 — Need precise OS information

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem
```

### Scenario 2 — Need hardware information

```powershell
Get-CimInstance -ClassName Win32_ComputerSystem
```

### Scenario 3 — Need BIOS information

```powershell
Get-CimInstance -ClassName Win32_BIOS
```

### Scenario 4 — Need information from a remote computer

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem `
    -ComputerName SERVER01
```

This makes CIM useful not only for local troubleshooting but also for administration and automation.

---

# 3️⃣ How do I interpret the output?

The output depends entirely on the CIM class being queried.

For example:

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem
```

might return properties such as:

```text
Caption
Version
BuildNumber
InstallDate
LastBootUpTime
OSArchitecture
SerialNumber
```

You should normally select only the properties relevant to your investigation.

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption,
                  Version,
                  BuildNumber,
                  OSArchitecture,
                  LastBootUpTime
```

### Important concept

Do not think:

> `Get-CimInstance` = operating system information.

Think:

> `Get-CimInstance` + **CIM Class** = specific management information.

---

# 4️⃣ What would I run next based on the result?

The next step depends on the class and the result.

| Investigation         | Command                                 |
| --------------------- | --------------------------------------- |
| OS information        | `Get-CimInstance Win32_OperatingSystem` |
| Hardware identity     | `Get-CimInstance Win32_ComputerSystem`  |
| BIOS/firmware         | `Get-CimInstance Win32_BIOS`            |
| Processor             | `Get-CimInstance Win32_Processor`       |
| Physical memory       | `Get-CimInstance Win32_PhysicalMemory`  |
| Processes             | `Get-CimInstance Win32_Process`         |
| Plug and Play devices | `Get-CimInstance Win32_PnPEntity`       |

If the query fails against a remote computer, investigate:

```text
Computer reachable?
        ↓
CIM/WMI access available?
        ↓
Authentication / permissions?
        ↓
Firewall / remoting?
        ↓
CIM session required?
```

---

# 🧪 Practical Examples

### Query operating system information

```powershell
Get-CimInstance -ClassName Win32_OperatingSystem
```

### Query only selected properties

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object Caption,
                  Version,
                  BuildNumber
```

### Query computer information

```powershell
Get-CimInstance Win32_ComputerSystem |
    Select-Object Manufacturer,
                  Model,
                  TotalPhysicalMemory,
                  Domain,
                  PartOfDomain
```

### Query BIOS information

```powershell
Get-CimInstance Win32_BIOS |
    Select-Object Manufacturer,
                  SMBIOSBIOSVersion,
                  SerialNumber,
                  ReleaseDate
```

### Use a filter

```powershell
Get-CimInstance Win32_Process |
    Where-Object Name -eq "explorer.exe"
```

### Query a remote computer

```powershell
Get-CimInstance Win32_OperatingSystem `
    -ComputerName SERVER01
```

---

# 🔬 Why `Get-CimInstance` matters for automation

CIM returns structured PowerShell objects rather than just screen text.

That makes the information easy to:

* Filter
* Select
* Sort
* Compare
* Export
* Store
* Process in scripts
* Use in automation

For example:

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object PSComputerName,
                  Caption,
                  Version,
                  BuildNumber
```

This can form the foundation of a system-inventory or troubleshooting script.

---

# 🔗 Related Commands

* `Get-ComputerInfo`
* `Get-CimClass`
* `Get-CimSession`
* `New-CimSession`
* `Get-Win32-OperatingSystem`
* `Get-Win32-ComputerSystem`
* `Get-Win32-BIOS`

---

# 🐧 Linux Equivalent

Linux does not have a direct equivalent to the Windows CIM model.

Comparable commands depend on the information required:

```bash
uname -a
```

```bash
hostnamectl
```

```bash
lscpu
```

```bash
lsblk
```

```bash
dmidecode
```

The key conceptual difference is that Windows exposes many management objects through CIM/WMI, whereas Linux commonly uses individual utilities and interfaces.

---

# ⚠️ Risk Level

🟢 **Read-only**

`Get-CimInstance` retrieves CIM information. The cmdlet itself does not modify the retrieved CIM objects.

---

# 🧠 Troubleshooting Takeaway

> **`Get-CimInstance` is the general-purpose PowerShell mechanism for querying Windows management information through CIM classes. The class you specify determines what information you actually investigate.**