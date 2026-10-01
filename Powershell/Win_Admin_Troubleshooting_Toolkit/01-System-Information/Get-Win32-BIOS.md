# Get-Win32-BIOS

## 🎯 Purpose

`Win32_BIOS` is a CIM/WMI class that represents the BIOS attributes installed on a computer.

It is particularly useful for investigating:

* BIOS/firmware version
* BIOS manufacturer
* BIOS serial number
* BIOS release date
* SMBIOS version
* Firmware-related hardware issues

> **Important:** `Win32_BIOS` is a CIM class, not a PowerShell cmdlet.

Query it using:

```powershell
Get-CimInstance Win32_BIOS
```

---

# 1️⃣ What does it show?

Useful properties include:

| Property                 | What it tells you                       |
| ------------------------ | --------------------------------------- |
| `Manufacturer`           | BIOS manufacturer                       |
| `SMBIOSBIOSVersion`      | BIOS version reported through SMBIOS    |
| `Version`                | BIOS version string                     |
| `SerialNumber`           | BIOS/system firmware serial information |
| `ReleaseDate`            | BIOS release date                       |
| `SMBIOSMajorVersion`     | SMBIOS major version                    |
| `SMBIOSMinorVersion`     | SMBIOS minor version                    |
| `SMBIOSPresent`          | Whether SMBIOS information is present   |
| `SystemBiosMajorVersion` | System BIOS major release               |
| `SystemBiosMinorVersion` | System BIOS minor release               |

---

# 2️⃣ What problem would make me run it?

### Scenario 1 — Firmware version verification

A device is experiencing a hardware-related problem.

Check:

```powershell
Get-CimInstance Win32_BIOS |
    Select-Object Manufacturer,
                  SMBIOSBIOSVersion,
                  ReleaseDate
```

You can compare the result against the firmware version expected for the device model.

---

### Scenario 2 — BIOS update investigation

A vendor has released a firmware update to address a hardware issue.

First establish the currently installed BIOS:

```powershell
Get-CimInstance Win32_BIOS |
    Select-Object Manufacturer,
                  Version,
                  ReleaseDate
```

Then determine whether the installed version requires further investigation.

---

### Scenario 3 — Hardware inventory

For inventory purposes:

```powershell
Get-CimInstance Win32_BIOS |
    Select-Object Manufacturer,
                  SMBIOSBIOSVersion,
                  SerialNumber
```

---

# 3️⃣ How do I interpret the output?

Example:

```text
Manufacturer       : Dell Inc.
SMBIOSBIOSVersion  : 1.18.0
SerialNumber       : ABC1234
ReleaseDate        : 01/15/2026
SMBIOSPresent      : True
```

Interpret it as:

```text
Manufacturer
 ↓
Who supplied the BIOS?

SMBIOSBIOSVersion
 ↓
What BIOS version does SMBIOS report?

SerialNumber
 ↓
What firmware/system serial information is reported?

ReleaseDate
 ↓
What release date does the BIOS report?

SMBIOSPresent
 ↓
Is SMBIOS information available?
```

### Important troubleshooting principle

A BIOS version being old does not automatically prove that it is causing the reported problem.

Treat it as evidence that may justify the next investigation.

---

# 4️⃣ What would I run next based on the result?

| Finding                        | Next investigation                          |
| ------------------------------ | ------------------------------------------- |
| BIOS version is unexpected     | Compare against vendor firmware information |
| BIOS is older than expected    | Investigate firmware update requirements    |
| Serial number is unexpected    | Verify hardware inventory                   |
| SMBIOS information unavailable | Investigate firmware/hardware reporting     |
| BIOS looks normal              | Continue with OS/device/event investigation |
| Need hardware model            | `Get-Win32-ComputerSystem`                  |
| Need OS build                  | `Get-Win32-OperatingSystem`                 |

---

# 🧪 Practical Examples

### Complete BIOS information

```powershell
Get-CimInstance Win32_BIOS
```

### Useful firmware information

```powershell
Get-CimInstance Win32_BIOS |
    Select-Object Manufacturer,
                  SMBIOSBIOSVersion,
                  Version,
                  ReleaseDate,
                  SerialNumber
```

### Firmware inventory object

```powershell
$bios = Get-CimInstance Win32_BIOS

[PSCustomObject]@{
    Manufacturer      = $bios.Manufacturer
    BIOSVersion       = $bios.SMBIOSBIOSVersion
    BIOSReleaseDate   = $bios.ReleaseDate
    SerialNumber      = $bios.SerialNumber
    SMBIOSVersion     = "$($bios.SMBIOSMajorVersion).$($bios.SMBIOSMinorVersion)"
}
```

---

# 🔗 Related Commands

* `Get-ComputerInfo`
* `Get-PnpDevice`

---

# 🐧 Linux Equivalent

Firmware information can commonly be investigated with:

```bash
sudo dmidecode -t bios
```

On some systems:

```bash
sudo dmidecode -t system
```

---

# ⚠️ Risk Level

🟢 **Read-only**

The examples in this document only retrieve BIOS information.

---

# 🧠 Troubleshooting Takeaway

> **Use `Win32_BIOS` when firmware version, BIOS identity or SMBIOS information could be relevant to a hardware or system problem.**