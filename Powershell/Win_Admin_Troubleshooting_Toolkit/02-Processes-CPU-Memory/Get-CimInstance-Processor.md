# Get-CimInstance — Win32_Processor

## 🎯 Purpose

This document covers processor information retrieved through:

```powershell
Get-CimInstance Win32_Processor
```

`Win32_Processor` is a CIM/WMI class representing a processor on a Windows computer. Microsoft documents properties such as processor name, number of cores, logical processors, maximum clock speed and architecture information.

> **Important:** `Get-CimInstance-Processor.md` is the documentation filename. There is no cmdlet named `Get-CimInstance-Processor`.

---

# 1️⃣ What does it show?

Useful processor properties include:

| Property                        | What it tells you                         |
| ------------------------------- | ----------------------------------------- |
| `Name`                          | Processor name                            |
| `Manufacturer`                  | Processor manufacturer                    |
| `NumberOfCores`                 | Number of physical cores reported         |
| `NumberOfLogicalProcessors`     | Number of logical processors              |
| `MaxClockSpeed`                 | Maximum processor speed in MHz            |
| `CurrentClockSpeed`             | Current reported processor speed          |
| `Architecture`                  | Processor architecture                    |
| `AddressWidth`                  | Processor address width                   |
| `SocketDesignation`             | Processor socket designation              |
| `VirtualizationFirmwareEnabled` | Firmware virtualization capability/status |

Microsoft documents `NumberOfCores` as the number of cores for the processor instance and `MaxClockSpeed` as the maximum processor speed reported in MHz.

---

# 2️⃣ What problem would make me run it?

### Scenario 1 — Verify processor configuration

A machine appears slower than expected.

Start with:

```powershell
Get-CimInstance Win32_Processor |
    Select-Object Name,
                  NumberOfCores,
                  NumberOfLogicalProcessors,
                  MaxClockSpeed,
                  CurrentClockSpeed
```

This establishes the processor configuration before deeper performance investigation.

---

### Scenario 2 — Compare two machines

Two systems have the same application but different performance.

Compare:

```powershell
Get-CimInstance Win32_Processor |
    Select-Object Name,
                  NumberOfCores,
                  NumberOfLogicalProcessors,
                  MaxClockSpeed
```

---

### Scenario 3 — Investigate virtualization

```powershell
Get-CimInstance Win32_Processor |
    Select-Object Name,
                  VirtualizationFirmwareEnabled
```

This can provide useful processor/firmware virtualization information.

---

### Scenario 4 — CPU topology looks unexpected

If a VM or server reports an unexpected number of processors or cores:

```powershell
Get-CimInstance Win32_Processor |
    Select-Object Name,
                  NumberOfCores,
                  NumberOfLogicalProcessors
```

Then compare the result with the expected VM or physical-system configuration.

---

# 3️⃣ How do I interpret the output?

Example:

```text
Name                     : Intel(R) Core(TM) Ultra 7
NumberOfCores            : 12
NumberOfLogicalProcessors: 14
MaxClockSpeed            : 3800
CurrentClockSpeed        : 1800
```

Interpret carefully:

```text
NumberOfCores
     ↓
Physical cores reported

NumberOfLogicalProcessors
     ↓
Logical processors reported

MaxClockSpeed
     ↓
Maximum reported processor speed

CurrentClockSpeed
     ↓
Current reported speed at query time
```

### Important

`CurrentClockSpeed` is a point-in-time value.

Do not conclude:

> "The CPU is permanently running at 1.8 GHz."

Processor frequency can change dynamically depending on workload and power-management behavior.

For actual CPU utilization, use:

```powershell
Get-Counter "\Processor(_Total)\% Processor Time"
```

---

# 4️⃣ What would I run next based on the result?

| Finding                        | Next command                               |
| ------------------------------ | ------------------------------------------ |
| Unexpected core count          | Verify physical/VM configuration           |
| High CPU suspected             | `Get-Counter`                              |
| Need process causing CPU usage | `Get-Counter \Process(*)\% Processor Time` |
| Need process details           | `Get-Process`                              |
| Need memory configuration      | `Get-CimInstance Win32_PhysicalMemory`     |
| Need complete machine identity | `Get-CimInstance Win32_ComputerSystem`     |

Typical workflow:

```text
Performance complaint
        ↓
Win32_Processor
        ↓
Understand CPU topology
        ↓
Get-Counter
        ↓
Measure CPU utilization
        ↓
Get-Counter Process counters
        ↓
Identify CPU-heavy process
        ↓
Get-Process
        ↓
Investigate process
```

---

# 🧪 Practical Examples

### Processor identity

```powershell
Get-CimInstance Win32_Processor |
    Select-Object Name, Manufacturer
```

### Core and logical processor count

```powershell
Get-CimInstance Win32_Processor |
    Select-Object NumberOfCores,
                  NumberOfLogicalProcessors
```

### Clock speed

```powershell
Get-CimInstance Win32_Processor |
    Select-Object MaxClockSpeed,
                  CurrentClockSpeed
```

### Complete processor baseline

```powershell
Get-CimInstance Win32_Processor |
    Select-Object Name,
                  Manufacturer,
                  NumberOfCores,
                  NumberOfLogicalProcessors,
                  MaxClockSpeed,
                  CurrentClockSpeed,
                  Architecture,
                  AddressWidth
```

### Multiple processor instances

Some systems can expose multiple processor instances.

```powershell
Get-CimInstance Win32_Processor |
    Select-Object DeviceID,
                  Name,
                  NumberOfCores,
                  NumberOfLogicalProcessors
```

---

# 🔬 Important Distinction: CPU Configuration vs CPU Utilization

This command tells you about:

```text
WHAT CPU does the machine have?
```

It does not directly answer:

```text
HOW BUSY is the CPU?
```

For that use:

```powershell
Get-Counter "\Processor(_Total)\% Processor Time"
```

And to identify the process consuming CPU:

```powershell
Get-Counter "\Process(*)\% Processor Time"
```

Then investigate the process:

```powershell
Get-Process
```

---

# 🐧 Linux Equivalent

CPU topology:

```bash
lscpu
```

Processor information:

```bash
cat /proc/cpuinfo
```

CPU utilization:

```bash
top
```

or:

```bash
vmstat
```

---

# ⚠️ Risk Level

🟢 **Read-only**

The command retrieves processor information.

---

# 🧠 Troubleshooting Takeaway

> **Use `Win32_Processor` to understand the CPU configuration and topology. Use `Get-Counter` to determine how heavily that CPU is actually being used.**