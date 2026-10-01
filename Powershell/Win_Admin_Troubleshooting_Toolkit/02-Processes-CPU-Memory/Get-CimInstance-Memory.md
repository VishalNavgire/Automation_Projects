# Get-CimInstance — Memory Investigation

## 🎯 Purpose

This document covers memory investigation using CIM.

There are two different questions that should not be confused:

```text
How much physical RAM is installed?
             ↓
Win32_PhysicalMemory


How much physical memory is currently available?
             ↓
Win32_OperatingSystem
```

For process-level memory consumption, use:

```powershell
Get-Process
```

This distinction is important when troubleshooting memory problems.

---

# 📌 Command Types

There is no cmdlet named `Get-CimInstance-Memory`.

The actual cmdlet is:

```powershell
Get-CimInstance
```

with different CIM classes.

### Installed physical memory

```powershell
Get-CimInstance Win32_PhysicalMemory
```

### Currently available physical memory

```powershell
Get-CimInstance Win32_OperatingSystem
```

Microsoft documents `Win32_PhysicalMemory` as representing physical memory devices available to the operating system. `Win32_OperatingSystem` exposes `FreePhysicalMemory`, which represents physical memory currently unused and available, in kilobytes.

---

# 1️⃣ What does it show?

## A. Installed physical memory

Use:

```powershell
Get-CimInstance Win32_PhysicalMemory
```

Useful properties:

| Property               | Meaning                                |
| ---------------------- | -------------------------------------- |
| `Capacity`             | Capacity of the physical memory device |
| `Manufacturer`         | Memory manufacturer                    |
| `PartNumber`           | Memory part number                     |
| `Speed`                | Memory speed                           |
| `ConfiguredClockSpeed` | Configured memory clock speed          |
| `DeviceLocator`        | Physical memory slot/location          |
| `BankLabel`            | Memory bank                            |

---

## B. Currently available memory

Use:

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object TotalVisibleMemorySize,
                  FreePhysicalMemory
```

These values are reported in kilobytes.

---

## C. Process-level memory

Use:

```powershell
Get-Process
```

For example:

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
        @{Name='MemoryMB';Expression={
            [math]::Round($_.WorkingSet64 / 1MB, 2)
        }}
```

---

# 2️⃣ What problem would make me run it?

### Scenario 1 — "How much RAM is installed?"

```powershell
Get-CimInstance Win32_PhysicalMemory |
    Measure-Object Capacity -Sum
```

Convert to GB:

```powershell
$Memory = Get-CimInstance Win32_PhysicalMemory

[math]::Round(
    ($Memory | Measure-Object Capacity -Sum).Sum / 1GB,
    2
)
```

---

### Scenario 2 — "The machine is running out of memory"

Check currently available physical memory:

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object TotalVisibleMemorySize,
                  FreePhysicalMemory
```

Convert to GB:

```powershell
$OS = Get-CimInstance Win32_OperatingSystem

[PSCustomObject]@{
    TotalMemoryGB = [math]::Round(
        $OS.TotalVisibleMemorySize / 1MB,
        2
    )

    FreeMemoryGB = [math]::Round(
        $OS.FreePhysicalMemory / 1MB,
        2
    )
}
```

---

### Scenario 3 — "Which process is consuming memory?"

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
        @{Name='MemoryMB';Expression={
            [math]::Round($_.WorkingSet64 / 1MB, 2)
        }}
```

---

### Scenario 4 — "Is memory pressure persistent?"

A single memory reading is not enough.

Use:

```powershell
Get-Counter "\Memory\Available MBytes"
```

Then collect multiple samples:

```powershell
Get-Counter `
    "\Memory\Available MBytes" `
    -SampleInterval 5 `
    -MaxSamples 12
```

This gives you a short time-series rather than a single snapshot.

---

# 3️⃣ How do I interpret the output?

## Installed memory

Example:

```text
Capacity
--------
17179869184
```

The value is in bytes.

Convert it:

```powershell
[math]::Round(
    17179869184 / 1GB,
    2
)
```

Result:

```text
16
```

So the physical memory device has approximately **16 GB** capacity.

---

## Available memory

Example:

```text
TotalVisibleMemorySize : 16646120
FreePhysicalMemory     : 3456120
```

These values are in KB.

Convert:

```powershell
$OS = Get-CimInstance Win32_OperatingSystem

[PSCustomObject]@{
    TotalGB = [math]::Round(
        $OS.TotalVisibleMemorySize / 1MB,
        2
    )

    FreeGB = [math]::Round(
        $OS.FreePhysicalMemory / 1MB,
        2
    )
}
```

---

## Process memory

Example:

```text
Name       Id     MemoryMB
----       --     --------
chrome     4820   1850
Teams      6204    920
sqlservr   7100    850
```

This tells you which processes have the largest working sets at that moment.

It does **not** by itself establish that the largest process is leaking memory.

---

# 4️⃣ What would I run next based on the result?

This is where the memory troubleshooting workflow becomes important.

```text
Memory complaint
       ↓
How much RAM is installed?
       ↓
Win32_PhysicalMemory
       ↓
How much is currently available?
       ↓
Win32_OperatingSystem
       ↓
Is available memory persistently low?
       │
       ├── No → Investigate another subsystem
       │
       └── Yes
             ↓
       Get-Process
             ↓
       Identify large processes
             ↓
       Get-Counter
             ↓
       Observe memory trend
             ↓
       Get-WinEvent
             ↓
       Investigate warnings/errors
```

---

# 🧪 Practical Examples

## Show physical memory modules

```powershell
Get-CimInstance Win32_PhysicalMemory |
    Select-Object DeviceLocator,
                  Manufacturer,
                  PartNumber,
                  Capacity,
                  Speed,
                  ConfiguredClockSpeed
```

---

## Calculate total installed RAM

```powershell
$Memory = Get-CimInstance Win32_PhysicalMemory

[math]::Round(
    ($Memory | Measure-Object Capacity -Sum).Sum / 1GB,
    2
)
```

---

## Show available memory

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object TotalVisibleMemorySize,
                  FreePhysicalMemory
```

---

## Show available memory in GB

```powershell
$OS = Get-CimInstance Win32_OperatingSystem

[PSCustomObject]@{
    TotalMemoryGB = [math]::Round(
        $OS.TotalVisibleMemorySize / 1MB,
        2
    )

    FreeMemoryGB = [math]::Round(
        $OS.FreePhysicalMemory / 1MB,
        2
    )
}
```

---

## Find the largest process working sets

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
        @{Name='MemoryMB';Expression={
            [math]::Round($_.WorkingSet64 / 1MB, 2)
        }}
```

---

## Monitor available memory

```powershell
Get-Counter `
    "\Memory\Available MBytes" `
    -SampleInterval 5 `
    -MaxSamples 12
```

---

# 🔬 Important Distinction

Do not treat these three measurements as the same thing:

| Question                                         | Tool                    |
| ------------------------------------------------ | ----------------------- |
| How much RAM is physically installed?            | `Win32_PhysicalMemory`  |
| How much physical memory is currently available? | `Win32_OperatingSystem` |
| Which process has a large working set?           | `Get-Process`           |
| Is memory availability changing over time?       | `Get-Counter`           |

This distinction prevents a common troubleshooting mistake:

> **A process using a lot of memory does not automatically mean the system has a memory leak.**

You need evidence over time.

---

# 🧠 Memory Troubleshooting Example

Suppose a user reports:

> "The computer becomes slow after several hours."

A reasonable investigation is:

### Step 1 — Check available memory

```powershell
Get-CimInstance Win32_OperatingSystem |
    Select-Object TotalVisibleMemorySize,
                  FreePhysicalMemory
```

### Step 2 — Identify large processes

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
        @{Name='MemoryMB';Expression={
            [math]::Round($_.WorkingSet64 / 1MB, 2)
        }}
```

### Step 3 — Monitor the trend

```powershell
Get-Counter `
    "\Memory\Available MBytes" `
    -SampleInterval 30 `
    -MaxSamples 20
```

### Step 4 — Investigate relevant events

```powershell
Get-WinEvent -LogName System -MaxEvents 100
```

The important lesson is:

```text
Snapshot
   ↓
Identify
   ↓
Trend
   ↓
Correlate
   ↓
Investigate
```

---

# 🐧 Linux Equivalent

Installed memory:

```bash
free -h
```

Detailed memory:

```bash
cat /proc/meminfo
```

Memory-consuming processes:

```bash
ps aux --sort=-%mem
```

Interactive monitoring:

```bash
top
```

---

# ⚠️ Risk Level

🟢 **Read-only**

The commands documented here retrieve memory information and do not modify system configuration.

---

# 🧠 Troubleshooting Takeaway

> **Memory troubleshooting requires separating installed RAM, currently available memory, process-level consumption and memory trends. `Win32_PhysicalMemory`, `Win32_OperatingSystem`, `Get-Process` and `Get-Counter` answer different parts of that investigation.**