# Get-Process

## 🎯 Purpose

`Get-Process` retrieves the processes currently running on a Windows computer.

It is one of the first commands to use when investigating:

* High CPU usage
* High memory usage
* An unresponsive application
* A hung process
* Excessive number of processes
* Unexpected application activity
* Process IDs (PIDs)
* Process ownership
* Process start time
* Loaded modules

Microsoft's `Get-Process` returns `System.Diagnostics.Process` objects by default, which means the output can be filtered, sorted and further investigated using PowerShell's object-based pipeline.

---

## 📌 Command Type

**PowerShell cmdlet**

**Module:** `Microsoft.PowerShell.Management`

Common aliases:

```powershell
gps
ps
```

---

## 🧾 Syntax

List all processes:

```powershell
Get-Process
```

Specific process:

```powershell
Get-Process -Name explorer
```

Specific PID:

```powershell
Get-Process -Id 1234
```

Include process owner:

```powershell
Get-Process -Name explorer -IncludeUserName
```

---

# 1️⃣ What does it show?

`Get-Process` returns information about running processes.

The default display includes information such as:

| Property      | What it tells you                       |
| ------------- | --------------------------------------- |
| `Handles`     | Number of handles opened by the process |
| `NPM`         | Non-paged memory usage                  |
| `PM`          | Paged memory usage                      |
| `WS`          | Working-set memory                      |
| `CPU`         | Processor time used by the process      |
| `Id`          | Process ID (PID)                        |
| `SI`          | Session ID                              |
| `ProcessName` | Process name                            |

Microsoft notes that the displayed memory values are formatted for readability, while the underlying properties are represented in bytes where applicable.

---

# 2️⃣ What problem would make me run it?

### Scenario 1 — User reports that an application is slow

Start by identifying the application process:

```powershell
Get-Process -Name explorer
```

Then investigate CPU and memory usage.

---

### Scenario 2 — Computer has high CPU

First identify processes consuming CPU:

```powershell
Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 10 Name, Id, CPU
```

This gives you a starting point for identifying CPU-heavy processes.

> **Important:** `CPU` represents accumulated processor time, not instantaneous CPU percentage.

For current CPU utilization over time, use `Get-Counter`.

---

### Scenario 3 — Computer has high memory usage

Sort processes by working-set memory:

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
        @{Name='MemoryMB';Expression={[math]::Round($_.WorkingSet64 / 1MB, 2)}}
```

---

### Scenario 4 — Need to identify a process from its PID

```powershell
Get-Process -Id 1234
```

This is particularly useful when another tool, Event Log entry or application message provides only a PID.

---

### Scenario 5 — Need to identify the process owner

```powershell
Get-Process -Name explorer -IncludeUserName
```

The `-IncludeUserName` parameter can require elevated rights when investigating processes you do not own.

---

# 3️⃣ How do I interpret the output?

Consider:

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 5 Name, Id,
        @{Name='MemoryMB';Expression={[math]::Round($_.WorkingSet64 / 1MB, 2)}}
```

Example:

```text
Name              Id    MemoryMB
----              --    --------
chrome            4820  1850
Teams             6204   920
explorer          3180   420
powershell        7112   280
svchost            980   210
```

Interpret it as:

```text
ProcessName
    ↓
Which application/process?

Id
    ↓
Which exact process instance?

MemoryMB
    ↓
How much working-set memory is it currently using?
```

### CPU interpretation

If you run:

```powershell
Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 10 Name, Id, CPU
```

remember:

```text
CPU
 ↓
Accumulated processor time
```

It is **not the same as `% Processor Time`** from Performance Monitor.

For percentage-based CPU investigation, move to `Get-Counter`.

---

# 4️⃣ What would I run next based on the result?

| Finding                         | Next step                                     |
| ------------------------------- | --------------------------------------------- |
| One process has high CPU time   | Investigate process with `Get-Counter`        |
| One process has high memory     | Check memory trend and process behavior       |
| Process is unresponsive         | Investigate Event Logs                        |
| Process keeps restarting        | Investigate parent/service/application events |
| Unknown process                 | Investigate path, command line and owner      |
| Process PID appears in an event | Query `Get-Process -Id <PID>`                 |
| Application appears healthy     | Move to system-level performance counters     |

Example:

```text
High CPU symptom
      ↓
Get-Process
      ↓
Identify suspicious process
      ↓
Get-Counter
      ↓
Measure CPU utilization over time
      ↓
Get-WinEvent
      ↓
Investigate application/system events
```

---

# 🧪 Practical Examples

### List all processes

```powershell
Get-Process
```

### Find a specific process

```powershell
Get-Process -Name explorer
```

### Find a process by PID

```powershell
Get-Process -Id 1234
```

### Top processes by CPU time

```powershell
Get-Process |
    Sort-Object CPU -Descending |
    Select-Object -First 10 Name, Id, CPU
```

### Top processes by memory

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending |
    Select-Object -First 10 Name, Id,
        @{Name='MemoryMB';Expression={[math]::Round($_.WorkingSet64 / 1MB, 2)}}
```

### Include process owner

```powershell
Get-Process -IncludeUserName
```

### Investigate available properties

```powershell
Get-Process explorer | Get-Member
```

This is particularly useful when learning what information is available on the returned process object.

### Investigate a process executable

```powershell
Get-Process explorer |
    Select-Object Name, Id, Path
```

> Access to some process properties can depend on permissions and whether the process can be inspected.

---

# 🔬 Useful Process Properties

Some properties worth learning:

```text
Name
Id
CPU
WorkingSet64
PrivateMemorySize64
VirtualMemorySize64
Handles
Threads
StartTime
Path
MainWindowTitle
Responding
```

Not every property is equally useful for every process.

The troubleshooting question should determine which property you inspect.

---

# 🌐 Remote Troubleshooting

`Get-Process` supports `-ComputerName` for remote process queries in Windows PowerShell scenarios. Microsoft also notes that for remote process investigation, `Invoke-Command` is commonly used.

Example:

```powershell
Get-Process -ComputerName SERVER01
```

For more complex remote investigation:

```powershell
Invoke-Command -ComputerName SERVER01 -ScriptBlock {
    Get-Process |
        Sort-Object CPU -Descending |
        Select-Object -First 10 Name, Id, CPU
}
```

---

# 🐧 Linux Equivalent

List processes:

```bash
ps aux
```

Interactive process view:

```bash
top
```

Or:

```bash
htop
```

The conceptual workflow is similar:

```text
Windows                         Linux
-------                         -----
Get-Process        ↔            ps
Get-Process        ↔            top / htop
PID                ↔            PID
WorkingSet         ↔            RSS
CPU                ↔            CPU time
```

---

# ⚠️ Risk Level

🟢 **Read-only**

The commands in this document only retrieve process information.

> Some `Get-Process` output can expose information about applications, paths or users, so be mindful when collecting diagnostic output for external sharing.

---

# 🧠 Troubleshooting Takeaway

> **`Get-Process` answers "which processes are running and what can I learn about them?" It is often the starting point for process-level CPU and memory investigation, but CPU percentage and performance trends require performance counters.**