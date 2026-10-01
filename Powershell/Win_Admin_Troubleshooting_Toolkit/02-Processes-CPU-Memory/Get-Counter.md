# Get-Counter

## 🎯 Purpose

`Get-Counter` retrieves Windows Performance Counter data from local or remote computers.

It is the command to use when you need to understand **performance over time**, rather than simply looking at a process snapshot.

Typical investigations include:

* High CPU
* High memory pressure
* Disk activity
* Network performance
* Process CPU utilization
* Processor queue activity
* Performance trends

`Get-Counter` is available on Windows and was reintroduced in PowerShell 7.

---

## 📌 Command Type

**PowerShell cmdlet**

**Module:** `Microsoft.PowerShell.Diagnostics`

---

## 🧾 Syntax

Get a counter:

```powershell
Get-Counter -Counter "\Processor(_Total)\% Processor Time"
```

Take multiple samples:

```powershell
Get-Counter `
    -Counter "\Processor(_Total)\% Processor Time" `
    -SampleInterval 2 `
    -MaxSamples 5
```

List counter sets:

```powershell
Get-Counter -ListSet *
```

---

# 1️⃣ What does it show?

`Get-Counter` retrieves data from Windows Performance Counters.

A performance counter path generally follows:

```text
\CounterSet(Instance)\CounterName
```

For example:

```text
\Processor(_Total)\% Processor Time
```

Important concepts:

| Concept       | Meaning                                         |
| ------------- | ----------------------------------------------- |
| Counter Set   | Performance area being measured                 |
| Instance      | Specific object being measured                  |
| Counter       | Specific measurement                            |
| Sample        | Value collected at a point in time              |
| `CookedValue` | Processed counter value used for interpretation |

Microsoft documents `-SampleInterval`, `-MaxSamples`, `-Continuous`, `-Counter`, and `-ListSet` as the primary controls for collecting counter data.

---

# 2️⃣ What problem would make me run it?

### Scenario 1 — User reports high CPU

Check total CPU utilization:

```powershell
Get-Counter "\Processor(_Total)\% Processor Time"
```

For repeated samples:

```powershell
Get-Counter `
    "\Processor(_Total)\% Processor Time" `
    -SampleInterval 2 `
    -MaxSamples 5
```

This helps determine whether the CPU is consistently busy or the high CPU was only a momentary spike.

---

### Scenario 2 — Need to identify CPU-heavy processes

```powershell
Get-Counter "\Process(*)\% Processor Time"
```

For easier analysis:

```powershell
$Counter = Get-Counter "\Process(*)\% Processor Time"

$Counter.CounterSamples |
    Sort-Object CookedValue -Descending |
    Select-Object -First 10 Path, InstanceName, CookedValue
```

---

### Scenario 3 — Need to investigate memory pressure

First discover available Memory counters:

```powershell
Get-Counter -ListSet Memory
```

Then inspect a specific counter:

```powershell
Get-Counter "\Memory\Available MBytes"
```

---

### Scenario 4 — Need to monitor performance continuously

```powershell
Get-Counter `
    "\Processor(_Total)\% Processor Time" `
    -Continuous
```

Stop with:

```text
CTRL + C
```

Microsoft documents that `-Continuous` samples until interrupted and normally samples once per second unless `-SampleInterval` is specified.

---

# 3️⃣ How do I interpret the output?

Example:

```text
CounterSamples

Path                                         CookedValue
----                                         -----------
\\PC01\processor(_total)\% processor time   82.4
```

Interpret:

```text
Counter
   ↓
What are we measuring?

Instance
   ↓
Which processor/process/device?

CookedValue
   ↓
What is the measured value?
```

For:

```text
\Processor(_Total)\% Processor Time
```

a value around:

```text
82.4
```

means the sampled total processor utilization was approximately **82.4%**.

### Do not diagnose from one sample alone

Prefer:

```text
Sample
   ↓
Sample
   ↓
Sample
   ↓
Sample
   ↓
Observe trend
```

For example:

```powershell
Get-Counter `
    "\Processor(_Total)\% Processor Time" `
    -SampleInterval 2 `
    -MaxSamples 10
```

---

# 4️⃣ What would I run next based on the result?

### High CPU

```text
Get-Counter
     ↓
High total CPU?
     ↓
Get-Counter \Process(*)\% Processor Time
     ↓
Identify process
     ↓
Get-Process
     ↓
Investigate process
```

### CPU appears normal

Move to another subsystem:

```text
CPU normal
   ↓
Memory?
   ↓
Disk?
   ↓
Network?
   ↓
Application/Event Logs?
```

### Memory appears low

Start with:

```powershell
Get-Counter "\Memory\Available MBytes"
```

Then investigate:

```powershell
Get-Process |
    Sort-Object WorkingSet64 -Descending
```

---

# 🧪 Practical Examples

### Total CPU

```powershell
Get-Counter "\Processor(_Total)\% Processor Time"
```

### CPU over 10 samples

```powershell
Get-Counter `
    "\Processor(_Total)\% Processor Time" `
    -SampleInterval 2 `
    -MaxSamples 10
```

### List performance counter sets

```powershell
Get-Counter -ListSet *
```

### List Memory counters

```powershell
Get-Counter -ListSet Memory
```

### Available memory

```powershell
Get-Counter "\Memory\Available MBytes"
```

### Process CPU

```powershell
Get-Counter "\Process(*)\% Processor Time"
```

### Sort process counters

```powershell
$Counter = Get-Counter "\Process(*)\% Processor Time"

$Counter.CounterSamples |
    Sort-Object CookedValue -Descending |
    Select-Object -First 10 InstanceName, CookedValue
```

---

# 🌐 Remote Performance Investigation

`Get-Counter` supports the `-ComputerName` parameter for collecting performance counter information from remote computers. Microsoft notes that this does not rely on PowerShell remoting.

Example:

```powershell
Get-Counter `
    -ComputerName SERVER01 `
    -Counter "\Processor(_Total)\% Processor Time"
```

Multiple computers:

```powershell
Get-Counter `
    -ComputerName SERVER01,SERVER02 `
    -Counter "\Processor(_Total)\% Processor Time"
```

---

# 🔎 Discovering Counters

Do not memorize every counter.

Discover them.

```powershell
Get-Counter -ListSet *
```

Then:

```powershell
Get-Counter -ListSet Processor
```

Or:

```powershell
(Get-Counter -ListSet Memory).Paths
```

This is an important troubleshooting skill:

> **Know how to discover the right counter rather than memorizing every counter path.**

---

# 🌍 Localization Consideration

Performance counter names are localized.

The English counter names used in examples may differ on systems using another Windows language.

Use:

```powershell
Get-Counter -ListSet *
```

to discover the names available on the target system.

---

# 🐧 Linux Equivalent

Common Linux performance tools include:

```bash
top
```

```bash
vmstat
```

```bash
iostat
```

```bash
sar
```

Conceptually:

```text
Windows                         Linux
-------                         -----
Get-Counter        ↔            vmstat
Get-Counter        ↔            iostat
Get-Counter        ↔            sar
Performance Monitor ↔           system monitoring tools
```

The tools are not identical; the important transferable concept is **sampling system performance and interpreting trends**.

---

# ⚠️ Risk Level

🟢 **Read-only**

`Get-Counter` collects performance data and does not modify the monitored system.

Some protected counter sets may require elevated permissions.

---

# 🧠 Troubleshooting Takeaway

> **Use `Get-Counter` when a snapshot is not enough and you need measured performance data over time. It is especially important for distinguishing a temporary spike from a sustained CPU, memory or other performance problem.**