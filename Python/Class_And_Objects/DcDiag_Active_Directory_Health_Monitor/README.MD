# 🛡️ Active Directory Health Monitor

A Python-based enterprise tool designed to automate the diagnosis and visualization of Active Directory Domain Controller health.

---

## 📖 Background: What is dcdiag?

**DCDiag (Domain Controller Diagnostics)** is a command-line tool that analyzes the state of Domain Controllers in a forest or enterprise and reports any problems to help in troubleshooting.
https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/dcdiag

---

## ❓ Why use dcdiag?

In an enterprise environment, Active Directory is the **"heart" of Identity and Access Management (IAM)**. If AD fails, business-critical authentication and authorization services are impacted.

`dcdiag` performs multiple essential tests, including:

* **Connectivity** → Verifies if DCs are reachable and DNS is functioning
* **Replication** → Ensures directory database synchronization between DCs
* **Services** → Checks critical services (DNS, KDC, NetLogon)
* **FSMO Roles** → Validates role holders are accessible

---

## ⚠️ The Problem This Tool Solves

While `dcdiag` is powerful, its output is:

* ❌ Unstructured
* ❌ Lengthy
* ❌ Difficult to monitor at scale

This project solves that by:

* ✅ Executing `dcdiag` automatically
* ✅ Parsing output using **Regular Expressions (Regex)**
* ✅ Transforming raw text into structured JSON
* ✅ Presenting results in a **modern dashboard**

---

## 🚀 Features

* ✅ Automated execution of `dcdiag`
* ✅ Structured parsing of CLI output
* ✅ Health summary per Domain Controller
* ✅ Interactive Streamlit dashboard
* ✅ JSON export with hostname + timestamp
* ✅ Modular Object-Oriented Design (OOP)
* ✅ Logging and error handling

---

## 🏗️ Architecture

```id="5u9w2q"
dcdiag (CLI)
   ↓
CommandExecutor (Extract)
   ↓
DCDiagParser (Transform)
   ↓
DCHealthAnalyzer (Analyze)
   ↓
DCHealthReporter (Load/Export)
   ↓
Streamlit Dashboard (Visualize)
```

---

## 📂 Project Structure

```id="j2v7h3"
project-folder/
│
├── main.py                 # Core logic (execution, parsing, analysis)
├── streamlitapp.py         # Streamlit dashboard
├── README.md
```

---

## ⚙️ Requirements

* Python 3.8+
* Windows OS (Domain joined or Domain Controller)
* `dcdiag` command available (RSAT or AD DS tools)

---

## 🐍 Virtual Environment Setup (Recommended)

### 📌 Step 1: Create Virtual Environment

```bash id="8lb8v0"
python -m venv venv
```

---

### 📌 Step 2: Activate Virtual Environment

#### 🪟 Windows (CMD / PowerShell)

```bash id="8k5jj2"
venv\Scripts\activate
```

---

### 📌 Step 3: Install Dependencies

```bash id="sclx0u"
pip install streamlit pandas
```

---

### 📌 Step 4: Deactivate (Optional)

```bash id="y9k9y1"
deactivate
```

---

## ▶️ How to Run

### 1. Clone Repository

---

### 2. Run Backend Script (Optional)

```bash id="1h3vph"
python main.py
```

---

### 3. Launch Dashboard

```bash id="m5h5nh"
streamlit run streamlitapp.py
```

---

### 4. Open Browser

```id="0v31b1"
http://localhost:8501
```

Click **"Run Diagnostic Now"** to execute health checks.

---

## 📊 Output

### 🖥️ Dashboard

* Health status per Domain Controller
* Passed vs Failed tests
* Detailed test results

### 📄 JSON Report

```id="k6mbjv"
<hostname>_dc_health_<timestamp>.json
```

---

## 🧠 How It Works

1. Executes:

   ```
   dcdiag /v
   ```
2. Captures output using Python `subprocess`
3. Parses using Regex
4. Structures into dictionary format
5. Generates summary metrics
6. Displays via Streamlit
7. Exports JSON report

---

## 🌍 OS Compatibility

| OS                         | Supported |
| -------------------------- | --------- |
| Windows Server             | ✅ Yes     |
| Windows Client (with RSAT) | ✅ Yes     |
| Linux                      | ❌ No      |
| macOS                      | ❌ No      |

---

## ⚠️ Important Notes

* Must be run on:

  * Domain Controller OR
  * Domain-joined machine with RSAT

* Recommended to run as:

  * Administrator

---

## 🔧 Use Cases

* Active Directory health monitoring
* Domain Controller diagnostics
* IT infrastructure audits
* Automation and reporting
* Dashboard-based monitoring

---

## 🔐 Security Considerations

* No credentials are stored
* Uses native Windows tools
* Ensure proper access control on reports

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Submit a Pull Request

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Developed by Vishal Navgire

---

## ⭐ Support

If you find this useful, please ⭐ the repository!
