# 🔐 Entra Device Info Collector

A Python-based utility to collect, parse, and export **Microsoft Entra ID (Azure AD) device join status** using the native Windows command:

`dsregcmd /status`

This tool transforms raw command-line output into structured JSON, making it easier to integrate with dashboards, APIs, and monitoring systems.

https://learn.microsoft.com/en-us/entra/identity/devices/troubleshoot-device-dsregcmd

---

## 🚀 Features

* ✅ Executes `dsregcmd /status` automatically
* ✅ Parses unstructured CLI output into structured JSON
* ✅ Extracts key device identity and join status fields
* ✅ Provides a quick summary (Azure AD Joined, Domain Joined, Device Name)
* ✅ Exports results to JSON
* ✅ Built-in logging for troubleshooting
* ✅ Modular, class-based design

---

## 📂 Project Structure

```id="n8y2fi"
entra_device_info.py   # Main script
README.md              # Documentation
```

---

## ⚙️ Requirements

* Python 3.7+
* Windows OS (see compatibility section below)

No external Python libraries required.

---

## ▶️ How to Run

### 1. Clone the repository

---

### 2. Run the script

```bash id="qmt0nx"
python entra_device_info.py
```

---

### 3. Sample Output

#### 🖥️ Console Output

```id="xiy4qk"
Quick Summary: {
  'AzureAdJoined': 'YES',
  'DomainJoined': 'NO',
  'DeviceName': 'MY-PC'
}
```

---

#### 📄 JSON Output

```json id="d41ywr"
{
  "Device_State": {
    "AzureAdJoined": "YES",
    "DomainJoined": "NO",
    "Device Name": "MY-PC"
  }
}
```

---

## 🧠 How It Works

1. Python executes:

   ```id="9y5nd5"
   dsregcmd /status
   ```

2. Captures the raw output using `subprocess`

3. Parses:

   * Sections (e.g., Device State)
   * Key-value pairs

4. Converts data into structured JSON format

---

## 🔍 Key Methods

| Method           | Description                          |
| ---------------- | ------------------------------------ |
| `run_dsregcmd()` | Executes the system command          |
| `parse_output()` | Converts raw text to structured data |
| `get_summary()`  | Extracts key device info             |
| `display()`      | Prints formatted output              |
| `export_json()`  | Saves data to file                   |

---

## 🛡️ Error Handling

* Handles command execution failures
* Detects missing `dsregcmd` command
* Prevents crashes due to empty output
* Logs errors for debugging

---

## 🌍 OS Compatibility

⚠️ **This tool is OS-dependent**

### Supported:

* ✅ Windows 10 / 11
* ✅ Windows Server

### Not Supported:

* ❌ Linux
* ❌ macOS

---

## ❓ Why is it OS-dependent?

The script relies on:

```id="r1cb6l"
dsregcmd /status
```

This command:

* Is **built into Windows only**
* Is part of **Microsoft Entra ID / Azure AD device registration**
* Does not exist on Linux or macOS

---

## 🔧 Use Cases

* Device compliance verification
* Entra ID join troubleshooting
* IT admin diagnostics
* Integration with monitoring tools
* Feeding data into dashboards (Streamlit, Power BI)
* Automation via Task Scheduler

---

## 🚀 Future Enhancements

* [ ] Combine with system hardware info collector
* [ ] REST API support (FastAPI)
* [ ] Remote device execution via WinRM
* [ ] Integration with Azure Log Analytics
* [ ] Streamlit dashboard visualization

---

## 🔐 Security Considerations

* Does not collect sensitive credentials
* Uses local system command only

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Open a Pull Request

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Developed by Vishal Navgire

---

## ⭐ Support

If you find this project useful, consider giving it a ⭐ on GitHub!