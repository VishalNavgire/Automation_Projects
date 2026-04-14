# 🖥️ System Information Collector

A lightweight, cross-platform Python utility to collect and export detailed system information including OS, CPU, memory, and disk usage.

This tool is designed for system monitoring, troubleshooting, and integration with dashboards or APIs.

---

## 🚀 Features

* ✅ Collect Operating System details
* ✅ CPU usage, cores, and frequency
* ✅ Memory (RAM) utilization
* ✅ Disk partitions and storage usage
* ✅ Human-readable size formatting (KB, MB, GB)
* ✅ Export data to JSON
* ✅ Structured logging for monitoring
* ✅ Cross-platform support (Windows, Linux, macOS)

---

## 📂 Project Structure

```
system_info.py   # Main script
README.md        # Documentation
```

---

## ⚙️ Requirements

* Python 3.7+
* Required Python package:

```bash
pip install psutil
```

---

## ▶️ How to Run

### 1. Clone the repository

### 2. Install dependencies

```bash
pip install psutil
```

### 3. Run the script

```bash
python system_info.py
```

---

## 📊 Sample Output

### Console Output

```
==================== System Information Report ====================

[+] OS
    System         : Windows
    Node Name      : MyPC
    Release        : 10

[+] CPU
    Physical Cores : 4
    Total Cores    : 8
    Max Frequency  : 2400.00Mhz
    Current Usage  : 12%

[+] Memory
    Total          : 16.00GB
    Used           : 8.20GB
```

---

### JSON Output

A file will be generated automatically:

```
<hostname>_report.json
```

Example:

```json
{
    "OS": {
        "System": "Windows",
        "Node Name": "MyPC"
    },
    "CPU": {
        "Total Cores": 8
    }
}
```

---

## 🧠 How It Works

The script uses:

* `psutil` → to collect system metrics
* `platform` → to gather OS-level information
* `logging` → to track execution and errors
* `json` → to export structured data


---

## 🌍 Cross-Platform Support

This script works on:

* ✅ Windows
* ✅ Linux

No OS-specific commands are used — making it fully portable.

---

## 🚀 Future Enhancements

* [ ] Network statistics collection
* [ ] REST API integration (FastAPI)
* [ ] Remote device monitoring
* [ ] Streamlit dashboard visualization
* [ ] Docker container support

---

## 🤝 Contributing

Contributions are welcome!

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a Pull Request

---

## 📜 License

This project is licensed under the MIT License.

---

## 👨‍💻 Author

Developed by Vishal Navgire

---

## ⭐ Support

If you find this project useful, consider giving it a ⭐ on GitHub!
