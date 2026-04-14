<div align="center">

# 🚀 Python Project Bootstrap Generator

[![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python\&logoColor=white)](https://www.python.org/)
[![VirtualEnv](https://img.shields.io/badge/Virtual%20Environment-venv-blue)]()
[![Git](https://img.shields.io/badge/Git-Initialized-F05032?logo=git\&logoColor=white)](https://git-scm.com/)
[![Automation](https://img.shields.io/badge/Automation-Project%20Setup-green)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**A cross-platform Python automation tool that scaffolds a complete project structure with virtual environment, dependency management, and Git initialization — in seconds.**

[Overview](#-overview) • [Key Features](#-key-features) • [Architecture](#-architecture) • [Prerequisites](#-prerequisites) • [Installation](#-installation) • [Execution Guide](#-execution-guide) • [Output](#-expected-output)

</div>

---

# 📖 Overview

Setting up a new Python project often involves repetitive tasks such as:

* Creating folder structures
* Initializing Git repositories
* Setting up virtual environments
* Installing dependencies

The **Python Project Bootstrap Generator** automates all of these steps into a **single streamlined workflow**.

This tool ensures:

* ✅ Consistent project structure
* ✅ Faster onboarding for developers
* ✅ Reduced manual errors
* ✅ Cross-platform compatibility

---

# ✨ Key Features

| Feature                          | Description                                               |
| -------------------------------- | --------------------------------------------------------- |
| **Automated Project Setup**      | Instantly generates a clean and structured Python project |
| **Virtual Environment Creation** | Automatically creates isolated `venv`                     |
| **Dependency Installation**      | Installs user-defined Python packages                     |
| **Interactive Input**            | Accepts module input dynamically                          |
| **Optional Version Freezing**    | Supports reproducible environments                        |
| **Git Initialization**           | Automatically initializes repository                      |
| **Path Safety Validation**       | Prevents OS-specific path length issues                   |
| **Cross-Platform Support**       | Works on Windows, Linux, and macOS                        |

---

# 🏗️ Architecture

The script follows a modular structure for clarity and maintainability:

```
project_bootstrap.py
│
├── Path Validation
│   └── validate_path_length()
│
├── Dependency Input
│   └── get_user_dependencies()
│
├── Environment Setup
│   ├── Virtual Environment Creation
│   ├── pip Upgrade
│   └── Dependency Installation
│
├── Project Structure Builder
│   ├── src/
│   ├── tests/
│   └── .github/workflows/
│
├── File Generator
│   ├── README.md
│   ├── requirements.txt
│   ├── .gitignore
│   └── LICENSE
│
└── Git Initialization
    └── git init
```

---

# 🛠 Prerequisites

Ensure the following are installed:

## 1️⃣ Python

* Version: **3.8 or above**

```bash
python --version
```

---

## 2️⃣ Git

```bash
git --version
```

---

# ⬇️ Installation

### Option 1: Clone Repository

```bash
git clone https://github.com/<your-username>/<your-repo>.git
cd <your-repo>
```

---

### Option 2: Download ZIP

* Click **Code → Download ZIP**
* Extract and navigate to project directory

---

# ▶️ Execution Guide

Run the script:

```bash
python your_script_name.py
```

---

## 🧪 Interactive Example

### Step 1: Enter Project Name

```
Please enter your desired Python project name:
> my_streamlit_app
```

---

### Step 2: Enter Dependencies

```
Enter required Third Party Python modules:
> streamlit, pandas, msal
```

---

### Step 3: Freeze Versions (Optional)

```
Freeze versions? (y/n):
> y
```

---

# 📤 Expected Output

```
📏 Project path length: 120
✅ Path length is safe.

📁 Creating structure in: /home/user/my_streamlit_app

📦 Installing dependencies...

🚀 Project 'my_streamlit_app' created successfully with dependencies!
```

---

# 📁 Generated Project Structure

```
my_streamlit_app/
│
├── src/
├── tests/
├── .github/
│   └── workflows/
│
├── venv/
├── README.md
├── requirements.txt
├── .gitignore
└── LICENSE
```

---

# ⚙️ What Happens Internally

1. Validates project path length
2. Creates folder structure
3. Generates base files
4. Initializes Git repository
5. Creates virtual environment
6. Upgrades pip inside venv
7. Installs dependencies
8. Optionally freezes versions

---

# 🔐 Path Safety & OS Compatibility

| OS          | Max Path Length | Safe Recommendation |
| ----------- | --------------- | ------------------- |
| Windows     | 260             | ~200                |
| Linux/macOS | ~4096           | ~1000               |

⚠️ The tool automatically warns or blocks unsafe paths.

---

# 🛠 Customization

You can modify:

### Folder Structure

```python
TEMPLATE = {
    "src": [],
    "tests": [],
    ".github": ["workflows"],
}
```

---

### Default Files

```python
FILES = {
    "README.md": "...",
    ...
}
```

---

# 🚀 Future Enhancements

* CLI argument support (`--name`, `--deps`)
* Template selection (API / Streamlit / CLI)
* Dockerfile generation
* CI/CD workflow templates
* Dependency validation

---

# 🤝 Contributing

Contributions are welcome!

* Fork the repository
* Create a feature branch
* Submit a pull request

---

# 👨‍💻 Author

### Vishal Navgire

Cloud & Endpoint Automation Engineer

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge\&logo=microsoftazure\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge\&logo=python\&logoColor=ffdd54)
![Automation](https://img.shields.io/badge/Automation-DevOps-green?style=for-the-badge)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge\&logo=microsoft\&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)

---

# ⭐ Support

If you find this useful:

* ⭐ Star the repository
* 🔁 Share with developers
* 💬 Provide feedback

---

# 🎯 Final Thought

This tool is designed to **standardize project setup, improve developer productivity, and eliminate repetitive tasks** — making it especially valuable in team environments and automation workflows.

Happy coding 🚀