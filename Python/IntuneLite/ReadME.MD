<div align="center">

# 💻 IntuneLite — Endpoint Management REST API Engine

[![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.0-D70A53?logo=sqlite&logoColor=white)](https://www.sqlalchemy.org/)
[![JWT](https://img.shields.io/badge/Authentication-OAuth2%20%2B%20JWT-black?logo=jsonwebtokens)](https://jwt.io/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

**A lightweight, production-grade RESTful API engine modeling the backend architecture of Microsoft Intune — including Endpoint Telemetry, Dynamic Security Baseline Compliance, and Targeted Script Deployment.**

[Overview](#-overview) • [Key Learnings](#-key-learnings--technical-takeaways) • [Key Features](#-key-features) • [Architecture](#-architecture) • [Prerequisites](#-prerequisites) • [Installation](#-installation) • [Execution Guide](#-execution-guide) • [Future Enhancements](#-future-enhancements)

</div>

---

# 📖 Overview

In modern Cloud and Endpoint Infrastructure, management engines like **Microsoft Intune** rely on structured REST APIs (such as Microsoft Graph) to enroll endpoints, evaluate host telemetry against enterprise baselines, and execute automated remediation scripts.

**IntuneLite** is a microservice-inspired REST API prototype built with **FastAPI**, **SQLAlchemy 2.0**, and **SQLite**. It simulates core endpoint management capabilities:

* Enrolling Windows & Linux host telemetry
* Evaluating security baselines (OS version enforcement & BitLocker disk encryption compliance)
* Fetching targeted PowerShell/Bash automation scripts for remote remediation
* Enforcing OAuth2 authentication with JWT access tokens and Role-Based Access Control (RBAC)

---

## 🧠 Technical Takeaways

Building **IntuneLite** taught me how to properly design a backend API and manage a database:

* **FastAPI Dependencies:** I set up secure "checkpoints" that verify a user is actually an admin before letting them talk to the database.
* **SQLAlchemy Databases:** I safely connected Python to the database, ensuring connections open and close properly so the server doesn't crash or leak memory.
* **Pydantic Data Validation:** I created filters that double-check incoming data for errors and strip out secret passwords before showing data on the screen.
* **Compliance Logic:** I built the "brain" of the app that looks at a laptop's stats and automatically decides if it meets the company's security rules.
* **Password Security:** I scrambled user passwords so they can never be stolen in plain text, and added a way for people to reset them.

---

# ✨ Key Features

| Feature | Description |
| :--- | :--- |
| **OAuth2 & JWT Authentication** | Secure admin login, token generation (`/authentication/token`), and identity verification (`/authentication/me`). |
| **Password Lifecycle Management** | Includes self-service password resets and administrative password override capabilities. |
| **Endpoint Inventory Telemetry** | Register, update check-in timestamps, patch level info, and track device metadata for Windows and Fedora Linux hosts. |
| **Compliance Rules Engine** | Define baseline security rules (`min_os_version`, `require_encryption`) and trigger audit checks against specific endpoints. |
| **Script Deployment Engine** | Store and dispatch target-specific PowerShell (`.ps1`) and Bash (`.sh`) remediation scripts based on host operating system. |
| **Admin System Overview** | Unified diagnostic endpoint (`/admin/db-overview`) exposing real-time database record metrics. |

---

# 🏗️ Architecture

        IntuneLite/
        │
        ├── app/
        │   ├── api/
        │   │   ├── dependencies.py       # JWT auth, RBAC checks, DB session factory
        │   │   └── v1/
        │   │       ├── admin.py          # Administrative metrics & system database dump
        │   │       ├── auth.py           # User registration, token auth, and password reset routes
        │   │       ├── compliance.py     # Compliance policy rules engine & device evaluation logic
        │   │       ├── devices.py        # Host enrollment, telemetry update, and unenrollment CRUD
        │   │       └── scripts.py        # PowerShell & Bash automation script repository
        │   │
        │   ├── core/
        │   │   ├── config.py             # Pydantic environment settings & API metadata
        │   │   └── security.py           # Password hashing & JWT token generation/decoding
        │   │
        │   ├── db/
        │   │   ├── base.py               # DeclarativeBase catalog for SQLAlchemy ORM
        │   │   └── session.py            # SQLite engine instance & session management
        │   │
        │   ├── models/                   # SQLAlchemy Database Table Models
        │   │   ├── init.py           # Central ORM export catalog
        │   │   ├── compliance.py         # CompliancePolicy table schema
        │   │   ├── device.py             # ManagedDevice table schema
        │   │   ├── script.py             # DeploymentScript table schema
        │   │   └── user.py               # User administrative table schema
        │   │
        │   └── schemas/                  # Pydantic Input/Output DTO Validation Schemas
        │       ├── init.py           # Central schema export catalog
        │       ├── compliance.py         # Compliance policy & evaluation DTOs
        │       ├── device.py             # Device registration & update telemetry DTOs
        │       ├── script.py             # Script upload & deployment payload DTOs
        │       ├── token.py              # JWT token response schemas
        │       └── user.py               # User profile & password reset DTOs
        │
        ├── .env                          # Environment configuration variables
        ├── intunelite.db                 # Local SQLite database instance
        ├── main.py                       # FastAPI entrypoint & router initialization
        └── pyproject.toml                # Project metadata & dependencies

---

# 🛠 Prerequisites

Ensure the following are installed on your environment:

### 1️⃣ Python

* Version: **3.10 or above** (Tested on Python 3.14 on Fedora Linux)

        Bash
        python3 --version

### 2️⃣ Virtual Environment Tooling

        Bash
        python3 -m venv --help

        ⬇️ Installation

        Step 1: Clone Repository

        Bash
        git clone https://github.com/VishalNavgire/IntuneLite.git
        cd IntuneLite

        Step 2: Create & Activate Virtual Environment

        Bash
        # On Linux / macOS
        python3 -m venv venv
        source venv/bin/activate

        # On Windows PowerShell
        python -m venv venv
        .\venv\Scripts\Activate.ps1

        Step 3: Install Dependencies

        Bash
        pip install --upgrade pip
        pip install fastapi "uvicorn[standard]" sqlalchemy pydantic pydantic-settings pyjwt "pwdlib[argon2,bcrypt]" email-validator

        Step 4: Configure Environment Variables
        Create a .env file in the root directory:

        Ini, TOML
        PROJECT_NAME="IntuneLite - Endpoint Management API"
        VERSION="1.0.0"
        API_V1_STR="/api/v1"
        SECRET_KEY="YOUR_SUPER_SECRET_DEVELOPMENT_KEY_CHANGE_IN_PRODUCTION"
        ALGORITHM="HS256"
        ACCESS_TOKEN_EXPIRE_MINUTES=30
        DATABASE_URL="sqlite:///./intunelite.db"
        DEVELOPER_NAME=""

### ▶️ Execution Guide
        Start the Uvicorn development server with live-reloading:

        Bash
        uvicorn main:app --reload

---

## 🧪 Interactive Swagger Documentation

Once started, access the interactive OpenAPI / Swagger UI documentation at:  
👉 [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

```text
 ┌─────────────────────────────────────────────────────────────────────────┐
 │                       IntuneLite OpenAPI Engine                         │
 ├─────────────────────────────────────────────────────────────────────────┤
 │  [POST]  /api/v1/authentication/token         Get OAuth2 Access Token   │
 │  [GET]   /api/v1/authentication/me            Fetch Logged-In User Profile │
 │  [POST]  /api/v1/devices/                     Register New Endpoint     │
 │  [POST]  /api/v1/compliance/policies          Create Security Baseline  │
 │  [POST]  /api/v1/compliance/evaluate/{id}     Evaluate Host Compliance  │
 │  [GET]   /api/v1/scripts/device/{id}          Fetch Targeted Scripts    │
 └─────────────────────────────────────────────────────────────────────────┘

```

---

## 🚀 Future Enhancements
        🌐 Streamlit Frontend Management Portal: Develop an interactive dashboard wrapping IntuneLite API endpoints to display real-time fleet health metrics.

        🔒 Executive Host Protection Guardrails: Add explicit device tags blocking destructive remote actions (like Wipe or Retire) on critical executive endpoints.

        🐳 Containerization & CI/CD: Package the FastAPI engine into lightweight Docker containers with GitHub Actions deployment workflows.

---

# 👨‍💻 Author

### Vishal Navgire

Cloud & Endpoint Automation Engineer

![Azure](https://img.shields.io/badge/Azure-%230072C6.svg?style=for-the-badge\&logo=microsoftazure\&logoColor=white)
![Python](https://img.shields.io/badge/Python-3670A0?style=for-the-badge\&logo=python\&logoColor=ffdd54)
![Automation](https://img.shields.io/badge/Automation-DevOps-green?style=for-the-badge)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-6264A7?style=for-the-badge\&logo=microsoft\&logoColor=white)
![PowerShell](https://img.shields.io/badge/PowerShell-5391FE?style=for-the-badge\&logo=powershell\&logoColor=white)