import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from tzlocal import get_localzone
import os
import platform
import psutil
import socket
import subprocess
import json

def get_script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

# ------------------------------ Logging --------------------------------------
def setup_logger():
    log_dir = os.path.join(get_script_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(f"System_Audit_{socket.gethostname()}_{platform.system()}.log")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(
            os.path.join(log_dir, "System_Audit.log"), 
            maxBytes=10 * 1024 * 1024, 
            backupCount=5, 
            encoding="utf-8"
        )
        fmt = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(funcName)s | %(message)s | %(filename)s:%(lineno)d",
            datefmt="%a %d %b %Y %I:%M:%S %p %Z"
        )
        local_tz = get_localzone()
        fmt.converter = lambda *args: datetime.now(tz=local_tz).timetuple()
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    return logger

LOGGER = setup_logger()

def get_windows_updates():
    try:
        cmd = [
            "powershell",
            "-Command",
            "Get-HotFix | Select HotFixID,InstalledOn | ConvertTo-Json"
        ]
        result = subprocess.check_output(cmd, text=True)
        updates = json.loads(result)
        LOGGER.info(f"Installed Windows Updates Found: {len(updates)}")
        return updates
    except Exception as e:
        LOGGER.error(f"Failed to fetch Windows updates: {e}")
        return []


def get_windows_apps():
    try:
        cmd = [
            "powershell",
            "-Command",
            """
            Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* |
            Select DisplayName, DisplayVersion |
            ConvertTo-Json
            """
        ]
        result = subprocess.check_output(cmd, text=True)
        apps = json.loads(result)
        LOGGER.info(f"Installed Applications Found: {len(apps)}")
        return apps
    except Exception as e:
        LOGGER.error(f"Failed to fetch installed apps: {e}")
        return []


def get_linux_updates():
    try:
        result = subprocess.check_output(
            ["dnf", "history", "list"],
            text=True
        )
        LOGGER.info("Fetched Linux update history")
        return result.splitlines()
    except Exception as e:
        LOGGER.error(f"Failed to fetch Linux updates: {e}")
        return []

def get_linux_apps():
    try:
        result = subprocess.check_output(
            ["rpm", "-qa"],
            text=True
        )
        apps = result.splitlines()
        LOGGER.info(f"Installed RPM packages found: {len(apps)}")
        return apps
    except Exception as e:
        LOGGER.error(f"Failed to fetch Linux apps: {e}")
        return []

def get_installed_updates():
    if platform.system() == "Windows":
        return get_windows_updates()
    elif platform.system() == "Linux":
        return get_linux_updates()
    return []

def get_installed_apps():
    if platform.system() == "Windows":
        return get_windows_apps()
    elif platform.system() == "Linux":
        return get_linux_apps()
    return []

# -------------------------- Data Collection ----------------------------------

def collect_inventory():
    """Collects OS-independent system information."""
    
    hostname = socket.gethostname()
    LOGGER.info(f"Hostname: {hostname}")

    fqdn = socket.getfqdn()
    LOGGER.info(f"Domain/FQDN: {fqdn}")
    
    disk = psutil.disk_usage('/')
    free_gb = round(disk.free / (1024**3), 2)
    LOGGER.info(f"Free Disk Space: {free_gb} GB")

    profiles = []
    if platform.system() == "Windows":
        profile_path = "C:\\Users"
    else:
        profile_path = "/home"
        profiles.append("root") # Add root manually for Unix

    if os.path.exists(profile_path):
        # List directories in the user folder, ignoring hidden or system files
        profiles.extend([d for d in os.listdir(profile_path) if os.path.isdir(os.path.join(profile_path, d))])
    
    LOGGER.info(f"User Profiles Found: {', '.join(profiles)}")

    updates = get_installed_updates()
    LOGGER.info(f"Updates Collected: {len(updates)}")
    apps = get_installed_apps()
    LOGGER.info(f"Applications Collected: {len(apps)}")
    
    return {
        "hostname": hostname,
        "fqdn": fqdn,
        "free_space": f"{free_gb} GB",
        "profiles": profiles,
        "updates": updates,
        "applications": apps
    }

def main():
    LOGGER.info("--- Starting OS-Independent Inventory Collection ---")
    data = collect_inventory()
    LOGGER.info(json.dumps(data, indent=4))
    LOGGER.info("--- Collection Complete ---")

if __name__ == "__main__":
    main()
