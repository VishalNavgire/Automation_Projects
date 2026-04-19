import psutil
import platform
import json
import logging
import socket
import os
import subprocess
from datetime import datetime
from typing import Dict, Any

logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %I:%M:%S %p %Z %Y'
)

class SystemInfoCollector:
    """A class to collect and format system infrastructure details."""

    def __init__(self):
        self.system_data: Dict[str, Any] = {}
        self.is_windows = platform.system() == "Windows"
        self.is_linux = platform.system() == "Linux"

    @staticmethod
    def get_size(num_bytes, suffix="B"):
        """Scales bytes to a human-readable format (e.g., GB, MB)."""
        factor = 1024
        for unit in ["", "K", "M", "G", "T", "P"]:
            if num_bytes < factor:
                return f"{num_bytes:.2f}{unit}{suffix}"
            num_bytes/= factor

    def collect_os_info(self):
        """Gathers OS and Platform details."""
        try:
            uname = platform.uname()
            processor_name = uname.processor
            self.system_data['OS'] = {
                "System": uname.system,
                "Node Name": uname.node,
                "Release": uname.release,
                "Version": uname.version,
                "Machine": uname.machine,
                "Processor": processor_name  if processor_name else "N/A",
            }
        except Exception as e:
            logging.error(f"Failed to collect OS info: {e}")

    def collect_cpu_info(self):
        """Gathers CPU usage and core counts."""
        try:
            freq = psutil.cpu_freq()
            self.system_data['CPU'] = {
                "Physical Cores": psutil.cpu_count(logical=False),
                "Total Cores": psutil.cpu_count(logical=True),
                "Max Frequency": f"{freq.max:.2f}Mhz" if freq else "N/A",
                "Current Usage": f"{psutil.cpu_percent()}%"
            }
        except Exception as e:
            logging.error(f"Failed to collect CPU info: {e}")

    def collect_memory_info(self):
        try:
            svmem = psutil.virtual_memory()
            self.system_data['Memory'] = {
                "Total": self.get_size(svmem.total),
                "Available": self.get_size(svmem.available),
                "Used": self.get_size(svmem.used),
                "Percentage": f"{svmem.percent}%"
            }
        except Exception as e:
            logging.error(f"Failed to collect Memory info: {e}")

    def collect_disk_info(self):
        partitions = psutil.disk_partitions()
        disk_info = []

        for partition in partitions:
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    "Device": partition.device,
                    "Mountpoint": partition.mountpoint,
                    "Total": self.get_size(usage.total),
                    "Used": self.get_size(usage.used),
                    "Free": self.get_size(usage.free),
                    "Usage": f"{usage.percent}%"
                })
            except PermissionError:
                continue

        self.system_data['Disk'] = disk_info

    def display_report(self):
        """Prints a formatted report to the console."""
        print("="*20, "System Information Report", "="*20)
        for category, metrics in self.system_data.items():
            # print(f"categoryname is:{category} and its type is type{type(category)}\n")
            # print(f"metricname is: {metrics} and its type is type{type(metrics)}\n")
            print(f"\n[+] {category}")
            
            # Check if metrics is a list (used for Disks)
            if isinstance(metrics, list):
                for item in metrics:
                    print(f"    --- Partition: {item.get('Mountpoint')} ---")
                    for key, value in item.items():
                        print(f"        {key:15}: {value}")
            
            # If it's a dictionary (used for OS, CPU, Memory)
            else:
                for key, value in metrics.items():
                    print(f"    {key:15}: {value}")
        print("\n" + "="*67)

    def collect_all(self):
        """Execution controller for full telemetry gathering."""
        logging.info("Initiating full system scan...")
        self.collect_os_info()
        self.collect_cpu_info()
        self.collect_memory_info()
        self.collect_disk_info()
        # self.collect_network_info()
        logging.info("Scan complete.")

    def export_to_json(self, filename=None):
        try:
            if not filename:
                hostname = self.system_data.get("OS", {}).get("Node Name", "unknown")
                filename = f"{hostname}_report.json"

            with open(filename, 'w') as f:
                json.dump(self.system_data, f, indent=4)

            logging.info(f"Saved: {filename}")

        except Exception as e:
            logging.error(f"Export failed: {e}")

# --- Execution ---
if __name__ == "__main__":
    # Instantiate the class
    collector = SystemInfoCollector()
    
    collector.collect_all()
    collector.display_report()
    collector.export_to_json()