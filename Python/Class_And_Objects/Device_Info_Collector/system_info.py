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

    def collect_network_info(self):
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_io_counters()

            net_data = {
                "Hostname": socket.gethostname(),
                "IP Address": socket.gethostbyname(socket.gethostname()),
                "Data Sent": self.get_size(stats.bytes_sent),
                "Data Received": self.get_size(stats.bytes_recv),
                "Interfaces": list(interfaces.keys())
            }

            self.system_data['Network'] = net_data
        except Exception as e:
            logging.error(f"Network info failed: {e}")

    def collect_boot_time(self):
        try:
            if self.is_windows:
                win_time_format = '%a %b %d %I:%M:%S %p %Z %Y'
                boot = datetime.fromtimestamp(psutil.boot_time())
                self.system_data['Boot'] = {
                    "Boot Time": boot.strftime(win_time_format)
                }
            else:
                linux_time_format = "%a %b %d %I:%M:%S %p %Z %Y %Z"
                boot = datetime.fromtimestamp(psutil.boot_time())
                self.system_data['Boot'] = {
                    "Boot Time": boot.strftime(linux_time_format)
                }

        except Exception as e:
            logging.error(f"Boot info failed: {e}")


    def collect_top_processes(self, limit=5):
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
                processes.append(proc.info)

            top = sorted(processes, key=lambda x: x['cpu_percent'], reverse=True)[:limit]
            self.system_data['Top Processes'] = top
        except Exception as e:
            logging.error(f"Process info failed: {e}")

    def collect_windows_intune_reg_info(self):
        if not self.is_windows:
            return
        try:
            import winreg
            data = {}

            path = r"SOFTWARE\Microsoft\Enrollments"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                count = winreg.QueryInfoKey(key)[0]
                data["Enrollments"] = [winreg.EnumKey(key, i) for i in range(count)]
            self.system_data['Windows'] = data

        except Exception as e:
            logging.error(f"Windows info failed: {e}")

    def collect_linux_reg_info(self):
        if not self.is_linux:
            return
        try:
            data = {}

            # OS release
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release") as f:
                    data["Distro"] = f.read()
            # Load avg
            load1, load5, load15 = os.getloadavg()
            data["Load Avg"] = f"{load1}, {load5}, {load15}"

            self.system_data['Linux'] = data

        except Exception as e:
            logging.error(f"Linux info failed: {e}")

    # def display_report(self):
    #     """Prints a formatted report to the console."""
    #     print("="*20, "System Information Report", "="*20)
    #     for category, metrics in self.system_data.items():
    #         # print(f"categoryname is:{category} and its type is type{type(category)}\n")
    #         # print(f"metricname is: {metrics} and its type is type{type(metrics)}\n")
    #         print(f"\n[+] {category}")
            
    #         # Check if metrics is a list (used for Disks)
    #         if isinstance(metrics, list):
    #             for item in metrics:
    #                 print(f"    --- Partition: {item.get('Mountpoint')} ---")
    #                 for key, value in item.items():
    #                     print(f"        {key:15}: {value}")
            
    #         # If it's a dictionary (used for OS, CPU, Memory)
    #         else:
    #             for key, value in metrics.items():
    #                 print(f"    {key:15}: {value}")
    #     print("\n" + "="*67)

    # def collect_all(self):
    #     """Execution controller for full telemetry gathering."""
    #     logging.info("Initiating full system scan...")
    #     self.collect_os_info()
    #     self.collect_cpu_info()
    #     self.collect_memory_info()
    #     self.collect_disk_info()
    #     # self.collect_network_info()
    #     logging.info("Scan complete.")


    def collect_all(self):
        logging.info("Starting scan...")
        self.collect_os_info()
        logging.info("Completed 'collect_os_info()'.\n")
        self.collect_cpu_info()
        logging.info("Completed 'collect_cpu_info()'.\n")
        self.collect_memory_info()
        logging.info("Completed 'collect_memory_info()'.\n")
        self.collect_disk_info()
        logging.info("Completed 'collect_disk_info()'.\n")
        self.collect_network_info()
        logging.info("Completed 'collect_network_info()'.\n")
        self.collect_boot_time()
        logging.info("Completed 'collect_boot_time()'.\n")
        self.collect_top_processes()
        logging.info("Completed 'collect_top_processes()'.\n")
        self.collect_windows_info()
        logging.info("Completed 'collect_windows_info()'.\n")
        self.collect_linux_info()
        logging.info("Completed 'collect_linux_info()'.\n")
        logging.info("Scan complete.")

    # def export_to_json(self, filename=None):
    #     try:
    #         if not filename:
    #             hostname = self.system_data.get("OS", {}).get("Node Name", "unknown")
    #             filename = f"{hostname}_report.json"

    #         with open(filename, 'w') as f:
    #             json.dump(self.system_data, f, indent=4)

    #         logging.info(f"Saved: {filename}")

    #     except Exception as e:
    #         logging.error(f"Export failed: {e}")


    # ---------------- DISPLAY ----------------
    def display_report(self):
        print("="*20, "System Report", "="*20)
        for k, v in self.system_data.items():
            print(f"\n[+] {k}")
            if isinstance(v, list):
                for item in v:
                    print(f"  {item}")
            elif isinstance(v, dict):
                for key, val in v.items():
                    print(f"  {key:15}: {val}")
        print("="*60)

    # ---------------- EXPORT ----------------
    def export_to_json(self, filename=None):
        try:
            if not filename:
                name = self.system_data.get("OS", {}).get("Node Name", "system")
                filename = f"{name}_report.json"

            with open(filename, "w") as f:
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