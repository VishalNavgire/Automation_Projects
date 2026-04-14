import subprocess
import logging
import json
import re
from typing import Dict, Any


logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %I:%M:%S %p %Z %Y'
)



class EntraDeviceInfoCollector:
    """Collects and parses dsregcmd output for Entra ID join status."""

    def __init__(self):
        self.raw_output = ""
        self.parsed_data: Dict[str, Any] = {}

    def run_dsregcmd(self):
        """Executes dsregcmd /status command."""
        try:
            result = subprocess.run(
                ["dsregcmd", "/status"],
                capture_output=True,
                text=True,
                check=True
            )
            self.raw_output = result.stdout
            logging.info("Successfully executed dsregcmd.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {e}")
        except FileNotFoundError:
            logging.error("dsregcmd not found. Run on Windows device.")

    def parse_output(self):
        """Parses raw dsregcmd output into structured dictionary."""
        if not self.raw_output:
            logging.warning("No output to parse.")
            return

        section = None

        for line in self.raw_output.splitlines():
            line = line.strip()

            # Detect section headers
            if line.startswith("|"):
                section = line.strip("| ").replace(" ", "_")
                self.parsed_data[section] = {}
                continue

            # Parse key-value pairs
            if ":" in line and section:
                key, value = line.split(":", 1)
                self.parsed_data[section][key.strip()] = value.strip()

    def get_summary(self):
        """Extracts key fields for quick view."""
        try:
            device_state = self.parsed_data.get("Device_State", {})

            return {
                "AzureAdJoined": device_state.get("AzureAdJoined"),
                "DomainJoined": device_state.get("DomainJoined"),
                "DeviceName": device_state.get("Device Name"),
            }
        except Exception as e:
            logging.error(f"Error creating summary: {e}")
            return {}

    def display(self):
        """Pretty prints parsed data."""
        print("\n=== Entra Device Status ===")
        for section, values in self.parsed_data.items():
            print(f"\n[{section}]")
            for k, v in values.items():
                print(f"  {k:25}: {v}")

    def export_json(self, filename=None):
        """Exports parsed data to JSON with hostname-based filename."""
        try:
            if not filename:
                # 🔹 Extract hostname safely
                device_state = self.parsed_data.get("Device_State", {})
                hostname = device_state.get("Device Name", "unknown")

                # 🔹 Sanitize hostname (remove invalid characters)
                hostname = re.sub(r'[\\/*?:"<>|]', "", hostname)

                # 🔹 Replace spaces with underscore
                hostname = hostname.replace(" ", "_")

                # 🔹 Build filename
                filename = f"{hostname}_entra_status.json"

            with open(filename, "w") as f:
                json.dump(self.parsed_data, f, indent=4)

            logging.info(f"Saved to {filename}")

        except Exception as e:
            logging.error(f"Export failed: {e}")


# --- Execution ---
if __name__ == "__main__":
    collector = EntraDeviceInfoCollector()

    collector.run_dsregcmd()
    collector.parse_output()

    summary = collector.get_summary()
    print("\nQuick Summary:", summary)

    collector.display()
    collector.export_json()