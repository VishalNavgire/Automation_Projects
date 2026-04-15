import subprocess
import logging
import json
import re
from typing import Dict, List
import socket
from datetime import datetime


logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%a %b %d %I:%M:%S %p %Z %Y'
)


# -------------------------------
# Command Execution Layer
# -------------------------------
class CommandExecutor:
    """Executes system commands."""

    @staticmethod
    def run(command: List[str]) -> str:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True
            )
            logging.info(f"Command executed: {' '.join(command)}")
            return result.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Command failed: {e}")
            return ""
        except FileNotFoundError:
            logging.error("Command not found. Ensure dcdiag is installed.")
            return ""


# -------------------------------
# Parsing Layer
# -------------------------------
class DCDiagParser:
    """Parses dcdiag output into structured format."""

    def __init__(self, raw_output: str):
        self.raw_output = raw_output
        self.parsed_data: Dict[str, Dict[str, str]] = {}

    def parse(self):
        current_server = None

        for line in self.raw_output.splitlines():
            line = line.strip()

            # Detect server name
            server_match = re.search(r"Testing server: (.+)", line)
            if server_match:
                current_server = server_match.group(1)
                self.parsed_data[current_server] = {}
                continue

            # Detect test result
            test_match = re.search(r"(\w+)\s+(passed|failed)\s+test\s+(\w+)", line, re.IGNORECASE)
            if test_match and current_server:
                # server = test_match.group(1)
                status = test_match.group(2).capitalize()
                test_name = test_match.group(3)

                self.parsed_data[current_server][test_name] = status

        return self.parsed_data


# -------------------------------
# Analysis Layer
# -------------------------------
class DCHealthAnalyzer:
    """Analyzes parsed dcdiag data."""

    def __init__(self, parsed_data: Dict):
        self.parsed_data = parsed_data

    def generate_summary(self):
        summary = {}

        for server, tests in self.parsed_data.items():
            total = len(tests)
            passed = sum(1 for v in tests.values() if v == "Passed")
            failed = sum(1 for v in tests.values() if v == "Failed")

            summary[server] = {
                "Total Tests": total,
                "Passed": passed,
                "Failed": failed,
                "Health": "Healthy" if failed == 0 else "Issues Detected"
            }

        return summary


# -------------------------------
# Reporting Layer
# -------------------------------
class DCHealthReporter:
    """Handles display and export of results."""

    def __init__(self, parsed_data: Dict, summary: Dict):
        self.parsed_data = parsed_data
        self.summary = summary

    def display(self):
        print("\n=== Domain Controller Health Report ===")

        for server, data in self.summary.items():
            print(f"\nServer: {server}")
            for key, value in data.items():
                print(f"  {key:15}: {value}")

    # def export_json(self, filename="dc_health_report.json"):
    #     try:
    #         output = {
    #             "Summary": self.summary,
    #             "Details": self.parsed_data
    #         }

    #         with open(filename, "w") as f:
    #             json.dump(output, f, indent=4)

    #         logging.info(f"Report saved to {filename}")
    #     except Exception as e:
    #         logging.error(f"Export failed: {e}")

    def export_json(self, filename=None):
        try:
            if not filename:
                hostname = socket.gethostname()
                timestamp = datetime.now().strftime("%a %b %d %I:%M:%S %p %Z %Y")
                clean_timestamp = timestamp.replace(" ", "_").replace(":", "-")
                filename = f"{hostname}_dc_health_{clean_timestamp}.json"
            output = {
                        "Summary": self.summary,
                        "Details": self.parsed_data
                    }
            with open(filename, "w") as f:
                json.dump(output, f, indent=4)

            logging.info(f"Report saved to {filename}")
        except Exception as e:
            logging.error(f"Export failed: {e}")

# -------------------------------
# Main Controller
# -------------------------------
class DCHealthCheckApp:
    """Main application controller."""

    def __init__(self):
        self.raw_output = ""
        self.parsed_data = {}
        self.summary = {}

    def run(self):
        logging.info("Starting DC health check...")

        # Step 1: Execute command
        self.raw_output = CommandExecutor.run(["dcdiag", "/v"])

        if not self.raw_output:
            logging.error("No output received from dcdiag.")
            return

        # Step 2: Parse
        parser = DCDiagParser(self.raw_output)
        self.parsed_data = parser.parse()

        # Step 3: Analyze
        analyzer = DCHealthAnalyzer(self.parsed_data)
        self.summary = analyzer.generate_summary()

        # Step 4: Report
        reporter = DCHealthReporter(self.parsed_data, self.summary)
        reporter.display()
        reporter.export_json()


# -------------------------------
# Execution
# -------------------------------
if __name__ == "__main__":
    app = DCHealthCheckApp()
    app.run()