
'''
    .Author         - Vishal Navgire [VishalNavgire54@Gmail.Com]
    .Company        - 
    .Created on     - 10-May-2025
    .Co-Author(s)   -
    .Reviewer(s)    -  

.Description
This Python script dynamically imports one or more Python modules (built-in or third-party), lists all their attributes and methods, and logs them to a file with timestamped filenames.

Each module's log file is saved in the **same directory where the script is executed**, including classification of each item as a **function** or an **attribute**.


.Features
- Accepts **multiple module names** (e.g., `math os sys`).
- Logs the **name, type (method/attribute)** of each item in the module.
- Each module generates its own log file.
- Logs are timestamped with local time and time zone.
- Custom logging format with severity levels: INFO, ERROR, SUCCESS.

# 🛠️ Requirements

- Python 3.6+

'''

import importlib
import os
import subprocess
from datetime import datetime
import tzlocal
import time
# from pytz import timezone

# Get the local timezone correctly
def get_custom_formatted_datetime_logfilename ():
    '''Fucntion for creating current date and time for Log entries and log file name.'''
    try:
        local_timezone = tzlocal.get_localzone()
        current_time = datetime.now(local_timezone).strftime('%d:%B:%Y %I:%M:%S %p') #if local_timezone else "Unknown TZ"
        formated_datetime_for_logfile = current_time.replace(' ',"_").replace(':',"_")
    except Exception as e:
        print(f"Error: Unable to fetch timezone - {e}")
        current_time = "Unknown"
        formatted_for_filename = "Unknown_Timestamp"

    return  current_time, formated_datetime_for_logfile


def log_message(level, message):
    """Logs a message with timestamp and level."""
    returned_values = get_custom_formatted_datetime_logfilename()
    current_time = returned_values[0]
    tz = datetime.now().astimezone().tzinfo

    # Extract the time zone name
    required_time_zone = tz.tzname(datetime.now())
    level_text = {'error': 'ERROR:','warning': 'WARNING:','info': 'INFO:', 'success': 'SUCCESS:'}.get(level.lower(), 'INFO:')

    return f"{[current_time]} - {[required_time_zone]} - {[level_text]} - {message}"


def get_module_methods_and_attributes(module_name):
    """Fetches all methods and attributes of a module."""
    output_lines = []

    try:
        module = importlib.import_module(module_name)
        all_methods = dir(module)

        for idx, each_item in enumerate(all_methods, start=1):
            output_lines.append(f"\n{idx}. {each_item.title()}")
            if callable(getattr(module, each_item)):
                output_lines.append(log_message('info', f"'{each_item}' is a function in module: {module_name}."))
            else:
                output_lines.append(log_message('info', f"'{each_item}' is an attribute in module: {module_name}."))

    except ModuleNotFoundError:
        error_message = log_message('error', f"The module '{module_name}' was not found.")
        output_lines.append(error_message)

    except Exception as e:
        error_message = log_message('error', f"An unexpected error occurred: {e}")
        output_lines.append(error_message)

    return output_lines

# Example usage
if __name__ == "__main__":
    print("\n")
    user_input = input("Enter module names separated by comma (e.g: os,sys,math):\n").strip()
    module_names = [name.strip() for name in user_input.split(",") if name.strip()]

    print("\n" + '--' * 10)
    script_dir = os.path.dirname(os.path.abspath(__file__))

    for Each_Module_Name in module_names:
        print(f"Process module name: {Each_Module_Name}. ")
        output_lines = get_module_methods_and_attributes(Each_Module_Name)
        returned_values = get_custom_formatted_datetime_logfilename()
        formated_datetime_for_logfile_name = returned_values[1]
        log_file_path = rf"{script_dir}\Fetch_Methods_And_Attributes_For_PythonModule_{Each_Module_Name}_{formated_datetime_for_logfile_name}.Log"

        with open(log_file_path, 'a') as file:
            file.write("------- Start Of log capturing --------" + "\n")
            file.write("\n".join(output_lines) + "\n")
            file.write("------- End Of log capturing --------" + "\n")
            file.write("\n")

        print(f"Log file created for '{Each_Module_Name}': {log_file_path}")
        time.sleep(5)
        print("\n" + '--' * 10)