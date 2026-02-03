import msal
import requests
# import json
import pandas as pd
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from tzlocal import get_localzone
import os
import getpass
import sys


def get_script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

# ------------------------------ Logging --------------------------------------
def setup_logger():
    log_dir = os.path.join(get_script_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("System_Audit")
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
    
# ----------------- CONFIGURATION -----------------
print("🔐 Microsoft Entra ID Authentication Setup")
CLIENT_ID = input("Enter your Client ID: ").strip()
TENANT_ID = input("Enter your Tenant ID: ").strip()
# TENANT_ID = getpass.getpass("Enter your Tenant ID (input will be hidden): ").strip()
# CLIENT_ID = getpass.getpass("Enter your CLIENT_ID =  (input will be hidden): ").strip()
# -------------------------------------------------

if not CLIENT_ID or not TENANT_ID:
    LOGGER.warning("Missing CLIENT_ID or TENANT_ID. Execution halted.")
    print("❌ warning: Both Client ID and Tenant ID are required.")
    exit()

SCOPES = ["https://graph.microsoft.com/.default"]
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
LOGGER.info(f"Accessing MS Entra ID devices using scope: {SCOPES}")
LOGGER.info(f"User credential will be validated using url: {AUTHORITY}")

print("1. Attempting Interactive Login with App Registration credentials...")
app = msal.PublicClientApplication(client_id=CLIENT_ID, authority=AUTHORITY)
result = app.acquire_token_interactive(scopes=SCOPES)

try: 

    if "access_token" in result:
        print("✅ Authentication Successful.")
        LOGGER.info("Authentication Successful")
        token = result['access_token']
        
    #     # 2. Try the exact URL that is failing in the app
    #     url = "https://graph.microsoft.com/v1.0/devices?$top=5"
    #     headers = {"Authorization": f"Bearer {token}"}
        
    #     print(f"2. Requesting: {url}")
    #     resp = requests.get(url, headers=headers)
        
    #     print(f"🔹 HTTP Status Code: {resp.status_code}")
        
    #     if resp.status_code == 200:
    #         data = resp.json()
    #         count = len(data.get('value', []))
    #         print(f"✅ Success! Retrieved {count} devices.")
    #         print("Sample Data:", json.dumps(data.get('value', [])[0], indent=2))
    #     else:
    #         print("❌ FAILED.")
    #         print("Response:", resp.text)
    #         print("\nDIAGNOSIS:")
    #         if resp.status_code == 403:
    #             print("This is a PERMISSION issue. Your User/App Registration lacks 'Device.Read.All'.")
    # else:
    #     print("❌ Authentication Failed:", result.get("error_description"))

        # 1. Construct the EXACT URL used by your app
        base_url = "https://graph.microsoft.com/v1.0/devices/delta"
        selects = "id,deviceId,trustType,accountEnabled,manufacturer,model,displayName"
        url = f"{base_url}?$select={selects}&$top=999"
        LOGGER.info(f"Final url call is {url}")

        print(f"Testing App URL: {url}")

        # 2. Make the request
        headers = {"Authorization": f"Bearer {token}"}
        resp = requests.get(url, headers=headers)

        print(f"HTTP Status: {resp.status_code}")
        LOGGER.info(f"HTTP Status: {resp.status_code}")

        if resp.status_code == 200:
            data = resp.json()
            items = data.get("value", [])
            print(f"✅ Success! Fetched {len(items)} items.")
            LOGGER.info(f"✅ Success! Fetched {len(items)} items.")
            
            # 3. Test the Pandas conversion (where it might be crashing)
            if items:
                try:
                    df = pd.json_normalize(items)
                    print("✅ Pandas Conversion Success.")
                    LOGGER.info("✅ Pandas Conversion Success.")
                    print(f"Columns found: {list(df.columns)}")
                    LOGGER.info(f"Columns found: {list(df.columns)}")
                    
                    # Check for the specific column that caused issues before
                    if "deviceId" in df.columns:
                        print("✅ 'deviceId' column is present.")
                        LOGGER.info("✅ 'deviceId' column is present.")
                    else:
                        print("❌ WARNING: 'deviceId' column is MISSING.")
                        LOGGER.warning("❌ WARNING: 'deviceId' column is MISSING.")
                except Exception as e:
                    print(f"❌ Pandas Error: {e}")
                    LOGGER.error(f"❌ Pandas Error: {e}")
        else:
            print("❌ Request Failed!")
            print(f"Error Response: {resp.text}")

    else:
        error_msg = result.get("error")
        error_desc = result.get("error_description")
        correlation_id = result.get("correlation_id") # Critical for L3/Microsoft Support
        
        full_error = f"Auth Failed: {error_msg} | Description: {error_desc} | CorrelationID: {correlation_id}"
        LOGGER.error(full_error)
        print(f"❌ {full_error}")
        sys.exit(1)
        
except Exception as e:
    # Captures unexpected errors (e.g., no internet, blocked port 8080)
    LOGGER.error(f"💣 Unexpected System Error during Auth: {str(e)}")
    print(f"❌ System Error: {e}")
    sys.exit(1)