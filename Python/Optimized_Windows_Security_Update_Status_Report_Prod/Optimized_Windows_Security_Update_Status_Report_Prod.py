# Optimized_Windows_Security_Update_Status_Report_Prod.py
'''
Docstring for ProdFolder.Optimized_Windows_Security_Update_Status_Report_Prod_V2
Resources :
https://learn.microsoft.com/en-us/graph/api/resources/device?view=graph-rest-1.0
'''

import os
import time
import random
import logging
from logging.handlers import RotatingFileHandler
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Tuple
import streamlit as st
import pandas as pd
import plotly.express as px
import requests
from bs4 import BeautifulSoup
import datetime as dt
from datetime import datetime
from tzlocal import get_localzone
from msal import PublicClientApplication
# from streamlit_plotly_events import plotly_events
# import io


# --------------------------- Constants / Defaults -----------------------------
SCOPES = ["https://graph.microsoft.com/.default"]
DEFAULT_INTUNE_URL_BASE = "https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"
DEFAULT_AAD_DEVICES_URL_BASE = "https://graph.microsoft.com/v1.0/devices"
DEFAULT_USERS_URL_BASE = "https://graph.microsoft.com/v1.0/users"
DEFAULT_WIN11_URL = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
BYTES_IN_GB = 1024 ** 3

# Tight $selects for small payloads
INTUNE_SELECT = ",".join([
    "id","deviceName","azureADDeviceId","operatingSystem","osVersion","enrolledDateTime",
    "isEncrypted","lastSyncDateTime","totalStorageSpaceInBytes",
    "freeStorageSpaceInBytes","userPrincipalName","complianceState",
])
USERS_SELECT = ["id","displayName","userPrincipalName"]
DEVICES_SELECT = ["id","deviceId","trustType","accountEnabled","manufacturer","model","displayName"]

# ------------------------------ Helper: Get Script Directory -----------------
def get_script_dir() -> str:
    """Returns the directory where the script is located."""
    script_name = os.path.splitext(os.path.basename(__file__))
    root_dir = os.path.dirname(os.path.abspath(__file__))
    return root_dir, script_name

# ------------------------------ Logging --------------------------------------
def setup_logger():
    '''
    This function configures a centralized logging system for the application. 
    It creates a logs directory relative to the script location and initializes a named logger. 
    The logger uses a rotating file handler to limit log file size to 10MB and keeps up to five backup files. 
    A custom formatter is used to include timestamp, log level, function name, message, filename, and line number. 
    The timestamp is converted to the system's local timezone using tzlocal. 
    Finally, the configured logger is returned and stored as a global variable so the entire application can use consistent logging.
    '''
    folder_location, file_name = get_script_dir()
    log_dir = os.path.join(folder_location, "logs")
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger(file_name[0])
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(
            os.path.join(log_dir, file_name[0] + ".log"),
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

# ------------------------------ HTTP (Retry) ---------------------------------
def _sleep_with_jitter(base_seconds: float) -> None:
    jitter = random.uniform(0.1 * base_seconds, 0.3 * base_seconds)
    sleep_time = base_seconds + jitter
    LOGGER.info(f"Pausing code execution for: {sleep_time:.2f} seconds.")
    time.sleep(base_seconds + jitter)

def http_get(url: str, headers: Dict[str, str], timeout: int = 30,
             max_retries: int = 6) -> requests.Response:
    '''
        This function performs an HTTP GET request with built-in retry logic. 
        It handles rate limiting (HTTP 429) and server errors (5xx) by retrying the request using exponential backoff with jitter to prevent simultaneous retries. 
        If the server provides a Retry-After header, the function respects that delay. 
        Network-related exceptions are also caught and retried. 
        If the request still fails after the maximum number of retries, the function raises a RuntimeError.
    '''
    attempt = 0
    backoff = 1.0
    last_exc = None
    while attempt <= max_retries:
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            if resp.status_code >= 400:
                LOGGER.warning(f"HTTP {resp.status_code} for {url}")
            
            ra = resp.headers.get("Retry-After")

            if resp.status_code == 429: # HTTPs 429 error code means that Too Many requests sent (rate limit exceeded).
                LOGGER.warning(f"Too Many HTTP requests sent status code {resp.status_code} for {url}")
                if ra:
                    time.sleep(float(ra))
                else:
                    _sleep_with_jitter(backoff)
                backoff = min(backoff * 2, 32)
                attempt += 1
                continue
            if 500 <= resp.status_code < 600: 
                LOGGER.warning(f"HTTP status code {resp.status_code} for {url}")
                _sleep_with_jitter(backoff)
                backoff = min(backoff * 2, 32)
                attempt += 1
                continue
            resp.raise_for_status()
            LOGGER.info(f"Successfully retrived the data for url {url}")
            return resp
        except requests.RequestException as e:
            last_exc = e
            LOGGER.error(f"HTTP error on {url}: {e}")
            _sleep_with_jitter(backoff)
            backoff = min(backoff * 2, 32)
            attempt += 1
    raise RuntimeError(f"GET failed after retries for {url}: {last_exc}")

# -------------------------- Graph paging helpers -----------------------------
def graph_get_all(url: str, token: str, page_limit: Optional[int] = None) -> List[Dict[str, Any]]:
    '''
    This function retrieves all paginated data from an API endpoint. 
    It sends authenticated requests using a Bearer token and repeatedly follows the @odata.nextLink pagination URL until all pages are retrieved or an optional page limit is reached. 
    Each page of results is safely extracted and flattened using pandas json_normalize to handle nested JSON structures. 
    The records are then converted back into dictionaries and accumulated in a list, which is returned at the end.
    '''
    # headers = {"Authorization": f"Bearer {token}"}
    headers = {
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "User-Agent": "PythonGraphClient/1.0"
                }
    items: List[Dict[str, Any]] = []
    fetched = 0
    next_url = url
    while next_url:
        resp = http_get(next_url, headers=headers)
        data = resp.json()
        # Safe extraction
        page_items = data.get("value", [])
        if page_items:
            # Flatten if needed, but safe append
            try:
                df_page = pd.json_normalize(page_items)
                items.extend(df_page.to_dict(orient="records"))
            except (ValueError, TypeError) as e:
                LOGGER.error(f"json_normalize failed: {e}. Falling back to raw items.")
                items.extend(page_items)
            except Exception as e:
                LOGGER.error(f"Normalization failed, using raw items. Error: {e}")
                items.extend(page_items)

            fetched += len(page_items)
        
        next_url = data.get("@odata.nextLink")
        LOGGER.info(f"Processing the Next url: {next_url}")
        if page_limit and fetched >= page_limit:
            break
    return items

# ----------------------------- Local cache -----------------------------------
def _cache_paths(name: str) -> Tuple[str, str]:
    """
    Generate local cache file paths for storing dataset files.

    This function ensures a `.cache` directory exists in the same
    location as the running script. It then constructs file paths
    for storing the dataset in both Parquet and CSV formats.

    Parquet is preferred because it is faster and more efficient,
    while CSV acts as a fallback format if Parquet writing fails.

    Benefits of using Parquet file:
        smaller file size
        faster loading
        better for large datasets

    Parameters
    ----------
    name : str
        Logical dataset name (for example: "users", "devices").
        This name is used as the file name prefix.

    Returns
    -------
    Tuple[str, str]
        A tuple containing:
        - Parquet file path
        - CSV file path

    Example
    -------
    >>> _cache_paths("users")
    ('/project/.cache/users.parquet', '/project/.cache/users.csv')

    Notes
    -----
    The `.cache` folder is automatically created if it does not exist.
    """
    folder_location, file_name = get_script_dir()
    cache_dir = os.path.join(folder_location, ".cache")
    os.makedirs(cache_dir, exist_ok=True)
    paraquet_filename = os.path.join(cache_dir, f"{name}.parquet")
    csv_filename = os.path.join(cache_dir, f"{name}.csv")
    # if os.path.exists(path=cache_dir):
    #     LOGGER.info(f"Successfully created cache directory as: {cache_dir}")
    #     if os.path.exists(paraquet_filename):
    #         LOGGER.info(f"Successfully created parquet file as: {paraquet_filename}")
    #     if os.path.exists(csv_filename):
    #         LOGGER.info(f"Successfully created csv file as: {csv_filename}")
    # return (os.path.join(cache_dir, f"{name}.parquet"),
    #         os.path.join(cache_dir, f"{name}.csv"))
    return (paraquet_filename, csv_filename)

def save_df(name: str, df: pd.DataFrame) -> None:
    """
    Save a pandas DataFrame to the local cache.

    The function attempts to store the DataFrame in Parquet format
    for optimal performance and smaller file size. If Parquet saving
    fails (for example due to missing dependencies), it automatically
    falls back to saving the data as a CSV file.

    Parameters
    ----------
    name : str
        Logical dataset name used to generate the cache file name.

    df : pandas.DataFrame
        The DataFrame that needs to be stored in the local cache.

    Returns
    -------
    None

    Notes
    -----
    - Files are stored in the `.cache` directory relative to the script.
    - Parquet format is preferred due to faster read/write performance.
    - CSV is used as a fallback if Parquet saving fails.
    """
    pq, csv = _cache_paths(name)
    try:
        df.to_parquet(pq, index=False)
        LOGGER.debug(f"Successfully saved Dataframe in the parquet format as: {pq}")
    except Exception as e:
        LOGGER.error(f"Parquet save failed ({e}); falling back to CSV.")
        df.to_csv(csv, index=False)
        LOGGER.debug(f"Successfully saved Dataframe in the csv file as: {csv}")

def load_df(name: str) -> pd.DataFrame:
    """
    Load a cached dataset from the local `.cache` directory.

    The function attempts to read the dataset in the following order:

    1. Parquet file (preferred format)
    2. CSV file (fallback format)

    If neither file exists or loading fails, an empty DataFrame
    is returned.

    Parameters
    ----------
    name : str
        Logical dataset name used to locate the cache file.

    Returns
    -------
    pandas.DataFrame
        The loaded DataFrame if cache exists, otherwise an empty DataFrame.

    Notes
    -----
    - Parquet is attempted first because it is faster and more efficient.
    - CSV is used as a fallback if Parquet reading fails.
    - If no cache file is found, an empty DataFrame is returned
      so that the calling function can trigger a full data sync.
    """
    pq, csv = _cache_paths(name)
    if os.path.exists(pq):
        try:
            df = pd.read_parquet(pq)
            LOGGER.info(f"Loading parquet file: {pq}")
            return df
        except Exception: 
            LOGGER.exception("Failed to load DataFrame as Parquet File.")
    if os.path.exists(csv):
        try:
            df = pd.read_csv(csv)
            LOGGER.info(f"Loading csv file: {csv}")
            return df
        except Exception: 
            LOGGER.exception("Failed to load DataFrame as CSV File.")
    return pd.DataFrame()

def _delta_link_path(name: str) -> str:
    """
    Generate the file path used to store the Microsoft Graph delta link.

    Microsoft Graph Delta API returns a special URL (`@odata.deltaLink`)
    that represents the last synchronization state. This function creates
    a file path where that delta link will be stored locally so that
    future runs can request only incremental changes.

    Parameters
    ----------
    name : str
        Logical dataset name (for example: "users" or "devices").

    Returns
    -------
    str
        Full file path where the delta link will be stored.

    Notes
    -----
    - The delta file is stored inside the `.cache` directory.
    - Example file name: `.cache/users.delta`
    - If the directory does not exist, it will be created automatically.
    """
    folder_location, file_name = get_script_dir()
    cache_dir = os.path.join(folder_location, ".cache")
    os.makedirs(cache_dir, exist_ok=True)
    delta_filename = os.path.join(cache_dir, f"{name}.delta")
    LOGGER.info(f"Delta file to process new changes is: {delta_filename}")
    return delta_filename

# ----------------------------- Delta Sync (Self-Healing) ---------------------
def _delta_initial_url(base: str, select: List[str], filt: Optional[str]) -> str:
    """
    Build or Develop the initial Microsoft Graph Delta API request URL.

    When the application runs for the first time and no delta token
    exists yet, a delta request must start with the `/delta` endpoint.
    This function constructs that initial request URL and optionally
    includes query parameters such as `$select`, `$filter`, and `$top`.

    Parameters
    ----------
    base : str
        Base Microsoft Graph endpoint (for example:
        "https://graph.microsoft.com/v1.0/users").

    select : List[str]
        List of fields to retrieve from the API using `$select`.
        This helps reduce payload size.

    filt : Optional[str]
        Optional OData filter expression applied to the query.

    Returns
    -------
    str
        Fully constructed delta request URL.

    Example
    -------
    https://graph.microsoft.com/v1.0/users/delta?$select=id,displayName&$top=999

    Notes
    -----
    - `$top=999` is used to increase page size and reduce API calls.
    - `$select` limits returned properties for performance optimization.
    """
    qs = []
    if select: 
        qs.append(f"$select={','.join(select)}")
    if filt: 
        qs.append(f"$filter={filt}")
    qs.append("$top=999")
    return f"{base}/delta" + ("?" + "&".join(qs) if qs else "")


def delta_sync_collection(name: str, session) -> pd.DataFrame:
    """
    Synchronize a Microsoft Graph collection using the delta query mechanism.

    This function keeps a local cached dataframe synchronized with a remote
    Microsoft Graph collection. It performs an initial full sync if no
    delta link exists, and incremental updates on subsequent runs.

    Workflow
    --------
    1. Load existing cached dataframe (if available)
    2. Load stored delta link
    3. Fetch changes from Microsoft Graph using delta query
    4. Apply deletions and updates to the local dataframe
    5. Save updated dataframe and delta link

    Parameters
    ----------
    name : str
        Name of the collection (example: "users", "groups").
        Used to determine cache file and delta token location.

    session : requests.Session
        Authenticated HTTP session used to call Microsoft Graph API.

    Returns
    -------
    pandas.DataFrame
        Updated dataframe containing the latest synchronized records.

    Notes
    -----
    - Uses delta tokens to fetch only changes since last sync.
    - Deleted records are removed from the dataframe.
    - Updated records replace older versions.
    """

    LOGGER.info("Starting delta sync for %s", name)
    df = load_df(name)
    delta_path = _delta_link_path(name)
    url = _delta_initial_url(name)
    if delta_path.exists():
        url = delta_path.read_text().strip()

    changed_rows = []
    new_delta_link = None

    # Fetch pages from Graph API
    while url:
        LOGGER.debug("Fetching delta page")

        resp = session.get(url)
        resp.raise_for_status()

        data = resp.json()

        changed_rows.extend(data.get("value", []))

        url = data.get("@odata.nextLink")
        new_delta_link = data.get("@odata.deltaLink", new_delta_link)

    # If no changes returned, return existing dataframe
    if not changed_rows:
        LOGGER.info("No changes detected for %s", name)
        return df

    # Convert JSON changes to dataframe
    changes = pd.json_normalize(changed_rows)

    deleted = changes[changes.get("@removed.reason").notna()] #Value is not empty. Meaning data is deleted.
    updates = changes[changes.get("@removed.reason").isna()] #Value is empty. Meaning data is not deleted.

    # Remove deleted records
    if not deleted.empty and not df.empty:
        LOGGER.info("Removing %d deleted rows", len(deleted))
        df = df[~df["id"].isin(deleted["id"])]

    # Apply updates (upsert pattern)
    if not updates.empty:
        LOGGER.info("Applying %d updates", len(updates))

        if df.empty:
            df = updates.copy()
        else:
            df = df[~df["id"].isin(updates["id"])]
            df = pd.concat([df, updates], ignore_index=True)

    # Normalize datatypes
    df = df.convert_dtypes()

    # Save updated dataframe
    save_df(name, df)

    # Save new delta link
    if new_delta_link:
        delta_path.write_text(new_delta_link, encoding="utf-8")

    LOGGER.info("Delta sync completed for %s", name)

    return df

# -------------------------- Windows release tables ---------------------------
@st.cache_data(ttl=2 * 3600) #Decorator used in the Streamlit framework to cache the result of a function 'fetch_windows_release_tables' so that it does not run again unnecessarily.
def fetch_windows_release_tables(url: str) -> List[pd.DataFrame]:
    """
    Fetch and parse HTML tables from a Windows release documentation page.

    This function downloads the HTML content of the provided URL, extracts
    all <table> elements, converts them into pandas DataFrames, and returns
    them as a list.

    The function attempts to normalize table rows so that each row has the
    same number of columns as the header.

    Parameters
    ----------
    url : str
        URL of the webpage containing Windows release tables.

    Returns
    -------
    List[pandas.DataFrame]
        A list of DataFrames representing the extracted tables.
        Returns an empty list if parsing fails.

    Notes
    -----
    - Uses BeautifulSoup to parse HTML tables.
    - Rows with fewer columns than headers are padded with empty strings.
    - Rows with extra columns are truncated.
    - Cached for 2 hours using Streamlit's cache_data decorator.
    """
    try:
        resp = http_get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=30)
        soup = BeautifulSoup(resp.text, "html.parser")
        tables = soup.find_all("table")
        dfs = []
        for t in tables:
            rows = t.find_all("tr")
            if not rows: 
                continue
            hdrs = [th.get_text(strip=True) for th in rows[0].find_all(["th", "td"])] #This line extracts the column names from the first row.
            data = []
            for r in rows[1:]:
                cols = [td.get_text(strip=True) for td in r.find_all("td")] #This extracts the data values from each row.
                if cols:
                    if len(cols) < len(hdrs): 
                        cols += [""] * (len(hdrs) - len(cols))
                    else: 
                        cols = cols[:len(hdrs)]
                    data.append(cols)
            if data: 
                dfs.append(pd.DataFrame(data, columns=hdrs))
        return dfs
    except Exception:
        LOGGER.exception("Error:")
        return []

def safe_merge_win11_tables(win_tables: List[pd.DataFrame]) -> pd.DataFrame:
    """
    Merge Windows release tables into a single dataframe.

    This function combines multiple DataFrames containing Windows release
    information into a single consolidated DataFrame.

    It prioritizes tables that contain important columns such as
    'Build' or 'Availability Date'. If such tables exist, only those
    are merged. Otherwise, all tables are merged.

    Parameters
    ----------
    win_tables : List[pandas.DataFrame]
        List of DataFrames extracted from Windows documentation tables.

    Returns
    -------
    pandas.DataFrame
        A merged DataFrame containing combined release information.
        Returns an empty DataFrame if input is empty or merging fails.

    Notes
    -----
    - Uses pandas.concat() for merging.
    - Logs errors using the application logger if merging fails.
    """
    if not win_tables: 
        return pd.DataFrame()
    try:
        candidates = [t for t in win_tables if any(c.lower().strip() in ["build", "availability date"] for c in t.columns)] # List comprehension - Find tables that contain important columns {build; avaiablability date}. Only tables with useful columns are selected.
        return pd.concat(candidates, ignore_index=True, sort=False) if candidates else pd.concat(win_tables, ignore_index=True, sort=False) #Conditional return statement - If candidate tables exist → merge them; Else → merge all tables.
    except Exception: 
        LOGGER.exception("An Error Occured.")
        return pd.DataFrame()

# ----------------------------- Autopilot devices -----------------------------
def get_autopilot_devices(token: str) -> pd.DataFrame:
    url = "https://graph.microsoft.com/v1.0/deviceManagement/windowsAutopilotDeviceIdentities?$top=999"
    try:
        items = graph_get_all(url, token)
        df = pd.json_normalize(items) if items else pd.DataFrame()
        if "serialNumber" in df.columns:
            df["serialNumber"] = df["serialNumber"].astype(str).str.upper().str.strip()
        return df
    except Exception:
        LOGGER.exception("Autopilot fetch failed (Permission denied or API error). Returning empty.")
        return pd.DataFrame()

def load_data_with_token(intune_base_url: str, users_url_base: str, aad_url_base: str, win_url: str, token: str) -> Dict[str, Any]:
    """
    Fetches and prepares multiple datasets required for the Streamlit dashboard
    using a Microsoft Graph access token.

    This function performs concurrent data collection from several sources,
    including Microsoft Intune, Microsoft Entra ID, Windows release health
    documentation, and Windows Autopilot devices. The data is retrieved using
    parallel execution to improve performance.

    The collected datasets are normalized into pandas DataFrames, validated
    against expected schemas, optimized with categorical types, and timestamp
    columns are converted into timezone-aware datetime formats.

    Parallel Data Sources:
        • Intune Managed Devices (Microsoft Graph)
        • Entra ID Users (Delta Sync)
        • Entra ID Devices (Delta Sync)
        • Windows 11 Release Health Tables (Web Scraping)
        • Windows Autopilot Devices (Graph API)

    Args:
        intune_base_url (str):
            Microsoft Graph endpoint for Intune managed devices.

        users_url_base (str):
            Microsoft Graph endpoint for Entra users.

        aad_url_base (str):
            Microsoft Graph endpoint for Entra devices.

        win_url (str):
            URL for Windows 11 release health information.

        token (str):
            OAuth2 access token obtained via MSAL authentication.

    Returns:
        Dict[str, Any]:
            Dictionary containing the following keys:

            intune_df : pandas.DataFrame
                Intune managed devices dataset.

            aad_df : pandas.DataFrame
                Entra ID devices dataset.

            ms_entra_users_df : pandas.DataFrame
                Entra ID users dataset.

            autopilot_devices_df : pandas.DataFrame
                Windows Autopilot devices dataset.

            win_tables : List[pandas.DataFrame]
                Raw scraped tables from Windows release health page.

            merged_win11_df : pandas.DataFrame
                Combined Windows 11 release information table.

    Raises:
        RuntimeError:
            If critical API calls fail after retries.

    Notes:
        • Uses ThreadPoolExecutor for parallel API requests.
        • Includes fault tolerance to prevent dashboard crashes.
        • Ensures schema consistency across datasets.
    """
    intune_url_final = (f"{intune_base_url}?$top=999&$select={INTUNE_SELECT}")
    results: Dict[str, Any] = {}
    
    with ThreadPoolExecutor(max_workers=4) as ex:
        futures = {
            "intune": ex.submit(graph_get_all, intune_url_final, token),
            "users": ex.submit(delta_sync_collection, "users", users_url_base, token, USERS_SELECT),
            "devices": ex.submit(delta_sync_collection, "devices", aad_url_base, token, DEVICES_SELECT),
            "win_tbls": ex.submit(fetch_windows_release_tables, win_url),
            "autopilot": ex.submit(get_autopilot_devices, token),
        }
        for name, f in futures.items():
            try:
                results[name] = f.result()
            except Exception as e:
                LOGGER.exception(f"Task '{name}' failed: {e}")
                results[name] = pd.DataFrame() if name != "win_tbls" else []

    # Unpack Results
    intune_data = results.get("intune", [])
    intune_df = pd.json_normalize(intune_data) if intune_data else pd.DataFrame()
    users_df  = results.get("users", pd.DataFrame())
    aad_df    = results.get("devices", pd.DataFrame())
    win_tables = results.get("win_tbls", [])
    autopilot_df = results.get("autopilot", pd.DataFrame())
    merged_win11_df = safe_merge_win11_tables(win_tables)

    # Force Schema: Aad Devices
    expected_aad_cols = ["id", "deviceId", "trustType", "accountEnabled", "manufacturer", "model", "displayName"]
    if aad_df.empty: 
        aad_df = pd.DataFrame(columns=expected_aad_cols)
    else:
        for col in expected_aad_cols:
            if col not in aad_df.columns: 
                aad_df[col] = pd.NA

    # Force Schema: Users
    expected_user_cols = ["id", "displayName", "userPrincipalName"]
    if users_df.empty: 
        users_df = pd.DataFrame(columns=expected_user_cols)
    else:
        for col in expected_user_cols:
            if col not in users_df.columns: 
                users_df[col] = pd.NA

    # Force Schema: Intune
    if "azureADDeviceId" not in intune_df.columns:
         intune_df = pd.DataFrame(columns=["id", "azureADDeviceId", "operatingSystem", "userPrincipalName"]) if intune_df.empty else intune_df.assign(azureADDeviceId=pd.NA)

    # Dtypes
    '''
        Many columns in device datasets contain repeated values like operating systems, compliance states, or manufacturers. 
        Converting these columns to categorical types reduces memory consumption because pandas stores unique values only once and references them internally. 
        It also improves performance for operations like grouping and filtering, which are common in analytics dashboards.
    '''
    for df, cats in [
        (intune_df, ["operatingSystem","complianceState","userPrincipalName"]),
        (aad_df,    ["trustType","manufacturer","model","displayName"]),
        (users_df,  ["displayName","userPrincipalName"]),
        (autopilot_df, ["groupTag","enrollmentState"])
    ]:
        if not df.empty:
            for c in cats:
                if c in df.columns: 
                    df[c] = df[c].astype("category")

    def _dt(df, cols):
        '''
            API responses may contain invalid or missing timestamp values. 
            Using errors="coerce" ensures that invalid entries are converted to NaT ('Not a Time') instead of raising exceptions, 
            allowing the Dashboard or pipeline to continue processing safely.
        '''
        if not df.empty:
            for c in cols:
                if c in df.columns: 
                    df[c] = pd.to_datetime(df[c], errors="coerce", utc=True)
                
    _dt(intune_df, ["enrolledDateTime","lastSyncDateTime"])
    _dt(aad_df,    ["createdDateTime","registrationDateTime"])
    _dt(autopilot_df, ["lastContactedDateTime"])

    return {"intune_df": intune_df, 
            "aad_df": aad_df, 
            "ms_entra_users_df": users_df, 
            "autopilot_devices_df": autopilot_df, 
            "win_tables": win_tables, 
            "merged_win11_df": merged_win11_df}

def get_current_user(token: str) -> Dict[str, Any]:
    try:
        return http_get("https://graph.microsoft.com/v1.0/me", headers={"Authorization": f"Bearer {token}"}).json()
    except Exception: 
        LOGGER.exception("An Error Occurred:")
        return {}

def is_cache_present(names: List[str]) -> bool:
    folder_location, file_name = get_script_dir()
    cache_dir = os.path.join(folder_location, ".cache")
    if not os.path.exists(cache_dir):
        LOGGER.warning(f"Cache folder/s doesn't exit: {cache_dir}") 
        return False
    for name in names:
        if not os.path.exists(os.path.join(cache_dir, f"{name}.parquet")):
            LOGGER.warning(f"Cache file doesn't exit: {name}.parquet")  
            return False
    return True

# ----------------------------- Streamlit UI ----------------------------------
st.set_page_config(page_title="Intune Managed Windows Endpoints Dashboard", layout="wide", initial_sidebar_state="expanded")

try:
    local_tz = get_localzone()
    formatted_datetime = dt.datetime.now(local_tz).strftime("%A, %B %d, %Y %I:%M:%S %p %Z")
except Exception:
    LOGGER.exception("An Error Occurred.")
    formatted_datetime = dt.datetime.now().strftime("%A, %B %d, %Y %I:%M:%S %p")

st.sidebar.header("🔐 User Authentication Required (Interactive)")
st.sidebar.caption("Use an account with **READ permissions** on Users, Devices (Entra) and Intune managed devices.")

st.sidebar.subheader("🌐 Data Source URLs")
intune_url = st.sidebar.text_input("Intune Devices URL", value=DEFAULT_INTUNE_URL_BASE)
aad_url_base = st.sidebar.text_input("Entra Devices URL", value=DEFAULT_AAD_DEVICES_URL_BASE)
users_url_base = st.sidebar.text_input("Entra Users URL", value=DEFAULT_USERS_URL_BASE)
win_url = st.sidebar.text_input("Windows 11 Health URL", value=DEFAULT_WIN11_URL)

st.sidebar.subheader("🛡️ Credentials")
CLIENT_ID = st.sidebar.text_input("Client ID", type="password", placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
TENANT_ID = st.sidebar.text_input("Tenant ID", type="password", placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
USER_UPN  = st.sidebar.text_input("Sign-in Email", placeholder="user@contoso.com")
auth_button = st.sidebar.button("🔑 Sign in")
st.sidebar.caption("Clicking this sign-in button will open a browser prompt for interactive sign-in.")

main_title_text = "📊 Intune Managed Windows Endpoints Dashboard"
st.markdown(f"<h1 style='text-align: center; color: #fefdfd;'>{main_title_text}</h1>", unsafe_allow_html=True)
st.markdown(f"<p style='text-align: center; color: #fefdfd;'>Last Refreshed: {formatted_datetime}</p>", unsafe_allow_html=True)
st.markdown("---")
tabs = st.tabs([
                "📊 KPIs",
                "💻 Windows Security Updates Status Report",
               "🪟 Windows 11 Release Information "
            ])

if auth_button:
    if not CLIENT_ID or not TENANT_ID or not USER_UPN:
        st.sidebar.error("Missing credentials.")
        LOGGER.error(f"Missing User login credentials CLIENT_ID: {CLIENT_ID}, TENANT_ID: {TENANT_ID}, USER_UPN: {USER_UPN}.")
    else:
        cache_exists = is_cache_present(["users", "devices"])
        try:
            authority = f"https://login.microsoftonline.com/{TENANT_ID}"
            LOGGER.info(f"User login will be redirected to and authenticated from: {authority}.")
            app = PublicClientApplication(client_id=CLIENT_ID, authority=authority)
            
            with st.status("🔐 Initiating Session...", expanded=True) as status:
                st.write("🔑 Authenticating...")
                result = app.acquire_token_interactive(scopes=SCOPES, login_hint=USER_UPN)
                
                if "access_token" in result:
                    start_time = time.perf_counter()
                    LOGGER.info(f"Authentication was successfull. Data Loading start time is {start_time}")
                    token = result["access_token"]
                    st.session_state["user_profile"] = get_current_user(token)
                    LOGGER.info(f"Logged in user is: {get_current_user(token)}")

                    if not cache_exists:
                        st.warning("⚠️ No local cache. Performing FULL SYNC. This will take a few minutes.")
                        LOGGER.warning("No cache detected. Starting Full Sync.")
                    else:
                        st.info("⚡Local Cache found. Performing DELTA SYNC.")
                        LOGGER.info("Cache detected. Starting Delta Sync.")

                    st.write("📦 Synchronizing Data...")
                    data = load_data_with_token(intune_url, users_url_base, aad_url_base, win_url, token)
                    if not data:
                        LOGGER.warning("Failed to load data frames using function name 'load_data_with_token'")
                    st.session_state["data"] = data
                    
                    elapsed = time.perf_counter() - start_time
                    mins, secs = divmod(elapsed, 60)
                    time_str = f"{int(mins)}m {int(secs)}s"
                    
                    LOGGER.info(f"Data load completed in {time_str}")
                    status.update(label=f"✅ Complete! ({time_str})", state="complete", expanded=False)
                    st.success(f"🚀 Dashboard refreshed in **{time_str}**")
                else:
                    st.error(f"Auth Failed: {result.get('error_description')}")
                    LOGGER.error(f"Auth Failed: {result.get('error_description')}")
                    st.stop()
        except Exception as e:
            st.error(f"System Error: {e}")
            LOGGER.exception(f"Critical failure: {e}")

if "user_profile" in st.session_state:
    profile = st.session_state["user_profile"]
    if profile:
        st.sidebar.divider()
        st.sidebar.subheader("👤 Signed In As")
        c1, c2 = st.sidebar.columns([1, 3])
        with c1:
            initials = profile.get('displayName', '??')[0:2].upper()
            st.markdown(f"""
            <div style='background-color:#0078D4; color:white; border-radius:50%; 
                        width:40px; height:40px; display:flex; align-items:center; 
                        justify-content:center; font-weight:bold;'>{initials}</div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown(f"**{profile.get('displayName')}**")
            st.caption(profile.get('userPrincipalName'))
            if profile.get('jobTitle'):
                st.caption(f"_{profile.get('jobTitle')}_")

if "data" not in st.session_state:
    st.info("👈 Sign in to view dashboard.")
    st.stop()

# Data Logic
intune_df = st.session_state["data"].get("intune_df", pd.DataFrame())
aad_df = st.session_state["data"].get("aad_df", pd.DataFrame())
users_df = st.session_state["data"].get("ms_entra_users_df", pd.DataFrame())
win_tables = st.session_state["data"].get("win_tables", [])
merged_win11_df = st.session_state["data"].get("merged_win11_df", pd.DataFrame())
autopilot_df = st.session_state["data"].get("autopilot_devices_df", pd.DataFrame())

merged_out = pd.merge(intune_df, 
                      aad_df,left_on="azureADDeviceId",
                      right_on="deviceId",
                      how="outer",
                      suffixes=("_intune", "_aad"),
                      indicator=True)

for col in ["totalStorageSpaceInBytes", "freeStorageSpaceInBytes"]:
    if col in merged_out.columns:
        merged_out[col] = pd.to_numeric(merged_out[col], errors="coerce")
merged_out["freeGB"] = (merged_out["freeStorageSpaceInBytes"] / BYTES_IN_GB).round(2)
merged_out["totalGB"] = (merged_out["totalStorageSpaceInBytes"] / BYTES_IN_GB).round(2)

merged_users_devices = pd.merge(merged_out,users_df,
                                on="userPrincipalName",
                                how="left",
                                suffixes=("", "_entra"))

# ============================ TAB 1 ============================ #
with tabs[0]:
    st.subheader("🚀 Key Performance Indicators (KPIs)")
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    st.write("---")
    col7, col8 = st.columns([2, 2])
    st.write("---")
    col9, col10 = st.columns([2, 2])
    st.write("---")
    col11, col12 = st.columns([2, 2])
    st.write("---")
    col13, col14 = st.columns([2, 2])

    df = merged_users_devices.copy()
    
    total_devices = df["azureADDeviceId"].nunique() if "azureADDeviceId" in df.columns else 0
    col1.metric("📊Total Intune Managed Endpoints", total_devices)
    
    df_windows = df[df["operatingSystem"].str.contains("Windows", case=False, na=False)] if "operatingSystem" in df.columns else pd.DataFrame()
    col2.metric("💻 Total Windows Endpoints", df_windows["azureADDeviceId"].nunique() if "azureADDeviceId" in df_windows.columns else 0)

    with st.expander("Preview: All Merged Windows AAD; Intune and Autopilot"):
        st.write(f"Total Rows: {len(df_windows)}")
        st.dataframe(df_windows.head(100))

    if not df_windows.empty:
        if "complianceState" in df_windows.columns:
            comp_count = df_windows["complianceState"].value_counts().get("compliant", 0)
            col3.metric("✅ Compliance Rate", f"{(comp_count / len(df_windows) * 100):.2f}%")
        
        if "isEncrypted" in df_windows.columns:
            enc_count = df_windows["isEncrypted"].value_counts().get(True, 0)
            col4.metric("🔒 Encrypted Devices", f"{(enc_count / len(df_windows) * 100):.2f}%")
        
        if "userPrincipalName" in df_windows.columns:
            users_count = df_windows["userPrincipalName"].nunique()
            col5.metric("🧑‍💻 Devices with Primary User", f"{(users_count / len(df_windows) * 100):.2f}%")

        if "lastSyncDateTime" in df_windows.columns:
            df_windows["lastSyncDateTime"] = pd.to_datetime(df_windows["lastSyncDateTime"], errors="coerce", utc=True)
            now_utc = pd.Timestamp.now(tz="UTC")
            df_windows["HoursSinceCheckin"] = (now_utc - df_windows["lastSyncDateTime"]).dt.total_seconds() / 3600
            active_count = df_windows[df_windows["HoursSinceCheckin"] <= 48].shape[0]
            col6.metric("✅ Devices Checked In Past 48 Hours", f"{(active_count / len(df_windows) * 100):.2f}%")

    # with col7:
    #     st.metric("🖥️✅ Total Autopilot Devices", autopilot_df["serialNumber"].nunique() if not autopilot_df.empty and "serialNumber" in autopilot_df.columns else 0)

    # with col8:
    #     enrolled_count = 0
    #     if not autopilot_df.empty and "enrollmentState" in autopilot_df.columns:
    #         enrolled_count = autopilot_df[autopilot_df["enrollmentState"].astype(str).str.lower() == "enrolled"].shape[0]
    #     st.metric("🖥️🛡️ Total Enrolled Autopilot Devices", enrolled_count)

   # --- Autopilot KPIs (FIXED) ---
    with col7:
        if not autopilot_df.empty and "serialNumber" in autopilot_df.columns:
            total_autopilot = autopilot_df["serialNumber"].nunique()
        else:
            total_autopilot = 0
        st.metric("🖥️✅ Total Autopilot Devices", f"{total_autopilot}")

    with col8:
        if not autopilot_df.empty and "enrollmentState" in autopilot_df.columns:
            # Note: The specific value for "enrolled" might vary (e.g. 'enrolled', 'ready', etc.)
            # Adjust 'enrolled' below based on your actual data values.
            enrolled_states = autopilot_df[autopilot_df["enrollmentState"].astype(str).str.lower() == "enrolled"].shape[0]
        else:
            enrolled_states = 0
        st.metric("🖥️🛡️ Total Enrolled Autopilot Devices", f"{enrolled_states}")

    with col9:
        st.write("📊 Autopilot Devices Count By Group Tag")
        if not autopilot_df.empty and "groupTag" in autopilot_df.columns:
            group_tag_counts = (
                autopilot_df["groupTag"]
                # .fillna("NotAssigned")
                .astype(str).str.strip()
                .value_counts()
                .reset_index()
            )
            group_tag_counts.columns = ["Group Tag", "Device Count"]
            fig = px.bar(group_tag_counts, x="Group Tag", y="Device Count", text="Device Count", color="Group Tag")
            fig.update_traces(textposition="outside", marker=dict(line=dict(color="white", width=0.5)))
            fig.update_layout(xaxis_title="Group Tag", yaxis_title="Device Count",
                              margin=dict(l=20, r=20, t=50, b=20), height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No Autopilot Group Tag data available.")

    with col11:
        st.write("🏢 Azure AD JoinType Distribution")
        if "trustType" in df_windows.columns and not df_windows.empty:
            join_counts = df_windows["trustType"].value_counts().reset_index()
            join_counts.columns = ["MS Entra Join Type", "Device Count"]
            fig = px.pie(join_counts, names="MS Entra Join Type", values="Device Count", color="MS Entra Join Type", hole=0.25)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No Join Type data available")

    with col12:
        st.write("📊 Autopilot Devices Count By Group Tag")
        if not autopilot_df.empty and "groupTag" in autopilot_df.columns:
            group_tag_counts = autopilot_df["groupTag"].astype(str).str.strip().value_counts().reset_index()
            group_tag_counts.columns = ["Group Tag", "Device Count"]
            fig = px.bar(group_tag_counts, x="Group Tag", y="Device Count", text="Device Count", color="Group Tag")
            fig.update_traces(textposition="outside")
            fig.update_layout(height=500, showlegend=False)
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No Group Tag data available")

    with col13:
        st.write("🏭 Device Distribution by Manufacturer")
        if "manufacturer" in df_windows.columns and not df_windows.empty:
            mfg_counts = df_windows["manufacturer"].value_counts().reset_index()
            mfg_counts.columns = ["Manufacturer", "Count"]
            fig = px.bar(mfg_counts.sort_values("Count", ascending=True), x="Count", y="Manufacturer", orientation="h", text="Count", color="Manufacturer")
            fig.update_layout(height=450)
            st.plotly_chart(fig, use_container_width=True)

    # with col14:
    #     st.write("🔑 Device Enabled Status in Ms Entra")
    #     if "accountEnabled" in df_windows.columns and not df_windows.empty:
    #         acc_counts = df_windows["accountEnabled"].value_counts().reset_index()
    #         acc_counts.columns = ["Status", "Count"]
    #         acc_counts["Status"] = acc_counts["Status"].map({True: "Enabled", False: "Disabled"})
    #         fig = px.pie(acc_counts, names="Status", values="Count", color="Status", color_discrete_map={"Enabled": "yellow", "Disabled": "red"}, hole=0.25)
    #         st.plotly_chart(fig, use_container_width=True)

    with col14:
        st.write("🔑 Device Status in Ms Entra ID")
        if "accountEnabled" in df_windows.columns:
            account_status_counts = (
                df_windows.groupby("accountEnabled").size().reset_index(name="Device Count").sort_values(by="Device Count", ascending=False)
            )
            account_status_counts["accountEnabled"] = account_status_counts["accountEnabled"].map({True: "Enabled", False: "Disabled"})
            fig = px.pie(account_status_counts, names="accountEnabled", values="Device Count",
                         color="accountEnabled", color_discrete_map={"Enabled": "yellow", "Disabled": "red"}, hole=0.25)
            fig.update_traces(textinfo="label+percent", pull=[0.02]*len(account_status_counts),
                              marker=dict(line=dict(color="white", width=2)))
            fig.update_layout(margin=dict(l=10, r=10, t=40, b=20), height=350)
            st.plotly_chart(fig, use_container_width=True)
# ============================ TAB 2 & 3 ============================ #
# (Standard logic for Security Updates and Release Info)
with tabs[1]:
    if not df_windows.empty and not merged_win11_df.empty:
       
        if "osVersion" in df_windows.columns:
            # intune_df["Existing OS Build"] = pd.to_numeric(intune_df["osVersion"].astype(str).str.split("10.0.", expand=True)[1], errors="coerce")
            df_windows['osVersion'] = df_windows['osVersion'].astype(str)
            df_windows["Existing OS Build"] = pd.to_numeric(df_windows["osVersion"].astype(str).str.split("10.0.", expand=True)[1], errors="coerce")
        if "Build" in merged_win11_df.columns:
            merged_win11_df["Build"] = pd.to_numeric(merged_win11_df["Build"], errors="coerce")
        merged_sec = df_windows.merge(merged_win11_df, left_on="Existing OS Build", right_on="Build", how="left")
        
        # ... (Metrics rendering) ...
        st.subheader("Windows Security Updates Status")
        c1, c2 = st.columns(2)
        with c1:
            if "Update Status" not in merged_sec.columns:
                latest = merged_win11_df["Build"].max()
                merged_sec["Update Status"] = merged_sec["Existing OS Build"].apply(lambda x: "Latest" if x == latest else "NotLatest")
            
            # Unique device count per status
            status_counts = (
                merged_sec.groupby("Update Status")["azureADDeviceId"]
                .nunique()
                .reset_index(name="Count")
                .rename(columns={"Update Status": "Status"})
            )

            fig = px.pie(status_counts, names="Status", values="Count", hole=0.25)
            st.plotly_chart(fig, use_container_width=True)

        with c2:
            if "osVersion" in df_windows.columns:
                ver_counts = df_windows["osVersion"].value_counts().reset_index()
                ver_counts.columns = ["Version", "Count"]
                fig = px.bar(ver_counts, x="Version", y="Count", color="Version")
                st.plotly_chart(fig, use_container_width=True)

        st.write("---")
        c3, c4 = st.columns(2)
        today = dt.datetime.now()
        merged_sec['lastSyncDateTime'] = pd.to_datetime(merged_sec['lastSyncDateTime'],errors='coerce', utc=True)
        now_utc = pd.Timestamp.now(tz="UTC").normalize()
        merged_sec['Days Since Last Sync'] = (now_utc - merged_sec['lastSyncDateTime']).dt.days
        merged_sec['Availability date'] = pd.to_datetime(merged_sec['Availability date'], errors='coerce')
        merged_sec['Days Since Update Release'] = (today - merged_sec['Availability date']).dt.days
        merged_sec["Days Since Update Release"] = pd.to_numeric(merged_sec["Days Since Update Release"], errors="coerce")

        def categorize_age(days):
            days = pd.to_numeric(days, errors="coerce")

            if pd.isna(days):
                return "DataIsNotAvailable"
            if days <= 45:
                return '≤45 days'
            elif days <= 90:
                return '≤90 days'
            elif days <= 180:
                return '≤180 days'
            elif days <= 365:
                return '≤365 days'
            else:
                return '>365 days'

        # merged_sec['Days Since Update Release'] = merged_sec['Days Since Update Release'].apply(categorize_age)
        merged_sec['Update Age Category'] = merged_sec['Days Since Update Release'].apply(categorize_age)
        latest_build = merged_win11_df['Build'].max()
        merged_sec['Update Status'] = merged_sec['Existing OS Build'].apply(lambda x: 'Latest' if x == latest_build else 'NotLatest')
        Not_Latest_Updates_Df = merged_sec[merged_sec['Update Status'] == "NotLatest"]
        Latest_Updates_Df = merged_sec[merged_sec['Update Status'] == "Latest"]
        with c3:
            # Normalize numeric field and compute Action Required per row
            merged_sec["Days Since Update Release"] = pd.to_numeric(
                merged_sec["Days Since Update Release"], errors="coerce"
            )
            merged_sec["Action Required"] = merged_sec.apply(
                lambda row: "Yes"
                if (
                    (pd.isna(row["Days Since Update Release"]) or row["Days Since Update Release"] > 90)
                    and row.get("Update Status", None) == "NotLatest"
                )
                else "No",
                axis=1
            )
            st.subheader("🚦Action Required Summary")
            # Option A: Count unique devices per status directly
            action_counts = (
                merged_sec.groupby("Action Required")["azureADDeviceId"]
                .nunique(dropna=True)
                .reset_index(name="Count")
            )
            colors = {"Yes": "#ff4d4d", "No": "#2eb82e"}
            fig = px.pie(
                action_counts,
                names="Action Required",
                values="Count",
                hole=0.25,
                color="Action Required",
                color_discrete_map=colors
            )
            fig.update_traces(
                textinfo="label+percent",
                textfont_size=16,
                pull=[0.02] * len(action_counts),
                marker=dict(line=dict(color="white", width=2))
            )
            fig.update_layout(height=350, margin=dict(l=10, r=10, t=40, b=20), showlegend=True)
            st.plotly_chart(fig, use_container_width=True)
            EXPORT_COLUMNS = [
                                "id_intune","deviceName","azureADDeviceId","operatingSystem","osVersion","enrolledDateTime","isEncrypted",
                                "lastSyncDateTime","userPrincipalName","complianceState","deviceId","trustType","accountEnabled","displayName",
                                "id_aad","freeGB","totalGB",
                                "HoursSinceCheckin","Existing OS Build","Update Status","Days Since Last Sync","Days Since Update Release",
                                "Update Age Category","Action Required"
                            ]
            yes_df = merged_sec[merged_sec["Action Required"] == "Yes"]
            no_df  = merged_sec[merged_sec["Action Required"] == "No"]

            # Keep only approved columns that exist
            yes_df = yes_df.loc[:, yes_df.columns.intersection(EXPORT_COLUMNS)]
            no_df  = no_df.loc[:, no_df.columns.intersection(EXPORT_COLUMNS)]

            # st.divider()
            st.subheader("⬇️ Download Device Lists")

            col1, col2 = st.columns(2)
            with col1:
                st.download_button(
                    label="⬇️Action Required = YES",
                    data=yes_df.to_csv(index=False),
                    file_name="Devices_Action_Required_Yes.csv",
                    mime="text/csv"
                )
            with col2:
                st.download_button(
                    label="⬇️Action Required = NO",
                    data=no_df.to_csv(index=False),
                    file_name="Devices_Action_Required_No.csv",
                    mime="text/csv"
                )

        # st.markdown("---")
        # with st.expander("Dataframe showing on Devices that needs Attention:"):
        #     st.write(yes_df["id_intune"].nunique())
        #     st.write("Columns:", yes_df.columns.tolist())
        #     st.dataframe(yes_df)

        # with st.expander("Preview: Latest:All Windows Security Updates"):
        #     st.write(f"Total Rows: {len(merged_sec)}")
        #     st.write("Unique values per column:")
        #     st.write(merged_sec.nunique())   # counts unique entries per column
        #     st.markdown("---")
        #     # status_counts = merged_sec["azureADDeviceId"].value_counts()
        #     status_counts = merged_sec["azureADDeviceId"].nunique()
        #     st.write(status_counts)
        #     st.dataframe(merged_sec[merged_sec["Action Required"] == "Yes"])
        #     st.write("Columns:", merged_sec.columns.tolist())
        # st.markdown("---")

        with c4:
            st.subheader("📈 **Devices with Low Disk space (<=5 GB)** ")
            merged_sec["freeGB"] = pd.to_numeric(
                     merged_sec["freeGB"], errors="coerce"
                )
            mask =  merged_sec["freeGB"].le(5)
            devices_count_lessthan_5gb = int(mask.sum())
            st.metric("Device Count",devices_count_lessthan_5gb)
            st.markdown("---")
            with st.expander("Dataframe showing Devices that has free disk space less than 5 GB:"):
                st.dataframe(merged_sec[merged_sec["freeGB"] <= 5])
                st.write("Columns:",merged_sec.columns.tolist())

        st.markdown("---")
        st.markdown("### 📊 **Emergency / Critical / OOB Update Release Trend**")
        merged_win11_df["Availability date"] = pd.to_datetime(
        merged_win11_df["Availability date"], errors="coerce"
    )
        tmp = merged_win11_df.dropna(subset=["Availability date"]).copy()
        if tmp.empty:
            st.info("⚠️ No valid Availability date values to plot.")
        else:
            tmp["Year"] = tmp["Availability date"].dt.year
            tmp["MonthName"] = tmp["Availability date"].dt.strftime("%b")  # Jan, Feb, etc.
            available_years = sorted(tmp["Year"].unique())
            selected_year = st.selectbox("Select Year", available_years)
            tmp_filtered = tmp[(tmp["Year"] == selected_year) & (tmp["Update type"].str.contains("OOB", case=False))]
            if tmp_filtered.empty:
                st.warning(f"No OOB updates found for {selected_year}.")
            else:
                oob_trend = (
                    tmp_filtered.groupby("MonthName")
                    .size()
                    .reset_index(name="OOB Updates")
                )
                month_order = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
                oob_trend["MonthName"] = pd.Categorical(oob_trend["MonthName"], categories=month_order, ordered=True)
                oob_trend = oob_trend.sort_values("MonthName")
                fig = px.line(
                    oob_trend,
                    x="MonthName",
                    y="OOB Updates",
                    markers=True,
                    labels={"MonthName": "Month", "OOB Updates": "Number of OOB Updates"},
                    color_discrete_sequence=["#82AA87"],  # Orange-red for emphasis
                )
                fig.update_traces(mode="lines+markers", line=dict(width=3), marker=dict(size=8))
                fig.update_layout(
                    xaxis=dict(title="Month"),
                    yaxis=dict(title="OOB Updates"),
                    margin=dict(l=30, r=20, t=60, b=80),
                    height=400,
                    plot_bgcolor="#0E1117",  # Dark theme background
                    paper_bgcolor="#0E1117",
                    font=dict(color="white", size=14),
                )
                st.plotly_chart(fig, use_container_width=True)
    else:
        st.warning("Waiting for data to populate Windows Security Updates charts...")

with tabs[2]:
    # st.header("Windows 11 Release Info")
    # for idx, df in enumerate(win_tables, 1):
    #     st.subheader(f"Table {idx}")
    #     st.dataframe(df, use_container_width=True)
    st.header("🪟 Windows 11 Security Updates Release Info (Live Data)")
    URL = "https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information"
    HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    TIMEOUT = 60
    try:
        response = requests.get(URL, headers=HEADERS)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        tables = soup.find_all('table')
        dfs = []
        titles = []
        for each_table in tables:
            title_tag = each_table.find_previous('strong')
            title_text = title_tag.get_text(strip=True) if title_tag else "Windows 11 Release Information"
            status_text = ""
            if title_tag and title_tag.next_sibling:
                status_text = title_tag.next_sibling.strip(' "\n')
            full_title = f"{title_text} {status_text}" if status_text else title_text
            titles.append(full_title)
            first_tr = each_table.find('tr')
            ths = first_tr.find_all('th') if first_tr else []
            if ths:
                headers = [th.get_text(strip=True) for th in ths]
            else:
                tds = first_tr.find_all('td') if first_tr else []
                headers = [f"Column {i+1}" for i in range(len(tds))]
            rows = []
            for tr in each_table.find_all('tr')[1:]:
                cells = [td.get_text(strip=True) for td in tr.find_all('td')]
                if not cells:
                    continue
                if len(cells) < len(headers):
                    cells.extend([""] * (len(headers) - len(cells)))
                elif len(cells) > len(headers):
                    cells = cells[:len(headers)]
                rows.append(cells)
            df = pd.DataFrame(rows, columns=headers)
            dfs.append(df)
        combined_df_list = []
        for idx, df in enumerate(dfs, start=1):
            st.subheader(f"{idx}. {titles[idx-1]}")
            st.dataframe(df, use_container_width=True)
            df_copy = df.copy()
            df_copy["Source_Table"] = titles[idx-1]
            combined_df_list.append(df_copy)
            st.markdown("---")
        st.divider()
    except Exception as e:
        st.error(f"❌ Failed to fetch Windows 11 release information: {e}")