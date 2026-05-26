import os
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.resource import SubscriptionClient

# --- Configuration ---
RUN_LOCALLY = True

# --- Safely import tzlocal ---
try:
    from tzlocal import get_localzone
except ImportError:
    get_localzone = None

# --- Helpers ---
def str_to_bool(value):
    """Safely convert strings like 'True', 'true', '1' to boolean."""
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "1", "yes")

def get_az_automation_variable(name, default):
    try:
        import automationassets
        return automationassets.get_automation_variable(name)
    except (ImportError, Exception):
        return os.getenv(name, default)

def get_credential():
    if RUN_LOCALLY:
        print("--- Local Mode: Triggering Interactive Browser Login ---")
        return InteractiveBrowserCredential()
    else:
        print("--- Cloud/Service Mode: Using DefaultAzureCredential ---")
        return DefaultAzureCredential()

def setup_logger():
    logger = logging.getLogger("DiskCleanup")
    logger.setLevel(logging.DEBUG)
    
    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(funcName)s | %(message)s | %(filename)s:%(lineno)d",
        datefmt="%a %d %b %Y %I:%M:%S %p %Z"
    )
    
    if get_localzone:
        local_tz = get_localzone()
        fmt.converter = lambda *args: datetime.now(tz=local_tz).timetuple()

    if not logger.handlers:
        is_cloud = os.getenv("AZURE_FUNCTIONS_ENVIRONMENT") or os.getenv("WEBSITE_INSTANCE_ID")
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(fmt)
        logger.addHandler(console_handler)
        
        if not is_cloud:
            log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
            os.makedirs(log_dir, exist_ok=True)
            file_handler = RotatingFileHandler(
                os.path.join(log_dir, "DiskCleanup.log"),
                maxBytes=10 * 1024 * 1024,
                backupCount=5
            )
            file_handler.setFormatter(fmt)
            logger.addHandler(file_handler)
    return logger

LOGGER = setup_logger()

# --- Main Logic ---
def main():
    # Convert variables to correct types
    raw_dry_run = get_az_automation_variable("DiskCleanup_DryRun", True)
    dry_run = str_to_bool(raw_dry_run)
    
    # raw_retention = get_az_automation_variable("DiskCleanup_RetentionDays", 30)
    # retention_days = int(raw_retention)

    LOGGER.info(f"Starting Cleanup. Mode: {'DRY-RUN' if dry_run else 'LIVE'}")

    credential = get_credential()
    sub_client = SubscriptionClient(credential)
    subscriptions = list(sub_client.subscriptions.list())

    total_disks_found = 0
    total_size_gb = 0

    for subscription in subscriptions:
        LOGGER.info(f"Processing subscription: {subscription.display_name}")
        compute_client = ComputeManagementClient(credential, subscription.subscription_id)
        
        try:
            # Note: For very large tenants, consider using .list_all() or pagination
            disks = compute_client.disks.list()
            for disk in disks:
                if disk.disk_state == "Unattached":
                    disk_size = disk.disk_size_gb or 0
                    LOGGER.info(f"Found unattached disk: {disk.name} ({disk_size} GB)")

                    total_disks_found += 1
                    total_size_gb += disk_size

                    if not dry_run:
                        rg_name = disk.id.split('/')[4]
                        LOGGER.warning(f"DELETING disk {disk.name} in {rg_name}")
                        # .result() makes this a blocking (synchronous) call
                        compute_client.disks.begin_delete(rg_name, disk.name).result()
                        LOGGER.info(f"Successfully deleted {disk.name}")
        except Exception as e:
            LOGGER.error(f"Error processing subscription {subscription.display_name}: {e}")

    LOGGER.info(f"Summary: Found {total_disks_found} disks ({total_size_gb} GB). Dry Run: {dry_run}")

if __name__ == "__main__":
    main()