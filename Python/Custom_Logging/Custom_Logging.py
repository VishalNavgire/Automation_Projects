import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from tzlocal import get_localzone
import os

def get_script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

# ------------------------------ Logging --------------------------------------
def setup_logger():
    log_dir = os.path.join(get_script_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("Custom_Logging")
    if not logger.handlers:
        logger.setLevel(logging.DEBUG)
        handler = RotatingFileHandler(
            os.path.join(log_dir, "Custom_Logging.log"),
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