import logging
from pathlib import Path

from src.utils.config import Config


Config.LOG_DIR.mkdir(
    parents=True,
    exist_ok=True
)

LOG_FILE = Config.LOG_DIR / "dnsentinel.log"


logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)


logger = logging.getLogger("DNSentinel")


