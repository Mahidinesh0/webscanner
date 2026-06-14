import logging
from database.models import (
    blacklist_ip as db_blacklist,
    is_blacklisted as db_is_blacklisted,
    get_blacklist as db_get_blacklist,
    remove_from_blacklist as db_remove,
)

logger = logging.getLogger(__name__)


def block_ip(ip_address: str, attack_type: str, reason: str, permanent: bool = False):
    """Add an IP to the blacklist."""
    db_blacklist(ip_address, attack_type, reason, permanent)
    logger.warning(f"[BLACKLIST] Blocked {ip_address} | type={attack_type} | permanent={permanent}")


def is_blocked(ip_address: str) -> bool:
    """Return True if the IP is currently blacklisted."""
    return db_is_blacklisted(ip_address)


def unblock_ip(ip_address: str):
    """Remove an IP from the blacklist."""
    db_remove(ip_address)
    logger.info(f"[BLACKLIST] Unblocked {ip_address}")


def get_all_blocked() -> list:
    """Return all blacklisted IPs."""
    return db_get_blacklist()
