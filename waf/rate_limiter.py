import time
import threading
import logging
from collections import defaultdict, deque
from database.models import blacklist_ip

logger = logging.getLogger(__name__)

# Config
REQUESTS_PER_MINUTE = 60
BURST_LIMIT = 20          # max requests in 10-second window
BURST_WINDOW = 10         # seconds
AUTO_BLACKLIST_THRESHOLD = 5  # blocks before permanent blacklist


class RateLimiter:
    def __init__(self,
                 rpm=REQUESTS_PER_MINUTE,
                 burst_limit=BURST_LIMIT,
                 burst_window=BURST_WINDOW):
        self.rpm = rpm
        self.burst_limit = burst_limit
        self.burst_window = burst_window
        self._lock = threading.Lock()
        # ip -> deque of timestamps (last 60s)
        self._minute_windows: dict[str, deque] = defaultdict(deque)
        # ip -> deque of timestamps (last burst_window seconds)
        self._burst_windows: dict[str, deque] = defaultdict(deque)
        # ip -> consecutive block count
        self._block_counts: dict[str, int] = defaultdict(int)

    def check(self, ip: str) -> tuple[bool, str]:
        """
        Returns (allowed: bool, reason: str).
        reason is empty string when allowed.
        """
        now = time.time()

        with self._lock:
            # Clean stale minute window
            minute_q = self._minute_windows[ip]
            while minute_q and minute_q[0] < now - 60:
                minute_q.popleft()
            minute_q.append(now)

            # Clean stale burst window
            burst_q = self._burst_windows[ip]
            while burst_q and burst_q[0] < now - self.burst_window:
                burst_q.popleft()
            burst_q.append(now)

            # Burst check
            if len(burst_q) > self.burst_limit:
                self._block_counts[ip] += 1
                self._maybe_blacklist(ip)
                reason = (f"Burst limit exceeded: {len(burst_q)} requests "
                          f"in {self.burst_window}s (limit {self.burst_limit})")
                logger.warning(f"[RATE] BURST block {ip}: {reason}")
                return False, reason

            # Per-minute check
            if len(minute_q) > self.rpm:
                self._block_counts[ip] += 1
                self._maybe_blacklist(ip)
                reason = f"Rate limit exceeded: {len(minute_q)} req/min (limit {self.rpm})"
                logger.warning(f"[RATE] RPM block {ip}: {reason}")
                return False, reason

            return True, ""

    def _maybe_blacklist(self, ip: str):
        if self._block_counts[ip] >= AUTO_BLACKLIST_THRESHOLD:
            logger.error(f"[RATE] Auto-blacklisting {ip} after {self._block_counts[ip]} blocks")
            blacklist_ip(
                ip_address=ip,
                attack_type="Rate Limit Abuse",
                block_reason=f"Auto-blacklisted after {self._block_counts[ip]} rate limit violations",
                permanent=False,
            )

    def reset(self, ip: str):
        with self._lock:
            self._minute_windows.pop(ip, None)
            self._burst_windows.pop(ip, None)
            self._block_counts.pop(ip, None)


# Module-level singleton
_limiter = RateLimiter()


def check_rate_limit(ip: str) -> tuple[bool, str]:
    return _limiter.check(ip)


def reset_rate_limit(ip: str):
    _limiter.reset(ip)
