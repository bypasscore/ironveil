"""
IronVeil Proxy Management

SOCKS5 and HTTP proxy rotation, health checking, latency measurement,
and automatic failover for audit sessions.
"""

import logging
import random
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("ironveil.utils.proxy")


class ProxyProtocol(Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


@dataclass
class ProxyInfo:
    """Metadata and health stats for a single proxy."""
    url: str
    protocol: ProxyProtocol
    host: str
    port: int
    username: Optional[str] = None
    password: Optional[str] = None
    latency_ms: Optional[float] = None
    last_check: float = 0.0
    alive: bool = True
    fail_count: int = 0
    success_count: int = 0
    country: Optional[str] = None
    tags: List[str] = field(default_factory=list)

    @property
    def score(self) -> float:
        """Health score: lower is better."""
        lat = self.latency_ms if self.latency_ms else 9999.0
        fail_penalty = self.fail_count * 500
        return lat + fail_penalty


def parse_proxy_url(url: str) -> ProxyInfo:
    """Parse a proxy URL string into a :class:`ProxyInfo`."""
    parsed = urlparse(url)
    protocol_str = (parsed.scheme or "http").lower()
    try:
        protocol = ProxyProtocol(protocol_str)
    except ValueError:
        protocol = ProxyProtocol.HTTP

    host = parsed.hostname or "127.0.0.1"
    port = parsed.port or (1080 if "socks" in protocol_str else 8080)
    return ProxyInfo(
        url=url,
        protocol=protocol,
        host=host,
        port=port,
        username=parsed.username,
        password=parsed.password,
    )


def load_proxy_file(path: str) -> List[ProxyInfo]:
    """Load proxy list from a text file (one URL per line)."""
    resolved = Path(path).resolve()
    if not resolved.exists():
        logger.warning("Proxy file not found: %s", resolved)
        return []

    proxies: List[ProxyInfo] = []
    with open(resolved, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                proxies.append(parse_proxy_url(line))
            except Exception as exc:
                logger.warning("Skipping invalid proxy line %r: %s", line, exc)
    logger.info("Loaded %d proxies from %s", len(proxies), resolved)
    return proxies


class ProxyHealthChecker:
    """Checks proxy liveness and measures latency."""

    DEFAULT_TEST_URL = "https://httpbin.org/ip"
    TIMEOUT = 10

    def __init__(self, test_url: Optional[str] = None, timeout: int = TIMEOUT) -> None:
        self.test_url = test_url or self.DEFAULT_TEST_URL
        self.timeout = timeout

    def check(self, proxy: ProxyInfo) -> bool:
        """Test a proxy, updating its health fields. Returns True if alive."""
        proxy_dict = self._build_proxy_dict(proxy)
        start = time.monotonic()
        try:
            resp = requests.get(
                self.test_url,
                proxies=proxy_dict,
                timeout=self.timeout,
                verify=False,
            )
            elapsed = (time.monotonic() - start) * 1000
            if resp.status_code == 200:
                proxy.alive = True
                proxy.latency_ms = round(elapsed, 1)
                proxy.success_count += 1
                proxy.last_check = time.time()
                logger.debug("Proxy %s alive (%.1f ms)", proxy.url, elapsed)
                return True
        except Exception as exc:
            logger.debug("Proxy %s failed: %s", proxy.url, exc)

        proxy.alive = False
        proxy.fail_count += 1
        proxy.last_check = time.time()
        return False

    def check_tcp(self, proxy: ProxyInfo) -> bool:
        """Quick TCP connect check (no HTTP)."""
        try:
            sock = socket.create_connection((proxy.host, proxy.port), timeout=5)
            sock.close()
            return True
        except OSError:
            return False

    @staticmethod
    def _build_proxy_dict(proxy: ProxyInfo) -> Dict[str, str]:
        url = proxy.url
        if proxy.protocol in (ProxyProtocol.SOCKS4, ProxyProtocol.SOCKS5):
            return {"http": url, "https": url}
        return {"http": url, "https": url}


class ProxyRotator:
    """Manages a pool of proxies with rotation strategies."""

    def __init__(
        self,
        proxies: Optional[List[ProxyInfo]] = None,
        strategy: str = "round_robin",
        health_check_interval: int = 300,
    ) -> None:
        self._proxies: List[ProxyInfo] = proxies or []
        self.strategy = strategy
        self.health_check_interval = health_check_interval
        self._index = 0
        self._checker = ProxyHealthChecker()

    def add(self, proxy: ProxyInfo) -> None:
        self._proxies.append(proxy)

    def remove(self, url: str) -> None:
        self._proxies = [p for p in self._proxies if p.url != url]

    def load_from_file(self, path: str) -> int:
        new_proxies = load_proxy_file(path)
        self._proxies.extend(new_proxies)
        return len(new_proxies)

    def next(self) -> Optional[ProxyInfo]:
        """Return the next proxy according to the configured strategy."""
        alive = [p for p in self._proxies if p.alive]
        if not alive:
            return None

        if self.strategy == "round_robin":
            proxy = alive[self._index % len(alive)]
            self._index += 1
            return proxy
        elif self.strategy == "random":
            return random.choice(alive)
        elif self.strategy == "least_used":
            return min(alive, key=lambda p: p.success_count)
        elif self.strategy == "lowest_latency":
            return min(alive, key=lambda p: p.score)
        else:
            return alive[0]

    def health_check_all(self) -> Dict[str, bool]:
        """Run health checks on all proxies, return {url: alive}."""
        results: Dict[str, bool] = {}
        for proxy in self._proxies:
            results[proxy.url] = self._checker.check(proxy)
        alive_count = sum(1 for v in results.values() if v)
        logger.info("Health check complete: %d/%d alive", alive_count, len(results))
        return results

    def stale_proxies(self) -> List[ProxyInfo]:
        """Return proxies that haven't been checked recently."""
        cutoff = time.time() - self.health_check_interval
        return [p for p in self._proxies if p.last_check < cutoff]

    @property
    def total(self) -> int:
        return len(self._proxies)

    @property
    def alive_count(self) -> int:
        return sum(1 for p in self._proxies if p.alive)

    def summary(self) -> Dict[str, Any]:
        return {
            "total": self.total,
            "alive": self.alive_count,
            "strategy": self.strategy,
            "proxies": [
                {"url": p.url, "alive": p.alive, "latency_ms": p.latency_ms, "fails": p.fail_count}
                for p in self._proxies
            ],
        }
