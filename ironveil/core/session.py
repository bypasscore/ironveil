"""
IronVeil Session Management

Handles browser fingerprint rotation, proxy rotation, cookie management,
and session lifecycle for audit operations.
"""

import hashlib
import logging
import random
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ironveil.session")


@dataclass
class Fingerprint:
    """Represents a browser fingerprint configuration."""
    user_agent: str
    viewport_width: int
    viewport_height: int
    language: str
    platform: str
    timezone: str
    webgl_vendor: str
    webgl_renderer: str
    canvas_noise_seed: int
    audio_context_noise: float

    def hash(self) -> str:
        raw = f"{self.user_agent}|{self.viewport_width}x{self.viewport_height}|{self.platform}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# Common user agent pool
_USER_AGENTS: List[str] = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

_VIEWPORTS = [
    (1920, 1080), (1366, 768), (1536, 864), (1440, 900),
    (1280, 720), (2560, 1440), (1680, 1050),
]

_LANGUAGES = ["en-US", "en-GB", "de-DE", "fr-FR", "es-ES", "pt-BR", "ja-JP"]
_PLATFORMS = ["Win32", "MacIntel", "Linux x86_64"]
_TIMEZONES = [
    "America/New_York", "America/Los_Angeles", "Europe/London",
    "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney",
]
_WEBGL_VENDORS = ["Google Inc. (NVIDIA)", "Google Inc. (Intel)", "Google Inc. (AMD)"]
_WEBGL_RENDERERS = [
    "ANGLE (NVIDIA GeForce RTX 3060 Direct3D11)",
    "ANGLE (Intel UHD Graphics 630 Direct3D11)",
    "ANGLE (AMD Radeon RX 6700 XT Direct3D11)",
]


def generate_fingerprint() -> Fingerprint:
    """Generate a randomised but realistic browser fingerprint."""
    vp = random.choice(_VIEWPORTS)
    return Fingerprint(
        user_agent=random.choice(_USER_AGENTS),
        viewport_width=vp[0],
        viewport_height=vp[1],
        language=random.choice(_LANGUAGES),
        platform=random.choice(_PLATFORMS),
        timezone=random.choice(_TIMEZONES),
        webgl_vendor=random.choice(_WEBGL_VENDORS),
        webgl_renderer=random.choice(_WEBGL_RENDERERS),
        canvas_noise_seed=random.randint(0, 2**32 - 1),
        audio_context_noise=random.uniform(0.0001, 0.01),
    )


@dataclass
class SessionCookieJar:
    """Simple cookie store for a session."""
    cookies: Dict[str, str] = field(default_factory=dict)

    def set(self, name: str, value: str) -> None:
        self.cookies[name] = value

    def get(self, name: str) -> Optional[str]:
        return self.cookies.get(name)

    def delete(self, name: str) -> None:
        self.cookies.pop(name, None)

    def clear(self) -> None:
        self.cookies.clear()

    def export(self) -> Dict[str, str]:
        return dict(self.cookies)


class Session:
    """Represents a single audit session with its own identity."""

    def __init__(
        self,
        session_id: Optional[str] = None,
        proxy: Optional[str] = None,
        fingerprint: Optional[Fingerprint] = None,
        timeout: int = 300,
    ) -> None:
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self.proxy = proxy
        self.fingerprint = fingerprint or generate_fingerprint()
        self.timeout = timeout
        self.cookies = SessionCookieJar()
        self.created_at = time.time()
        self.last_activity = self.created_at
        self._active = False
        self._request_count = 0
        self._metadata: Dict[str, Any] = {}
        logger.info("Session %s created (fp=%s)", self.session_id, self.fingerprint.hash())

    @property
    def is_active(self) -> bool:
        return self._active

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.last_activity) > self.timeout

    @property
    def age(self) -> float:
        return time.time() - self.created_at

    @property
    def request_count(self) -> int:
        return self._request_count

    def activate(self) -> None:
        self._active = True
        self.last_activity = time.time()
        logger.debug("Session %s activated", self.session_id)

    def deactivate(self) -> None:
        self._active = False
        logger.debug("Session %s deactivated", self.session_id)

    def touch(self) -> None:
        self.last_activity = time.time()
        self._request_count += 1

    def set_meta(self, key: str, value: Any) -> None:
        self._metadata[key] = value

    def get_meta(self, key: str, default: Any = None) -> Any:
        return self._metadata.get(key, default)

    def rotate_fingerprint(self) -> Fingerprint:
        old_hash = self.fingerprint.hash()
        self.fingerprint = generate_fingerprint()
        logger.info("Session %s fingerprint rotated %s -> %s",
                     self.session_id, old_hash, self.fingerprint.hash())
        return self.fingerprint

    def summary(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "proxy": self.proxy,
            "fingerprint_hash": self.fingerprint.hash(),
            "active": self._active,
            "expired": self.is_expired,
            "age_seconds": round(self.age, 1),
            "requests": self._request_count,
        }


class SessionPool:
    """Manages a pool of rotating sessions for parallel auditing."""

    def __init__(
        self,
        max_sessions: int = 5,
        proxies: Optional[List[str]] = None,
        session_timeout: int = 300,
    ) -> None:
        self.max_sessions = max_sessions
        self.proxies = proxies or []
        self.session_timeout = session_timeout
        self._sessions: List[Session] = []
        self._proxy_index = 0

    def _next_proxy(self) -> Optional[str]:
        if not self.proxies:
            return None
        proxy = self.proxies[self._proxy_index % len(self.proxies)]
        self._proxy_index += 1
        return proxy

    def create_session(self) -> Session:
        if len(self._sessions) >= self.max_sessions:
            self._evict_oldest()
        session = Session(
            proxy=self._next_proxy(),
            timeout=self.session_timeout,
        )
        self._sessions.append(session)
        return session

    def get_session(self) -> Session:
        self._cleanup_expired()
        active = [s for s in self._sessions if s.is_active and not s.is_expired]
        if active:
            return random.choice(active)
        return self.create_session()

    def _evict_oldest(self) -> None:
        if self._sessions:
            oldest = min(self._sessions, key=lambda s: s.last_activity)
            oldest.deactivate()
            self._sessions.remove(oldest)
            logger.debug("Evicted session %s", oldest.session_id)

    def _cleanup_expired(self) -> None:
        expired = [s for s in self._sessions if s.is_expired]
        for s in expired:
            s.deactivate()
            self._sessions.remove(s)
            logger.debug("Cleaned up expired session %s", s.session_id)

    @property
    def active_count(self) -> int:
        return sum(1 for s in self._sessions if s.is_active and not s.is_expired)

    @property
    def total_count(self) -> int:
        return len(self._sessions)

    def all_summaries(self) -> List[Dict[str, Any]]:
        return [s.summary() for s in self._sessions]
