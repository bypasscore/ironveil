"""
IronVeil Platform API Probing

Discovers and tests platform API endpoints for security weaknesses
including: endpoint enumeration, rate limit testing, authentication
bypass probing, parameter tampering, and response analysis.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

logger = logging.getLogger("ironveil.platform.api_probe")


class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class RiskLevel(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Endpoint:
    """Represents a discovered API endpoint."""
    url: str
    method: HttpMethod = HttpMethod.GET
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    content_type: Optional[str] = None
    requires_auth: bool = False
    parameters: List[str] = field(default_factory=list)
    discovered_via: str = "enumeration"

    @property
    def path(self) -> str:
        return urlparse(self.url).path


@dataclass
class Finding:
    """A security finding from API probing."""
    title: str
    description: str
    risk: RiskLevel
    endpoint: Optional[str] = None
    evidence: Optional[str] = None
    remediation: str = ""
    cwe_id: Optional[str] = None


# Common API path patterns for iGaming platforms
_COMMON_PATHS: List[str] = [
    "/api/v1/user/profile",
    "/api/v1/user/balance",
    "/api/v1/user/transactions",
    "/api/v1/user/session",
    "/api/v1/auth/login",
    "/api/v1/auth/register",
    "/api/v1/auth/refresh",
    "/api/v1/auth/forgot-password",
    "/api/v1/games/list",
    "/api/v1/games/session",
    "/api/v1/games/history",
    "/api/v1/games/rng-seed",
    "/api/v1/payments/deposit",
    "/api/v1/payments/withdraw",
    "/api/v1/payments/methods",
    "/api/v1/bonus/list",
    "/api/v1/bonus/claim",
    "/api/v2/user/profile",
    "/api/v2/games/list",
    "/api/internal/admin",
    "/api/internal/config",
    "/api/debug",
    "/api/health",
    "/api/status",
    "/graphql",
    "/api/graphql",
    "/ws/game",
    "/socket.io/",
]

_AUTH_BYPASS_HEADERS: List[Dict[str, str]] = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Original-URL": "/api/internal/admin"},
    {"X-Rewrite-URL": "/api/internal/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
]


class EndpointDiscovery:
    """Discovers API endpoints on a target platform."""

    def __init__(
        self,
        base_url: str,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.session = session or requests.Session()
        self.timeout = timeout
        self._discovered: List[Endpoint] = []

    def enumerate_common_paths(self) -> List[Endpoint]:
        """Try common API paths and record which ones respond."""
        logger.info("Enumerating common API paths on %s", self.base_url)
        for path in _COMMON_PATHS:
            url = urljoin(self.base_url, path)
            try:
                start = time.monotonic()
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                elapsed = (time.monotonic() - start) * 1000

                if resp.status_code not in (404, 502, 503):
                    ep = Endpoint(
                        url=url,
                        method=HttpMethod.GET,
                        status_code=resp.status_code,
                        response_time_ms=round(elapsed, 1),
                        content_type=resp.headers.get("Content-Type"),
                        requires_auth=resp.status_code in (401, 403),
                        discovered_via="common_path_enum",
                    )
                    self._discovered.append(ep)
                    logger.debug("Found: %s [%d] (%.1fms)", path, resp.status_code, elapsed)
            except requests.RequestException as exc:
                logger.debug("Failed: %s — %s", path, exc)

        logger.info("Discovered %d endpoints via path enumeration", len(self._discovered))
        return list(self._discovered)

    def discover_from_js(self, js_source: str) -> List[str]:
        """Extract API paths from JavaScript source code."""
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'endpoint:\s*["\']([^"\']+)["\']',
        ]
        found: set = set()
        for pattern in patterns:
            matches = re.findall(pattern, js_source)
            for m in matches:
                if m.startswith("/") or m.startswith("http"):
                    found.add(m)

        logger.info("Extracted %d unique API paths from JS", len(found))
        return sorted(found)

    @property
    def endpoints(self) -> List[Endpoint]:
        return list(self._discovered)


class RateLimitTester:
    """Tests API endpoint rate limiting."""

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout

    def test_rate_limit(
        self,
        url: str,
        num_requests: int = 100,
        method: str = "GET",
    ) -> Dict[str, Any]:
        """Send rapid requests and detect rate limiting behavior."""
        logger.info("Testing rate limits on %s (%d requests)", url, num_requests)

        status_codes: List[int] = []
        response_times: List[float] = []
        rate_limited_at: Optional[int] = None

        for i in range(num_requests):
            try:
                start = time.monotonic()
                if method == "GET":
                    resp = self.session.get(url, timeout=self.timeout)
                else:
                    resp = self.session.post(url, timeout=self.timeout, json={})
                elapsed = (time.monotonic() - start) * 1000

                status_codes.append(resp.status_code)
                response_times.append(elapsed)

                if resp.status_code == 429 and rate_limited_at is None:
                    rate_limited_at = i + 1
                    retry_after = resp.headers.get("Retry-After")
                    logger.info("Rate limited at request %d (Retry-After: %s)",
                               i + 1, retry_after)

            except requests.RequestException:
                status_codes.append(0)
                response_times.append(0)

        unique_codes = set(status_codes)
        has_rate_limit = 429 in unique_codes

        return {
            "url": url,
            "total_requests": num_requests,
            "has_rate_limit": has_rate_limit,
            "rate_limited_at_request": rate_limited_at,
            "status_code_distribution": {
                str(code): status_codes.count(code) for code in unique_codes
            },
            "avg_response_time_ms": round(
                sum(response_times) / len(response_times), 1
            ) if response_times else 0,
            "risk": RiskLevel.HIGH.value if not has_rate_limit else RiskLevel.LOW.value,
        }


class AuthBypassTester:
    """Tests for authentication bypass vulnerabilities."""

    def __init__(
        self,
        session: Optional[requests.Session] = None,
        timeout: int = 10,
    ) -> None:
        self.session = session or requests.Session()
        self.timeout = timeout

    def test_header_bypass(self, url: str) -> List[Finding]:
        """Test common header-based auth bypass techniques."""
        findings: List[Finding] = []
        baseline = self._get_status(url, {})

        for headers in _AUTH_BYPASS_HEADERS:
            status = self._get_status(url, headers)
            if baseline in (401, 403) and status == 200:
                header_name = list(headers.keys())[0]
                findings.append(Finding(
                    title=f"Auth bypass via {header_name}",
                    description=(
                        f"Endpoint {url} returns 200 with header "
                        f"{header_name}: {headers[header_name]} "
                        f"while normally returning {baseline}"
                    ),
                    risk=RiskLevel.CRITICAL,
                    endpoint=url,
                    evidence=f"Baseline: {baseline}, With header: {status}",
                    remediation="Ensure authentication is enforced server-side regardless of headers",
                    cwe_id="CWE-287",
                ))

        return findings

    def test_method_override(self, url: str) -> List[Finding]:
        """Test HTTP method override to bypass access controls."""
        findings: List[Finding] = []
        methods = [HttpMethod.POST, HttpMethod.PUT, HttpMethod.PATCH, HttpMethod.DELETE]

        baseline_get = self._get_status(url, {})
        if baseline_get not in (401, 403):
            return findings

        for method in methods:
            try:
                resp = self.session.request(
                    method.value, url, timeout=self.timeout
                )
                if resp.status_code == 200:
                    findings.append(Finding(
                        title=f"Access control bypass via {method.value}",
                        description=f"Endpoint {url} accessible via {method.value} but blocks GET",
                        risk=RiskLevel.HIGH,
                        endpoint=url,
                        evidence=f"GET: {baseline_get}, {method.value}: {resp.status_code}",
                        remediation="Apply consistent access controls across all HTTP methods",
                        cwe_id="CWE-285",
                    ))
            except requests.RequestException:
                pass

        return findings

    def _get_status(self, url: str, extra_headers: Dict[str, str]) -> int:
        try:
            resp = self.session.get(url, headers=extra_headers, timeout=self.timeout)
            return resp.status_code
        except requests.RequestException:
            return 0


class ApiProber:
    """Orchestrates all API probing operations."""

    def __init__(self, base_url: str, timeout: int = 10) -> None:
        self.base_url = base_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
            "Accept": "application/json",
        })
        self.discovery = EndpointDiscovery(base_url, self.session, timeout)
        self.rate_limiter = RateLimitTester(self.session, timeout)
        self.auth_bypass = AuthBypassTester(self.session, timeout)
        self._findings: List[Finding] = []

    def run_full_probe(self, rate_limit_requests: int = 100) -> Dict[str, Any]:
        """Run a complete API security probe."""
        endpoints = self.discovery.enumerate_common_paths()
        rate_limit_results = []
        auth_findings: List[Finding] = []

        for ep in endpoints[:10]:  # Limit to top 10
            if not ep.requires_auth:
                rl = self.rate_limiter.test_rate_limit(ep.url, rate_limit_requests)
                rate_limit_results.append(rl)
                if not rl["has_rate_limit"]:
                    self._findings.append(Finding(
                        title=f"No rate limiting on {ep.path}",
                        description=f"Endpoint {ep.url} has no rate limiting after {rate_limit_requests} requests",
                        risk=RiskLevel.HIGH,
                        endpoint=ep.url,
                        remediation="Implement rate limiting on all API endpoints",
                    ))

            if ep.requires_auth:
                auth_findings.extend(self.auth_bypass.test_header_bypass(ep.url))
                auth_findings.extend(self.auth_bypass.test_method_override(ep.url))

        self._findings.extend(auth_findings)

        return {
            "base_url": self.base_url,
            "endpoints_discovered": len(endpoints),
            "rate_limit_tests": rate_limit_results,
            "auth_bypass_findings": len(auth_findings),
            "total_findings": len(self._findings),
            "findings": [
                {
                    "title": f.title,
                    "risk": f.risk.value,
                    "endpoint": f.endpoint,
                    "description": f.description,
                }
                for f in self._findings
            ],
        }

    @property
    def findings(self) -> List[Finding]:
        return list(self._findings)
