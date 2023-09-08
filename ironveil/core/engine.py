"""
IronVeil Audit Engine

Orchestrates the full security audit lifecycle: initializes test suites,
manages browser sessions, coordinates detection/evasion modules,
collects findings, and triggers report generation.
"""

import logging
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from ironveil.core.config import Config
from ironveil.core.session import SessionPool, generate_fingerprint
from ironveil.detection.bot_detector import BotDetectionAnalyzer
from ironveil.detection.behavioral import BehavioralAnalyzer
from ironveil.detection.fingerprint import FingerprintAnalyzer
from ironveil.detection.captcha import CaptchaAnalyzer
from ironveil.evasion.human_sim import HumanSimulator
from ironveil.evasion.fingerprint_spoof import FingerprintSpoofer
from ironveil.evasion.timing import TimingEvasion, get_profile
from ironveil.platform.api_probe import ApiProber
from ironveil.platform.integrity import IntegrityChecker
from ironveil.utils.browser import BrowserWrapper, BrowserConfig

logger = logging.getLogger("ironveil.engine")


class AuditPhase(Enum):
    INIT = "initialization"
    RECON = "reconnaissance"
    DETECTION = "detection_analysis"
    EVASION = "evasion_testing"
    PLATFORM = "platform_analysis"
    INTEGRITY = "integrity_checks"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class AuditFinding:
    """A single finding from the audit."""
    phase: AuditPhase
    module: str
    title: str
    description: str
    severity: str  # critical, high, medium, low, info
    data: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    remediation: str = ""


@dataclass
class AuditResult:
    """Complete audit results."""
    audit_id: str
    target_url: str
    started_at: float
    completed_at: float = 0.0
    phase: AuditPhase = AuditPhase.INIT
    findings: List[AuditFinding] = field(default_factory=list)
    phase_results: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None

    @property
    def duration_seconds(self) -> float:
        end = self.completed_at or time.time()
        return end - self.started_at

    @property
    def risk_score(self) -> float:
        weights = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0.5}
        total = sum(weights.get(f.severity, 1) for f in self.findings)
        return min(10.0, round(total / max(len(self.findings), 1), 2))

    @property
    def finding_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


class AuditEngine:
    """Main orchestrator for IronVeil security audits."""

    def __init__(self, config: Optional[Config] = None) -> None:
        self.config = config or Config(auto_discover=True)
        self.audit_id = uuid.uuid4().hex[:12]
        self._result: Optional[AuditResult] = None
        self._browser: Optional[BrowserWrapper] = None
        self._session_pool: Optional[SessionPool] = None
        self._hooks: Dict[str, List[Callable]] = {
            "before_phase": [],
            "after_phase": [],
            "on_finding": [],
            "on_error": [],
        }
        logger.info("AuditEngine initialized (id=%s)", self.audit_id)

    def register_hook(self, event: str, callback: Callable) -> None:
        """Register a callback for audit lifecycle events."""
        if event in self._hooks:
            self._hooks[event].append(callback)

    def _fire_hooks(self, event: str, **kwargs: Any) -> None:
        for cb in self._hooks.get(event, []):
            try:
                cb(**kwargs)
            except Exception as exc:
                logger.warning("Hook %s error: %s", event, exc)

    def run(self, target_url: str) -> AuditResult:
        """Execute a full security audit against the target URL."""
        self._result = AuditResult(
            audit_id=self.audit_id,
            target_url=target_url,
            started_at=time.time(),
        )

        try:
            self._phase_init()
            self._phase_recon(target_url)
            self._phase_detection(target_url)
            self._phase_evasion(target_url)
            self._phase_platform(target_url)
            self._phase_integrity()
            self._set_phase(AuditPhase.COMPLETE)
        except Exception as exc:
            logger.error("Audit failed: %s", exc)
            self._result.error = str(exc)
            self._set_phase(AuditPhase.FAILED)
            self._fire_hooks("on_error", error=exc)
        finally:
            self._cleanup()
            self._result.completed_at = time.time()

        logger.info(
            "Audit %s complete: %d findings, risk_score=%.1f, duration=%.0fs",
            self.audit_id,
            len(self._result.findings),
            self._result.risk_score,
            self._result.duration_seconds,
        )
        return self._result

    def _set_phase(self, phase: AuditPhase) -> None:
        old = self._result.phase if self._result else None
        if self._result:
            self._result.phase = phase
        self._fire_hooks("before_phase", phase=phase)
        logger.info("Audit phase: %s -> %s", old.value if old else "none", phase.value)

    def _add_finding(self, finding: AuditFinding) -> None:
        if self._result:
            self._result.findings.append(finding)
        self._fire_hooks("on_finding", finding=finding)
        logger.info("[%s] %s: %s", finding.severity.upper(), finding.module, finding.title)

    # ------------------------------------------------------------------
    # Phase implementations
    # ------------------------------------------------------------------

    def _phase_init(self) -> None:
        """Initialize browser, session pool, and timing."""
        self._set_phase(AuditPhase.INIT)

        # Validate config
        warnings = self.config.validate()
        for w in warnings:
            logger.warning("Config warning: %s", w)

        # Session pool
        proxy_file = self.config.get("session.proxy_list_file")
        proxies: List[str] = []
        if proxy_file:
            from ironveil.utils.proxy import load_proxy_file
            proxy_infos = load_proxy_file(proxy_file)
            proxies = [p.url for p in proxy_infos]

        self._session_pool = SessionPool(
            max_sessions=self.config.get("session.max_concurrent_sessions", 5),
            proxies=proxies,
            session_timeout=self.config.get("session.session_timeout", 300),
        )

        # Browser
        browser_cfg = BrowserConfig(
            headless=self.config.get("browser.headless", True),
            viewport=(
                self.config.get("browser.viewport_width", 1920),
                self.config.get("browser.viewport_height", 1080),
            ),
            user_agent=self.config.get("browser.user_agent"),
        )
        self._browser = BrowserWrapper(browser_cfg)
        self._browser.launch()

    def _phase_recon(self, target_url: str) -> None:
        """Reconnaissance: load target, gather initial data."""
        self._set_phase(AuditPhase.RECON)
        self._browser.navigate(target_url, wait=2.0)

        title = self._browser.title()
        source_len = len(self._browser.page_source())
        cookies = self._browser.get_cookies()

        self._result.phase_results["recon"] = {
            "title": title,
            "source_length": source_len,
            "cookies_count": len(cookies),
            "url": self._browser.current_url(),
        }

    def _phase_detection(self, target_url: str) -> None:
        """Test platform's detection capabilities."""
        self._set_phase(AuditPhase.DETECTION)
        results: Dict[str, Any] = {}

        if self.config.get("detection.bot_detection_tests"):
            bot_analyzer = BotDetectionAnalyzer(self._browser)
            bot_results = bot_analyzer.run_all_checks()
            results["bot_detection"] = bot_analyzer.summary()

            for r in bot_results:
                if r.detected:
                    self._add_finding(AuditFinding(
                        phase=AuditPhase.DETECTION,
                        module="bot_detector",
                        title=f"Bot detection vector: {r.vector.value}",
                        description=r.details,
                        severity="high" if r.confidence >= 0.7 else "medium",
                        data={"vector": r.vector.value, "confidence": r.confidence},
                    ))

        if self.config.get("detection.behavioral_analysis"):
            behavioral = BehavioralAnalyzer(self._browser)
            behavioral.inject_collectors()
            time.sleep(3)  # Let collectors gather data
            behavioral.collect_events()
            results["behavioral"] = behavioral.full_analysis()

        if self.config.get("detection.fingerprint_analysis"):
            fp_analyzer = FingerprintAnalyzer(self._browser)
            fp_analyzer.collect_all()
            results["fingerprint"] = fp_analyzer.summary()

        if self.config.get("detection.captcha_analysis"):
            captcha = CaptchaAnalyzer(self._browser)
            captcha.scan_page()
            results["captcha"] = captcha.summary()

            for det in captcha.detections:
                if det.captcha_type.value != "none":
                    self._add_finding(AuditFinding(
                        phase=AuditPhase.DETECTION,
                        module="captcha",
                        title=f"CAPTCHA detected: {det.captcha_type.value}",
                        description=f"Bypass difficulty: {det.bypass_difficulty}/10",
                        severity="info",
                        data={"type": det.captcha_type.value, "difficulty": det.bypass_difficulty},
                    ))

        self._result.phase_results["detection"] = results

    def _phase_evasion(self, target_url: str) -> None:
        """Test evasion techniques against the platform."""
        self._set_phase(AuditPhase.EVASION)
        results: Dict[str, Any] = {}

        if self.config.get("evasion.fingerprint_spoofing"):
            spoofer = FingerprintSpoofer(self._browser)
            spoofer.apply_all()
            verification = spoofer.verify()
            results["fingerprint_spoof"] = {
                "profile": spoofer.summary(),
                "verification": verification,
            }

        if self.config.get("evasion.human_simulation"):
            human = HumanSimulator(self._browser)
            human.scroll_page(300)
            results["human_simulation"] = {"status": "executed"}

        self._result.phase_results["evasion"] = results

    def _phase_platform(self, target_url: str) -> None:
        """Platform-level security analysis."""
        self._set_phase(AuditPhase.PLATFORM)
        results: Dict[str, Any] = {}

        if self.config.get("platform.api_probing"):
            prober = ApiProber(target_url)
            probe_results = prober.run_full_probe(
                rate_limit_requests=self.config.get("platform.rate_limit_test_requests", 100),
            )
            results["api_probe"] = probe_results

            for finding in prober.findings:
                self._add_finding(AuditFinding(
                    phase=AuditPhase.PLATFORM,
                    module="api_probe",
                    title=finding.title,
                    description=finding.description,
                    severity=finding.risk.value,
                    data={"endpoint": finding.endpoint},
                    remediation=finding.remediation,
                ))

        self._result.phase_results["platform"] = results

    def _phase_integrity(self) -> None:
        """Run integrity checks if data is available."""
        self._set_phase(AuditPhase.INTEGRITY)
        checker = IntegrityChecker(
            rng_sample_size=self.config.get("platform.rng_sample_size", 10000),
        )
        self._result.phase_results["integrity"] = {"status": "awaiting_data"}

    def _cleanup(self) -> None:
        """Clean up resources."""
        if self._browser:
            self._browser.close()
        self._fire_hooks("after_phase", phase=AuditPhase.COMPLETE)

    @property
    def result(self) -> Optional[AuditResult]:
        return self._result
