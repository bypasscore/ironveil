"""
IronVeil Bot Detection Analysis

Tests a target platform's bot detection capabilities by probing for
common detection vectors: WebDriver flags, automation indicators,
navigator property inconsistencies, and behavioral red flags.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ironveil.detection.bot_detector")


class DetectionVector(Enum):
    """Categories of bot detection techniques."""
    WEBDRIVER_FLAG = "webdriver_flag"
    NAVIGATOR_PROPS = "navigator_properties"
    CHROME_RUNTIME = "chrome_runtime"
    PERMISSIONS_API = "permissions_api"
    PLUGIN_CHECK = "plugin_check"
    LANGUAGE_INCONSISTENCY = "language_inconsistency"
    SCREEN_RESOLUTION = "screen_resolution"
    TIMING_ANALYSIS = "timing_analysis"
    HEADLESS_INDICATOR = "headless_indicator"
    CDP_DETECTION = "cdp_detection"
    IFRAME_SANDBOX = "iframe_sandbox"
    STACK_TRACE = "stack_trace"


@dataclass
class DetectionResult:
    """Result of a single detection vector test."""
    vector: DetectionVector
    detected: bool
    confidence: float  # 0.0 - 1.0
    details: str = ""
    raw_data: Any = None
    timestamp: float = field(default_factory=time.time)

    @property
    def risk_level(self) -> str:
        if self.confidence >= 0.8:
            return "CRITICAL"
        elif self.confidence >= 0.5:
            return "HIGH"
        elif self.confidence >= 0.3:
            return "MEDIUM"
        return "LOW"


# JavaScript snippets used to probe for detection vectors
_JS_CHECKS: Dict[str, str] = {
    "webdriver": "return navigator.webdriver === true",
    "webdriver_undefined": "return navigator.webdriver === undefined",
    "chrome_runtime": "return typeof window.chrome !== 'undefined' && typeof window.chrome.runtime !== 'undefined'",
    "chrome_app": "return typeof window.chrome !== 'undefined' && typeof window.chrome.app !== 'undefined'",
    "permissions_query": """
        try {
            const result = await navigator.permissions.query({name: 'notifications'});
            return result.state;
        } catch(e) { return 'error: ' + e.message; }
    """,
    "plugins_length": "return navigator.plugins.length",
    "languages": "return JSON.stringify(navigator.languages)",
    "platform": "return navigator.platform",
    "hardware_concurrency": "return navigator.hardwareConcurrency",
    "device_memory": "return navigator.deviceMemory || 'undefined'",
    "screen_props": """
        return JSON.stringify({
            width: screen.width, height: screen.height,
            availWidth: screen.availWidth, availHeight: screen.availHeight,
            colorDepth: screen.colorDepth, pixelDepth: screen.pixelDepth
        })
    """,
    "headless_ua": "return /HeadlessChrome/.test(navigator.userAgent)",
    "webgl_vendor": """
        try {
            const c = document.createElement('canvas');
            const gl = c.getContext('webgl');
            const ext = gl.getExtension('WEBGL_debug_renderer_info');
            return gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
        } catch(e) { return 'error'; }
    """,
    "connection_rtt": """
        return navigator.connection ? navigator.connection.rtt : 'unavailable';
    """,
    "cdp_runtime": """
        try {
            const e = new Error();
            if (e.stack && e.stack.includes('Runtime.evaluate')) return true;
            return false;
        } catch(ex) { return false; }
    """,
}


class BotDetectionAnalyzer:
    """Analyze a platform's bot detection capabilities.

    Runs a suite of JavaScript probes through the browser wrapper,
    collects results, and produces a scored assessment of how robust
    the platform's anti-bot measures are.
    """

    def __init__(self, browser: Any) -> None:
        self.browser = browser
        self._results: List[DetectionResult] = []

    def run_all_checks(self) -> List[DetectionResult]:
        """Execute every detection vector test and return results."""
        self._results.clear()

        self._check_webdriver_flag()
        self._check_chrome_runtime()
        self._check_permissions_api()
        self._check_plugins()
        self._check_language_consistency()
        self._check_screen_properties()
        self._check_headless_indicators()
        self._check_cdp_detection()

        logger.info(
            "Bot detection analysis complete: %d vectors tested, %d detected",
            len(self._results),
            sum(1 for r in self._results if r.detected),
        )
        return list(self._results)

    def _check_webdriver_flag(self) -> None:
        """Test if navigator.webdriver is set to true (standard detection)."""
        try:
            is_webdriver = self.browser.execute_js(_JS_CHECKS["webdriver"])
            is_undefined = self.browser.execute_js(_JS_CHECKS["webdriver_undefined"])

            if is_webdriver:
                self._add(DetectionVector.WEBDRIVER_FLAG, True, 0.95,
                          "navigator.webdriver is true — platform will detect automation")
            elif is_undefined:
                self._add(DetectionVector.WEBDRIVER_FLAG, False, 0.1,
                          "navigator.webdriver is undefined — deletion detected by some frameworks")
            else:
                self._add(DetectionVector.WEBDRIVER_FLAG, False, 0.0,
                          "navigator.webdriver is false — appears human-controlled")
        except Exception as exc:
            self._add(DetectionVector.WEBDRIVER_FLAG, False, 0.0,
                      f"Check failed: {exc}")

    def _check_chrome_runtime(self) -> None:
        """Test for chrome.runtime and chrome.app presence."""
        try:
            has_runtime = self.browser.execute_js(_JS_CHECKS["chrome_runtime"])
            has_app = self.browser.execute_js(_JS_CHECKS["chrome_app"])

            if not has_runtime and not has_app:
                self._add(DetectionVector.CHROME_RUNTIME, True, 0.6,
                          "Missing chrome.runtime/app — detectable in real Chrome")
            else:
                self._add(DetectionVector.CHROME_RUNTIME, False, 0.0,
                          "chrome.runtime and chrome.app present")
        except Exception as exc:
            self._add(DetectionVector.CHROME_RUNTIME, False, 0.0, f"Check failed: {exc}")

    def _check_permissions_api(self) -> None:
        """Test permissions API behavior (differs in automated browsers)."""
        try:
            state = self.browser.execute_js(_JS_CHECKS["permissions_query"])
            if state == "prompt":
                self._add(DetectionVector.PERMISSIONS_API, False, 0.1,
                          "Permissions state 'prompt' — normal")
            elif state and "error" in str(state):
                self._add(DetectionVector.PERMISSIONS_API, True, 0.4,
                          f"Permissions API anomaly: {state}")
            else:
                self._add(DetectionVector.PERMISSIONS_API, False, 0.0,
                          f"Permissions state: {state}")
        except Exception as exc:
            self._add(DetectionVector.PERMISSIONS_API, True, 0.3, f"Check exception: {exc}")

    def _check_plugins(self) -> None:
        """Check navigator.plugins length (headless browsers often have 0)."""
        try:
            count = self.browser.execute_js(_JS_CHECKS["plugins_length"])
            if count == 0:
                self._add(DetectionVector.PLUGIN_CHECK, True, 0.7,
                          "navigator.plugins is empty — typical of headless browsers")
            else:
                self._add(DetectionVector.PLUGIN_CHECK, False, 0.0,
                          f"navigator.plugins has {count} entries")
        except Exception as exc:
            self._add(DetectionVector.PLUGIN_CHECK, False, 0.0, f"Check failed: {exc}")

    def _check_language_consistency(self) -> None:
        """Check for inconsistencies between navigator.languages and UA."""
        try:
            languages = self.browser.execute_js(_JS_CHECKS["languages"])
            platform = self.browser.execute_js(_JS_CHECKS["platform"])

            if not languages or languages == "[]":
                self._add(DetectionVector.LANGUAGE_INCONSISTENCY, True, 0.5,
                          "Empty navigator.languages — suspicious")
            else:
                self._add(DetectionVector.LANGUAGE_INCONSISTENCY, False, 0.0,
                          f"Languages: {languages}, Platform: {platform}")
        except Exception as exc:
            self._add(DetectionVector.LANGUAGE_INCONSISTENCY, False, 0.0,
                      f"Check failed: {exc}")

    def _check_screen_properties(self) -> None:
        """Verify screen properties are realistic."""
        try:
            import json
            raw = self.browser.execute_js(_JS_CHECKS["screen_props"])
            props = json.loads(raw) if isinstance(raw, str) else raw

            w, h = props.get("width", 0), props.get("height", 0)
            if w == 0 or h == 0:
                self._add(DetectionVector.SCREEN_RESOLUTION, True, 0.8,
                          "Zero screen dimensions — headless indicator")
            elif w == props.get("availWidth") and h == props.get("availHeight"):
                self._add(DetectionVector.SCREEN_RESOLUTION, True, 0.3,
                          "avail dimensions match screen exactly — possible VM/headless")
            else:
                self._add(DetectionVector.SCREEN_RESOLUTION, False, 0.0,
                          f"Screen {w}x{h} (avail {props.get('availWidth')}x{props.get('availHeight')})")
        except Exception as exc:
            self._add(DetectionVector.SCREEN_RESOLUTION, False, 0.0, f"Check failed: {exc}")

    def _check_headless_indicators(self) -> None:
        """Check for headless Chrome indicators in the UA and WebGL."""
        try:
            ua_headless = self.browser.execute_js(_JS_CHECKS["headless_ua"])
            hw = self.browser.execute_js(_JS_CHECKS["hardware_concurrency"])
            mem = self.browser.execute_js(_JS_CHECKS["device_memory"])

            issues = []
            confidence = 0.0
            if ua_headless:
                issues.append("HeadlessChrome in UA")
                confidence = max(confidence, 0.9)
            if hw and hw <= 1:
                issues.append(f"hardwareConcurrency={hw}")
                confidence = max(confidence, 0.4)
            if mem == "undefined":
                issues.append("deviceMemory undefined")
                confidence = max(confidence, 0.2)

            detected = len(issues) > 0
            self._add(DetectionVector.HEADLESS_INDICATOR, detected, confidence,
                      "; ".join(issues) if issues else "No headless indicators found")
        except Exception as exc:
            self._add(DetectionVector.HEADLESS_INDICATOR, False, 0.0, f"Check failed: {exc}")

    def _check_cdp_detection(self) -> None:
        """Test if Chrome DevTools Protocol usage is detectable."""
        try:
            cdp_leaked = self.browser.execute_js(_JS_CHECKS["cdp_runtime"])
            if cdp_leaked:
                self._add(DetectionVector.CDP_DETECTION, True, 0.85,
                          "CDP Runtime.evaluate detected in stack trace")
            else:
                self._add(DetectionVector.CDP_DETECTION, False, 0.0,
                          "No CDP leakage in stack traces")
        except Exception as exc:
            self._add(DetectionVector.CDP_DETECTION, False, 0.0, f"Check failed: {exc}")

    def _add(self, vector: DetectionVector, detected: bool, confidence: float, details: str) -> None:
        result = DetectionResult(
            vector=vector, detected=detected, confidence=confidence, details=details,
        )
        self._results.append(result)
        level = logging.WARNING if detected else logging.DEBUG
        logger.log(level, "[%s] detected=%s confidence=%.2f — %s",
                   vector.value, detected, confidence, details)

    @property
    def results(self) -> List[DetectionResult]:
        return list(self._results)

    @property
    def detection_score(self) -> float:
        """Overall detection score (0-10). Higher = more detectable."""
        if not self._results:
            return 0.0
        total = sum(r.confidence for r in self._results if r.detected)
        return min(10.0, round(total * (10.0 / max(len(self._results), 1)), 2))

    def summary(self) -> Dict[str, Any]:
        return {
            "total_checks": len(self._results),
            "detected": sum(1 for r in self._results if r.detected),
            "detection_score": self.detection_score,
            "results": [
                {
                    "vector": r.vector.value,
                    "detected": r.detected,
                    "confidence": r.confidence,
                    "risk_level": r.risk_level,
                    "details": r.details,
                }
                for r in self._results
            ],
        }
