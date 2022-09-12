"""
IronVeil CAPTCHA System Analysis

Detects and classifies CAPTCHA implementations on target platforms,
including reCAPTCHA (v2/v3), hCaptcha, Turnstile, FunCaptcha, and
custom CAPTCHA solutions. Assesses difficulty and bypass potential.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ironveil.detection.captcha")


class CaptchaType(Enum):
    """Known CAPTCHA provider types."""
    RECAPTCHA_V2 = "recaptcha_v2"
    RECAPTCHA_V3 = "recaptcha_v3"
    RECAPTCHA_ENTERPRISE = "recaptcha_enterprise"
    HCAPTCHA = "hcaptcha"
    TURNSTILE = "turnstile"
    FUNCAPTCHA = "funcaptcha"
    GEETEST = "geetest"
    TEXT_CAPTCHA = "text_captcha"
    IMAGE_CAPTCHA = "image_captcha"
    CUSTOM = "custom"
    NONE = "none"


class CaptchaTrigger(Enum):
    """When the CAPTCHA appears."""
    ON_LOAD = "on_load"
    ON_LOGIN = "on_login"
    ON_REGISTRATION = "on_registration"
    ON_TRANSACTION = "on_transaction"
    ON_SUSPICIOUS_ACTIVITY = "on_suspicious_activity"
    ON_RATE_LIMIT = "on_rate_limit"
    INVISIBLE = "invisible"


@dataclass
class CaptchaDetection:
    """Information about a detected CAPTCHA on a page."""
    captcha_type: CaptchaType
    provider_version: Optional[str] = None
    site_key: Optional[str] = None
    trigger: CaptchaTrigger = CaptchaTrigger.ON_LOAD
    difficulty_score: float = 5.0  # 1-10 scale
    bypass_difficulty: float = 5.0  # 1-10 scale
    invisible: bool = False
    element_selector: Optional[str] = None
    script_urls: List[str] = field(default_factory=list)
    raw_config: Dict[str, Any] = field(default_factory=dict)
    detected_at: float = field(default_factory=time.time)

    @property
    def risk_assessment(self) -> str:
        if self.bypass_difficulty >= 8:
            return "VERY_HARD"
        elif self.bypass_difficulty >= 6:
            return "HARD"
        elif self.bypass_difficulty >= 4:
            return "MEDIUM"
        return "EASY"


# Detection signatures
_RECAPTCHA_PATTERNS = [
    r"google\.com/recaptcha",
    r"grecaptcha",
    r"g-recaptcha",
    r"recaptcha/api",
    r"recaptcha/enterprise",
]

_HCAPTCHA_PATTERNS = [
    r"hcaptcha\.com",
    r"h-captcha",
    r"hcaptcha-challenge",
]

_TURNSTILE_PATTERNS = [
    r"challenges\.cloudflare\.com/turnstile",
    r"cf-turnstile",
    r"turnstile/v0",
]

_FUNCAPTCHA_PATTERNS = [
    r"funcaptcha\.com",
    r"arkoselabs\.com",
    r"arkose",
]

_GEETEST_PATTERNS = [
    r"geetest\.com",
    r"gt_lib",
    r"initGeetest",
]


def _search_patterns(source: str, patterns: List[str]) -> List[str]:
    """Return all patterns that match in the source."""
    found: List[str] = []
    for pat in patterns:
        if re.search(pat, source, re.IGNORECASE):
            found.append(pat)
    return found


class CaptchaAnalyzer:
    """Detects and classifies CAPTCHA implementations on a platform."""

    def __init__(self, browser: Any) -> None:
        self.browser = browser
        self._detections: List[CaptchaDetection] = []

    def scan_page(self) -> List[CaptchaDetection]:
        """Scan the current page for CAPTCHA presence."""
        self._detections.clear()

        page_source = self.browser.page_source()
        scripts = self._get_external_scripts()

        combined_source = page_source + " ".join(scripts)

        self._check_recaptcha(page_source, scripts)
        self._check_hcaptcha(page_source, scripts)
        self._check_turnstile(page_source, scripts)
        self._check_funcaptcha(page_source, scripts)
        self._check_geetest(page_source, scripts)
        self._check_custom_captcha(page_source)

        if not self._detections:
            self._detections.append(CaptchaDetection(
                captcha_type=CaptchaType.NONE,
                difficulty_score=0.0,
                bypass_difficulty=0.0,
            ))

        logger.info("CAPTCHA scan complete: %d type(s) detected", len(self._detections))
        return list(self._detections)

    def _get_external_scripts(self) -> List[str]:
        """Get URLs of all external scripts on the page."""
        try:
            urls = self.browser.execute_js(
                "return Array.from(document.querySelectorAll('script[src]'))"
                ".map(s => s.src)"
            )
            return urls or []
        except Exception:
            return []

    def _check_recaptcha(self, source: str, scripts: List[str]) -> None:
        """Check for reCAPTCHA presence."""
        matches = _search_patterns(source, _RECAPTCHA_PATTERNS)
        script_matches = [s for s in scripts if any(
            re.search(p, s, re.IGNORECASE) for p in _RECAPTCHA_PATTERNS
        )]

        if not matches and not script_matches:
            return

        # Determine version
        is_enterprise = "recaptcha/enterprise" in source.lower()
        is_v3 = "recaptcha/api.js?render=" in source.lower() or self._detect_recaptcha_v3(source)
        is_invisible = 'data-size="invisible"' in source

        # Extract site key
        site_key = self._extract_recaptcha_sitekey(source)

        if is_enterprise:
            captcha_type = CaptchaType.RECAPTCHA_ENTERPRISE
            bypass_diff = 9.0
        elif is_v3:
            captcha_type = CaptchaType.RECAPTCHA_V3
            bypass_diff = 7.5
        else:
            captcha_type = CaptchaType.RECAPTCHA_V2
            bypass_diff = 5.0 if not is_invisible else 6.5

        self._detections.append(CaptchaDetection(
            captcha_type=captcha_type,
            provider_version="enterprise" if is_enterprise else ("v3" if is_v3 else "v2"),
            site_key=site_key,
            difficulty_score=7.0 if is_enterprise else 5.0,
            bypass_difficulty=bypass_diff,
            invisible=is_invisible or is_v3,
            script_urls=script_matches,
        ))

    def _detect_recaptcha_v3(self, source: str) -> bool:
        return bool(re.search(r"grecaptcha\.execute", source))

    def _extract_recaptcha_sitekey(self, source: str) -> Optional[str]:
        match = re.search(r'data-sitekey="([^"]+)"', source)
        if match:
            return match.group(1)
        match = re.search(r"grecaptcha\.execute\(['\"]([^'\"]+)['\"]", source)
        if match:
            return match.group(1)
        return None

    def _check_hcaptcha(self, source: str, scripts: List[str]) -> None:
        matches = _search_patterns(source, _HCAPTCHA_PATTERNS)
        script_matches = [s for s in scripts if any(
            re.search(p, s, re.IGNORECASE) for p in _HCAPTCHA_PATTERNS
        )]
        if not matches and not script_matches:
            return

        site_key = None
        match = re.search(r'data-sitekey="([^"]+)"', source)
        if match:
            site_key = match.group(1)

        is_invisible = 'data-size="invisible"' in source

        self._detections.append(CaptchaDetection(
            captcha_type=CaptchaType.HCAPTCHA,
            site_key=site_key,
            difficulty_score=6.0,
            bypass_difficulty=6.0 if not is_invisible else 7.0,
            invisible=is_invisible,
            script_urls=script_matches,
        ))

    def _check_turnstile(self, source: str, scripts: List[str]) -> None:
        matches = _search_patterns(source, _TURNSTILE_PATTERNS)
        script_matches = [s for s in scripts if any(
            re.search(p, s, re.IGNORECASE) for p in _TURNSTILE_PATTERNS
        )]
        if not matches and not script_matches:
            return

        self._detections.append(CaptchaDetection(
            captcha_type=CaptchaType.TURNSTILE,
            difficulty_score=7.0,
            bypass_difficulty=7.5,
            invisible=True,
            script_urls=script_matches,
        ))

    def _check_funcaptcha(self, source: str, scripts: List[str]) -> None:
        matches = _search_patterns(source, _FUNCAPTCHA_PATTERNS)
        if not matches:
            return
        self._detections.append(CaptchaDetection(
            captcha_type=CaptchaType.FUNCAPTCHA,
            difficulty_score=7.0,
            bypass_difficulty=8.0,
            script_urls=[s for s in scripts if "arkoselabs" in s.lower()],
        ))

    def _check_geetest(self, source: str, scripts: List[str]) -> None:
        matches = _search_patterns(source, _GEETEST_PATTERNS)
        if not matches:
            return
        self._detections.append(CaptchaDetection(
            captcha_type=CaptchaType.GEETEST,
            difficulty_score=6.5,
            bypass_difficulty=7.0,
            script_urls=[s for s in scripts if "geetest" in s.lower()],
        ))

    def _check_custom_captcha(self, source: str) -> None:
        """Heuristic check for custom CAPTCHA implementations."""
        indicators = [
            (r'<img[^>]*captcha[^>]*>', "image_captcha_tag"),
            (r'captcha[-_]?image', "captcha_image_class"),
            (r'captcha[-_]?input', "captcha_input_field"),
            (r'verify[-_]?human', "verify_human_text"),
            (r'type the (characters|text|code)', "type_code_prompt"),
        ]
        found = []
        for pattern, label in indicators:
            if re.search(pattern, source, re.IGNORECASE):
                found.append(label)

        if found:
            is_text = any("text" in f or "code" in f or "type" in f for f in found)
            self._detections.append(CaptchaDetection(
                captcha_type=CaptchaType.TEXT_CAPTCHA if is_text else CaptchaType.IMAGE_CAPTCHA,
                difficulty_score=3.0,
                bypass_difficulty=2.5 if is_text else 4.0,
                raw_config={"indicators": found},
            ))

    @property
    def detections(self) -> List[CaptchaDetection]:
        return list(self._detections)

    def summary(self) -> Dict[str, Any]:
        return {
            "captcha_count": len(self._detections),
            "types": [d.captcha_type.value for d in self._detections],
            "max_bypass_difficulty": max(
                (d.bypass_difficulty for d in self._detections), default=0.0
            ),
            "detections": [
                {
                    "type": d.captcha_type.value,
                    "version": d.provider_version,
                    "site_key": d.site_key,
                    "difficulty": d.difficulty_score,
                    "bypass_difficulty": d.bypass_difficulty,
                    "risk": d.risk_assessment,
                    "invisible": d.invisible,
                }
                for d in self._detections
            ],
        }
