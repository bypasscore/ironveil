"""
IronVeil Fingerprint Spoofing

Generates and applies browser fingerprint overrides including Canvas noise
injection, WebGL parameter randomization, AudioContext manipulation,
navigator property spoofing, and font enumeration masking.
"""

import hashlib
import logging
import random
import string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ironveil.evasion.fingerprint_spoof")


@dataclass
class SpoofProfile:
    """A complete set of fingerprint spoofing parameters."""
    canvas_noise_seed: int = 0
    canvas_noise_amplitude: float = 0.01
    webgl_vendor: str = ""
    webgl_renderer: str = ""
    webgl_params: Dict[str, Any] = field(default_factory=dict)
    audio_noise: float = 0.0001
    navigator_overrides: Dict[str, Any] = field(default_factory=dict)
    screen_overrides: Dict[str, Any] = field(default_factory=dict)
    font_blocklist: List[str] = field(default_factory=list)
    timezone: str = "America/New_York"
    language: str = "en-US"
    languages: List[str] = field(default_factory=lambda: ["en-US", "en"])

    @property
    def profile_hash(self) -> str:
        raw = f"{self.canvas_noise_seed}|{self.webgl_vendor}|{self.webgl_renderer}|{self.timezone}"
        return hashlib.md5(raw.encode()).hexdigest()[:12]


# Realistic WebGL configurations
_WEBGL_CONFIGS: List[Dict[str, Any]] = [
    {
        "vendor": "Google Inc. (NVIDIA)",
        "renderer": "ANGLE (NVIDIA, NVIDIA GeForce RTX 3060 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "max_texture_size": 16384,
        "max_renderbuffer_size": 16384,
        "max_vertex_attribs": 16,
    },
    {
        "vendor": "Google Inc. (NVIDIA)",
        "renderer": "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 SUPER Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "max_texture_size": 32768,
        "max_renderbuffer_size": 32768,
        "max_vertex_attribs": 16,
    },
    {
        "vendor": "Google Inc. (Intel)",
        "renderer": "ANGLE (Intel, Intel(R) UHD Graphics 630 Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "max_texture_size": 16384,
        "max_renderbuffer_size": 16384,
        "max_vertex_attribs": 16,
    },
    {
        "vendor": "Google Inc. (AMD)",
        "renderer": "ANGLE (AMD, AMD Radeon RX 6700 XT Direct3D11 vs_5_0 ps_5_0, D3D11)",
        "max_texture_size": 16384,
        "max_renderbuffer_size": 16384,
        "max_vertex_attribs": 16,
    },
    {
        "vendor": "Google Inc. (Apple)",
        "renderer": "ANGLE (Apple, Apple M1 Pro, OpenGL 4.1)",
        "max_texture_size": 16384,
        "max_renderbuffer_size": 16384,
        "max_vertex_attribs": 16,
    },
]

_SCREEN_CONFIGS: List[Dict[str, Any]] = [
    {"width": 1920, "height": 1080, "colorDepth": 24, "pixelRatio": 1.0},
    {"width": 2560, "height": 1440, "colorDepth": 24, "pixelRatio": 1.0},
    {"width": 1440, "height": 900, "colorDepth": 24, "pixelRatio": 2.0},
    {"width": 1536, "height": 864, "colorDepth": 24, "pixelRatio": 1.25},
    {"width": 1366, "height": 768, "colorDepth": 24, "pixelRatio": 1.0},
    {"width": 2560, "height": 1600, "colorDepth": 30, "pixelRatio": 2.0},
]

_NAVIGATOR_PLATFORMS = {
    "Win32": {"oscpu": None, "vendor": "Google Inc.", "product": "Gecko", "productSub": "20030107"},
    "MacIntel": {"oscpu": None, "vendor": "Apple Computer, Inc.", "product": "Gecko", "productSub": "20030107"},
    "Linux x86_64": {"oscpu": "Linux x86_64", "vendor": "Google Inc.", "product": "Gecko", "productSub": "20030107"},
}


def generate_spoof_profile(
    platform: Optional[str] = None,
    timezone: Optional[str] = None,
) -> SpoofProfile:
    """Generate a randomised but consistent spoof profile."""
    platform = platform or random.choice(list(_NAVIGATOR_PLATFORMS.keys()))
    webgl = random.choice(_WEBGL_CONFIGS)
    screen = random.choice(_SCREEN_CONFIGS)
    nav_props = _NAVIGATOR_PLATFORMS.get(platform, _NAVIGATOR_PLATFORMS["Win32"])

    return SpoofProfile(
        canvas_noise_seed=random.randint(0, 2**32 - 1),
        canvas_noise_amplitude=random.uniform(0.005, 0.02),
        webgl_vendor=webgl["vendor"],
        webgl_renderer=webgl["renderer"],
        webgl_params={
            "MAX_TEXTURE_SIZE": webgl["max_texture_size"],
            "MAX_RENDERBUFFER_SIZE": webgl["max_renderbuffer_size"],
            "MAX_VERTEX_ATTRIBS": webgl["max_vertex_attribs"],
        },
        audio_noise=random.uniform(0.00001, 0.01),
        navigator_overrides={
            "platform": platform,
            "hardwareConcurrency": random.choice([4, 6, 8, 12, 16]),
            "deviceMemory": random.choice([4, 8, 16]),
            **nav_props,
        },
        screen_overrides=screen,
        timezone=timezone or random.choice([
            "America/New_York", "America/Chicago", "America/Los_Angeles",
            "Europe/London", "Europe/Berlin", "Asia/Tokyo",
        ]),
        language=random.choice(["en-US", "en-GB", "de-DE"]),
        languages=random.choice([
            ["en-US", "en"], ["en-GB", "en"], ["de-DE", "de", "en"],
        ]),
    )


class FingerprintSpoofer:
    """Applies fingerprint spoofing overrides to a browser session."""

    def __init__(self, browser: Any, profile: Optional[SpoofProfile] = None) -> None:
        self.browser = browser
        self.profile = profile or generate_spoof_profile()
        self._applied = False

    def apply_all(self) -> None:
        """Apply all fingerprint overrides."""
        self._spoof_navigator()
        self._spoof_canvas()
        self._spoof_webgl()
        self._spoof_audio_context()
        self._spoof_screen()
        self._spoof_timezone()
        self._applied = True
        logger.info("Fingerprint spoofing applied (profile=%s)", self.profile.profile_hash)

    def _spoof_navigator(self) -> None:
        """Override navigator properties."""
        overrides = self.profile.navigator_overrides
        js_lines = []
        for key, value in overrides.items():
            if value is None:
                js_lines.append(
                    f"Object.defineProperty(navigator, '{key}', "
                    f"{{get: () => undefined, configurable: true}});"
                )
            elif isinstance(value, str):
                js_lines.append(
                    f"Object.defineProperty(navigator, '{key}', "
                    f"{{get: () => '{value}', configurable: true}});"
                )
            elif isinstance(value, (int, float)):
                js_lines.append(
                    f"Object.defineProperty(navigator, '{key}', "
                    f"{{get: () => {value}, configurable: true}});"
                )

        # Spoof languages
        langs_str = str(self.profile.languages).replace("'", '"')
        js_lines.append(
            f"Object.defineProperty(navigator, 'languages', "
            f"{{get: () => {langs_str}, configurable: true}});"
        )

        # Hide webdriver
        js_lines.append(
            "Object.defineProperty(navigator, 'webdriver', "
            "{get: () => false, configurable: true});"
        )

        self.browser.execute_js("\n".join(js_lines))
        logger.debug("Navigator spoofed (%d overrides)", len(overrides))

    def _spoof_canvas(self) -> None:
        """Inject noise into Canvas 2D operations."""
        seed = self.profile.canvas_noise_seed
        amp = self.profile.canvas_noise_amplitude
        js = f"""
        (function() {{
            const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
            const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
            const seed = {seed};
            let s = seed;
            function pseudoRandom() {{
                s = (s * 1664525 + 1013904223) & 0xFFFFFFFF;
                return (s >>> 0) / 0xFFFFFFFF;
            }}

            HTMLCanvasElement.prototype.toDataURL = function() {{
                const ctx = this.getContext('2d');
                if (ctx) {{
                    const imageData = origGetImageData.call(ctx, 0, 0, this.width, this.height);
                    for (let i = 0; i < imageData.data.length; i += 4) {{
                        imageData.data[i] = Math.max(0, Math.min(255,
                            imageData.data[i] + Math.floor((pseudoRandom() - 0.5) * {amp} * 255)));
                    }}
                    ctx.putImageData(imageData, 0, 0);
                }}
                return origToDataURL.apply(this, arguments);
            }};
        }})();
        """
        self.browser.execute_js(js)
        logger.debug("Canvas noise injected (seed=%d, amp=%.4f)", seed, amp)

    def _spoof_webgl(self) -> None:
        """Override WebGL vendor and renderer strings."""
        vendor = self.profile.webgl_vendor
        renderer = self.profile.webgl_renderer
        js = f"""
        (function() {{
            const getParam = WebGLRenderingContext.prototype.getParameter;
            WebGLRenderingContext.prototype.getParameter = function(param) {{
                const UNMASKED_VENDOR = 0x9245;
                const UNMASKED_RENDERER = 0x9246;
                if (param === UNMASKED_VENDOR) return '{vendor}';
                if (param === UNMASKED_RENDERER) return '{renderer}';
                return getParam.call(this, param);
            }};
        }})();
        """
        self.browser.execute_js(js)
        logger.debug("WebGL spoofed: vendor=%s, renderer=%s", vendor, renderer)

    def _spoof_audio_context(self) -> None:
        """Add noise to AudioContext fingerprinting."""
        noise = self.profile.audio_noise
        js = f"""
        (function() {{
            const origGetFloatFreq = AnalyserNode.prototype.getFloatFrequencyData;
            AnalyserNode.prototype.getFloatFrequencyData = function(array) {{
                origGetFloatFreq.call(this, array);
                for (let i = 0; i < array.length; i++) {{
                    array[i] += (Math.random() - 0.5) * {noise};
                }}
            }};
        }})();
        """
        self.browser.execute_js(js)
        logger.debug("AudioContext noise injected (amplitude=%.6f)", noise)

    def _spoof_screen(self) -> None:
        """Override screen dimension properties."""
        sc = self.profile.screen_overrides
        if not sc:
            return
        js_parts = []
        for prop in ["width", "height", "colorDepth", "pixelDepth"]:
            if prop in sc:
                js_parts.append(
                    f"Object.defineProperty(screen, '{prop}', "
                    f"{{get: () => {sc[prop]}, configurable: true}});"
                )
        if "pixelRatio" in sc:
            js_parts.append(
                f"Object.defineProperty(window, 'devicePixelRatio', "
                f"{{get: () => {sc['pixelRatio']}, configurable: true}});"
            )
        self.browser.execute_js("\n".join(js_parts))
        logger.debug("Screen spoofed: %s", sc)

    def _spoof_timezone(self) -> None:
        """Override Intl timezone information."""
        tz = self.profile.timezone
        js = f"""
        (function() {{
            const origResolvedOptions = Intl.DateTimeFormat.prototype.resolvedOptions;
            Intl.DateTimeFormat.prototype.resolvedOptions = function() {{
                const opts = origResolvedOptions.call(this);
                opts.timeZone = '{tz}';
                return opts;
            }};
        }})();
        """
        self.browser.execute_js(js)
        logger.debug("Timezone spoofed to %s", tz)

    @property
    def is_applied(self) -> bool:
        return self._applied

    def verify(self) -> Dict[str, bool]:
        """Verify that spoofing overrides are effective."""
        results: Dict[str, bool] = {}

        # Check webdriver flag
        webdriver_val = self.browser.execute_js("return navigator.webdriver")
        results["webdriver_hidden"] = webdriver_val is False

        # Check platform
        plat = self.browser.execute_js("return navigator.platform")
        results["platform_spoofed"] = plat == self.profile.navigator_overrides.get("platform")

        # Check hardware concurrency
        hc = self.browser.execute_js("return navigator.hardwareConcurrency")
        results["hw_concurrency_spoofed"] = hc == self.profile.navigator_overrides.get("hardwareConcurrency")

        passed = sum(1 for v in results.values() if v)
        logger.info("Spoof verification: %d/%d checks passed", passed, len(results))
        return results

    def summary(self) -> Dict[str, Any]:
        return {
            "profile_hash": self.profile.profile_hash,
            "applied": self._applied,
            "webgl_vendor": self.profile.webgl_vendor,
            "webgl_renderer": self.profile.webgl_renderer,
            "platform": self.profile.navigator_overrides.get("platform"),
            "timezone": self.profile.timezone,
            "canvas_noise_seed": self.profile.canvas_noise_seed,
            "screen": self.profile.screen_overrides,
        }
