"""
IronVeil Browser Fingerprint Analysis

Collects and analyzes browser fingerprints from the target platform,
covering Canvas, WebGL, AudioContext, navigator properties, fonts,
and screen characteristics to assess fingerprinting robustness.
"""

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ironveil.detection.fingerprint")


class FingerprintComponent(Enum):
    """Individual fingerprint components."""
    CANVAS_2D = "canvas_2d"
    WEBGL = "webgl"
    WEBGL2 = "webgl2"
    WEBGL_EXTENSIONS = "webgl_extensions"
    AUDIO_CONTEXT = "audio_context"
    NAVIGATOR = "navigator"
    SCREEN = "screen"
    FONTS = "fonts"
    TIMEZONE = "timezone"
    PLUGINS = "plugins"
    MEDIA_DEVICES = "media_devices"
    WEBRTC = "webrtc"
    CSS_FEATURES = "css_features"


@dataclass
class ComponentResult:
    """Result from fingerprinting a single component."""
    component: FingerprintComponent
    hash_value: str
    raw_data: Any = None
    entropy_bits: float = 0.0
    collection_time_ms: float = 0.0
    success: bool = True
    error: Optional[str] = None

    @property
    def uniqueness(self) -> str:
        if self.entropy_bits >= 20:
            return "VERY_HIGH"
        elif self.entropy_bits >= 10:
            return "HIGH"
        elif self.entropy_bits >= 5:
            return "MEDIUM"
        return "LOW"


@dataclass
class FingerprintProfile:
    """Complete fingerprint profile collected from a session."""
    components: Dict[str, ComponentResult] = field(default_factory=dict)
    collected_at: float = field(default_factory=time.time)

    @property
    def combined_hash(self) -> str:
        parts = sorted(f"{k}:{v.hash_value}" for k, v in self.components.items() if v.success)
        raw = "|".join(parts)
        return hashlib.sha256(raw.encode()).hexdigest()

    @property
    def total_entropy(self) -> float:
        return sum(c.entropy_bits for c in self.components.values() if c.success)

    @property
    def component_count(self) -> int:
        return sum(1 for c in self.components.values() if c.success)


# JavaScript for fingerprint collection
_JS_CANVAS_2D = """
(function() {
    const canvas = document.createElement('canvas');
    canvas.width = 280; canvas.height = 60;
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('IronVeil fp test', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Canvas 2D', 4, 45);
    ctx.beginPath();
    ctx.arc(50, 50, 10, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();
    return canvas.toDataURL();
})();
"""

_JS_WEBGL = """
(function() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    return {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        unmaskedVendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : null,
        unmaskedRenderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : null,
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        maxRenderBufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
        maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
        aliasedLineWidthRange: gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE),
        aliasedPointSizeRange: gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE),
        extensions: gl.getSupportedExtensions()
    };
})();
"""

_JS_AUDIO = """
(function() {
    try {
        const ctx = new (window.AudioContext || window.webkitAudioContext)();
        const oscillator = ctx.createOscillator();
        const analyser = ctx.createAnalyser();
        const gain = ctx.createGain();
        const processor = ctx.createScriptProcessor(4096, 1, 1);
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, ctx.currentTime);
        gain.gain.setValueAtTime(0, ctx.currentTime);
        oscillator.connect(analyser);
        analyser.connect(processor);
        processor.connect(gain);
        gain.connect(ctx.destination);
        return {
            sampleRate: ctx.sampleRate,
            state: ctx.state,
            channelCount: ctx.destination.channelCount,
            maxChannelCount: ctx.destination.maxChannelCount,
            numberOfInputs: ctx.destination.numberOfInputs,
            numberOfOutputs: ctx.destination.numberOfOutputs,
            fftSize: analyser.fftSize,
        };
    } catch(e) { return {error: e.message}; }
})();
"""

_JS_NAVIGATOR = """
(function() {
    return {
        userAgent: navigator.userAgent,
        platform: navigator.platform,
        language: navigator.language,
        languages: navigator.languages ? Array.from(navigator.languages) : [],
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: navigator.deviceMemory || null,
        maxTouchPoints: navigator.maxTouchPoints,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,
        vendor: navigator.vendor,
        product: navigator.product,
        productSub: navigator.productSub,
        buildID: navigator.buildID || null,
        oscpu: navigator.oscpu || null,
        pdfViewerEnabled: navigator.pdfViewerEnabled,
    };
})();
"""

_JS_SCREEN = """
(function() {
    return {
        width: screen.width,
        height: screen.height,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        devicePixelRatio: window.devicePixelRatio,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
    };
})();
"""

_JS_FONTS = """
(function() {
    const testFonts = [
        'Arial', 'Verdana', 'Helvetica', 'Times New Roman', 'Courier New',
        'Georgia', 'Palatino', 'Garamond', 'Comic Sans MS', 'Impact',
        'Lucida Console', 'Tahoma', 'Trebuchet MS', 'Arial Black',
        'Segoe UI', 'Roboto', 'Open Sans', 'Consolas', 'Monaco',
    ];
    const baseFonts = ['monospace', 'sans-serif', 'serif'];
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';
    const body = document.body;
    const span = document.createElement('span');
    span.style.fontSize = testSize;
    span.style.position = 'absolute';
    span.style.left = '-9999px';
    span.textContent = testString;
    body.appendChild(span);

    const baseWidths = {};
    for (const base of baseFonts) {
        span.style.fontFamily = base;
        baseWidths[base] = span.offsetWidth;
    }

    const detected = [];
    for (const font of testFonts) {
        for (const base of baseFonts) {
            span.style.fontFamily = '"' + font + '",' + base;
            if (span.offsetWidth !== baseWidths[base]) {
                detected.push(font);
                break;
            }
        }
    }
    body.removeChild(span);
    return detected;
})();
"""

_JS_WEBGL2 = """
(function() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl2');
    if (!gl) return null;
    const ext = gl.getExtension('WEBGL_debug_renderer_info');
    return {
        version: gl.getParameter(gl.VERSION),
        shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        unmaskedVendor: ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : null,
        unmaskedRenderer: ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : null,
        maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
        max3DTextureSize: gl.getParameter(gl.MAX_3D_TEXTURE_SIZE),
        maxArrayTextureLayers: gl.getParameter(gl.MAX_ARRAY_TEXTURE_LAYERS),
        maxColorAttachments: gl.getParameter(gl.MAX_COLOR_ATTACHMENTS),
        maxDrawBuffers: gl.getParameter(gl.MAX_DRAW_BUFFERS),
        maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
        maxSamples: gl.getParameter(gl.MAX_SAMPLES),
        maxTransformFeedbackInterleavedComponents: gl.getParameter(gl.MAX_TRANSFORM_FEEDBACK_INTERLEAVED_COMPONENTS),
        maxUniformBlockSize: gl.getParameter(gl.MAX_UNIFORM_BLOCK_SIZE),
        maxUniformBufferBindings: gl.getParameter(gl.MAX_UNIFORM_BUFFER_BINDINGS),
        maxVertexUniformComponents: gl.getParameter(gl.MAX_VERTEX_UNIFORM_COMPONENTS),
        maxFragmentUniformComponents: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_COMPONENTS),
        maxVertexOutputComponents: gl.getParameter(gl.MAX_VERTEX_OUTPUT_COMPONENTS),
        maxFragmentInputComponents: gl.getParameter(gl.MAX_FRAGMENT_INPUT_COMPONENTS),
        extensions: gl.getSupportedExtensions(),
        contextAttributes: gl.getContextAttributes(),
    };
})();
"""

_JS_TIMEZONE = """
(function() {
    return {
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        locale: Intl.DateTimeFormat().resolvedOptions().locale,
    };
})();
"""

# Estimated entropy values per component (bits)
_ENTROPY_ESTIMATES: Dict[str, float] = {
    FingerprintComponent.CANVAS_2D.value: 12.5,
    FingerprintComponent.WEBGL.value: 18.0,
    FingerprintComponent.WEBGL2.value: 20.0,
    FingerprintComponent.WEBGL_EXTENSIONS.value: 8.5,
    FingerprintComponent.AUDIO_CONTEXT.value: 6.0,
    FingerprintComponent.NAVIGATOR.value: 10.0,
    FingerprintComponent.SCREEN.value: 5.5,
    FingerprintComponent.FONTS.value: 13.0,
    FingerprintComponent.TIMEZONE.value: 4.0,
}


class FingerprintAnalyzer:
    """Collects and analyzes browser fingerprints from a target platform."""

    def __init__(self, browser: Any) -> None:
        self.browser = browser
        self.profile = FingerprintProfile()

    def collect_all(self) -> FingerprintProfile:
        """Collect all fingerprint components."""
        collectors = [
            (FingerprintComponent.CANVAS_2D, self._collect_canvas),
            (FingerprintComponent.WEBGL, self._collect_webgl),
            (FingerprintComponent.WEBGL2, self._collect_webgl2),
            (FingerprintComponent.AUDIO_CONTEXT, self._collect_audio),
            (FingerprintComponent.NAVIGATOR, self._collect_navigator),
            (FingerprintComponent.SCREEN, self._collect_screen),
            (FingerprintComponent.FONTS, self._collect_fonts),
            (FingerprintComponent.TIMEZONE, self._collect_timezone),
        ]

        for component, collector in collectors:
            start = time.monotonic()
            try:
                raw = collector()
                elapsed = (time.monotonic() - start) * 1000
                hash_val = hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:16]
                entropy = _ENTROPY_ESTIMATES.get(component.value, 5.0)

                self.profile.components[component.value] = ComponentResult(
                    component=component,
                    hash_value=hash_val,
                    raw_data=raw,
                    entropy_bits=entropy,
                    collection_time_ms=round(elapsed, 2),
                )
                logger.debug("Collected %s (hash=%s, %.1fms)", component.value, hash_val, elapsed)
            except Exception as exc:
                elapsed = (time.monotonic() - start) * 1000
                self.profile.components[component.value] = ComponentResult(
                    component=component,
                    hash_value="error",
                    entropy_bits=0.0,
                    collection_time_ms=round(elapsed, 2),
                    success=False,
                    error=str(exc),
                )
                logger.warning("Failed to collect %s: %s", component.value, exc)

        logger.info(
            "Fingerprint collected: %d components, %.1f bits entropy, hash=%s",
            self.profile.component_count,
            self.profile.total_entropy,
            self.profile.combined_hash[:12],
        )
        return self.profile

    def _collect_canvas(self) -> Any:
        return self.browser.execute_js(_JS_CANVAS_2D)

    def _collect_webgl(self) -> Any:
        return self.browser.execute_js(_JS_WEBGL)

    def _collect_webgl2(self) -> Any:
        return self.browser.execute_js(_JS_WEBGL2)

    def _collect_audio(self) -> Any:
        return self.browser.execute_js(_JS_AUDIO)

    def _collect_navigator(self) -> Any:
        return self.browser.execute_js(_JS_NAVIGATOR)

    def _collect_screen(self) -> Any:
        return self.browser.execute_js(_JS_SCREEN)

    def _collect_fonts(self) -> Any:
        return self.browser.execute_js(_JS_FONTS)

    def _collect_timezone(self) -> Any:
        return self.browser.execute_js(_JS_TIMEZONE)

    def compare(self, other: FingerprintProfile) -> Dict[str, Any]:
        """Compare two fingerprint profiles component by component."""
        diffs: List[str] = []
        matches: List[str] = []
        for key in set(self.profile.components) | set(other.components):
            a = self.profile.components.get(key)
            b = other.components.get(key)
            if a and b and a.hash_value == b.hash_value:
                matches.append(key)
            else:
                diffs.append(key)

        return {
            "hash_a": self.profile.combined_hash[:16],
            "hash_b": other.combined_hash[:16],
            "matching": matches,
            "different": diffs,
            "similarity": len(matches) / max(len(matches) + len(diffs), 1),
        }

    def summary(self) -> Dict[str, Any]:
        return {
            "combined_hash": self.profile.combined_hash,
            "total_entropy_bits": round(self.profile.total_entropy, 1),
            "components_collected": self.profile.component_count,
            "components": {
                k: {
                    "hash": v.hash_value,
                    "entropy_bits": v.entropy_bits,
                    "uniqueness": v.uniqueness,
                    "collection_time_ms": v.collection_time_ms,
                    "success": v.success,
                }
                for k, v in self.profile.components.items()
            },
        }
