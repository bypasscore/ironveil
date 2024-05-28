"""
Tests for ironveil.detection.fingerprint and ironveil.evasion.fingerprint_spoof

Validates fingerprint component hashing, entropy calculations,
profile generation, and spoofing parameter consistency.
"""

import hashlib
import json

import pytest

from ironveil.detection.fingerprint import (
    ComponentResult,
    FingerprintComponent,
    FingerprintProfile,
    _ENTROPY_ESTIMATES,
)
from ironveil.evasion.fingerprint_spoof import (
    FingerprintSpoofer,
    SpoofProfile,
    generate_spoof_profile,
    _WEBGL_CONFIGS,
    _SCREEN_CONFIGS,
    _NAVIGATOR_PLATFORMS,
)


# ---------------------------------------------------------------------------
# FingerprintProfile
# ---------------------------------------------------------------------------

class TestFingerprintProfile:
    def test_empty_profile_hash(self):
        profile = FingerprintProfile()
        h = profile.combined_hash
        assert isinstance(h, str)
        assert len(h) == 64  # sha256 hex

    def test_combined_hash_changes_with_components(self):
        profile_a = FingerprintProfile()
        profile_a.components["canvas_2d"] = ComponentResult(
            component=FingerprintComponent.CANVAS_2D,
            hash_value="abc123",
            entropy_bits=12.5,
        )

        profile_b = FingerprintProfile()
        profile_b.components["canvas_2d"] = ComponentResult(
            component=FingerprintComponent.CANVAS_2D,
            hash_value="def456",
            entropy_bits=12.5,
        )

        assert profile_a.combined_hash != profile_b.combined_hash

    def test_total_entropy(self):
        profile = FingerprintProfile()
        profile.components["a"] = ComponentResult(
            component=FingerprintComponent.CANVAS_2D,
            hash_value="x", entropy_bits=10.0,
        )
        profile.components["b"] = ComponentResult(
            component=FingerprintComponent.WEBGL,
            hash_value="y", entropy_bits=18.0,
        )
        assert profile.total_entropy == pytest.approx(28.0)

    def test_component_count_excludes_failures(self):
        profile = FingerprintProfile()
        profile.components["ok"] = ComponentResult(
            component=FingerprintComponent.CANVAS_2D,
            hash_value="x", entropy_bits=10.0, success=True,
        )
        profile.components["fail"] = ComponentResult(
            component=FingerprintComponent.WEBGL,
            hash_value="error", entropy_bits=0, success=False,
        )
        assert profile.component_count == 1


class TestComponentResult:
    @pytest.mark.parametrize("entropy,expected", [
        (25.0, "VERY_HIGH"),
        (15.0, "HIGH"),
        (7.0, "MEDIUM"),
        (2.0, "LOW"),
    ])
    def test_uniqueness_levels(self, entropy, expected):
        result = ComponentResult(
            component=FingerprintComponent.CANVAS_2D,
            hash_value="test",
            entropy_bits=entropy,
        )
        assert result.uniqueness == expected


class TestEntropyEstimates:
    def test_all_components_have_estimates(self):
        # At least the major components should have entropy estimates
        assert FingerprintComponent.CANVAS_2D.value in _ENTROPY_ESTIMATES
        assert FingerprintComponent.WEBGL.value in _ENTROPY_ESTIMATES
        assert FingerprintComponent.AUDIO_CONTEXT.value in _ENTROPY_ESTIMATES
        assert FingerprintComponent.NAVIGATOR.value in _ENTROPY_ESTIMATES

    def test_estimates_are_positive(self):
        for component, entropy in _ENTROPY_ESTIMATES.items():
            assert entropy > 0, f"{component} has non-positive entropy"


# ---------------------------------------------------------------------------
# SpoofProfile
# ---------------------------------------------------------------------------

class TestSpoofProfile:
    def test_default_profile(self):
        profile = SpoofProfile()
        assert isinstance(profile.profile_hash, str)
        assert len(profile.profile_hash) == 12

    def test_profile_hash_deterministic(self):
        p1 = SpoofProfile(canvas_noise_seed=42, webgl_vendor="V", webgl_renderer="R", timezone="UTC")
        p2 = SpoofProfile(canvas_noise_seed=42, webgl_vendor="V", webgl_renderer="R", timezone="UTC")
        assert p1.profile_hash == p2.profile_hash

    def test_different_profiles_different_hashes(self):
        p1 = SpoofProfile(canvas_noise_seed=1, webgl_vendor="A", webgl_renderer="X", timezone="UTC")
        p2 = SpoofProfile(canvas_noise_seed=2, webgl_vendor="B", webgl_renderer="Y", timezone="EST")
        assert p1.profile_hash != p2.profile_hash


class TestGenerateSpoofProfile:
    def test_generates_valid_profile(self):
        profile = generate_spoof_profile()
        assert isinstance(profile, SpoofProfile)
        assert profile.webgl_vendor != ""
        assert profile.webgl_renderer != ""
        assert profile.timezone != ""
        assert profile.canvas_noise_seed >= 0

    def test_respects_platform_override(self):
        profile = generate_spoof_profile(platform="MacIntel")
        assert profile.navigator_overrides["platform"] == "MacIntel"

    def test_respects_timezone_override(self):
        profile = generate_spoof_profile(timezone="Asia/Tokyo")
        assert profile.timezone == "Asia/Tokyo"

    def test_generates_different_profiles(self):
        profiles = [generate_spoof_profile() for _ in range(10)]
        hashes = {p.profile_hash for p in profiles}
        # With random generation, most should be unique
        assert len(hashes) >= 5

    def test_webgl_config_valid(self):
        for config in _WEBGL_CONFIGS:
            assert "vendor" in config
            assert "renderer" in config
            assert config["max_texture_size"] >= 4096

    def test_screen_configs_valid(self):
        for config in _SCREEN_CONFIGS:
            assert config["width"] > 0
            assert config["height"] > 0
            assert config["colorDepth"] in (24, 30, 32)

    def test_navigator_platforms(self):
        assert "Win32" in _NAVIGATOR_PLATFORMS
        assert "MacIntel" in _NAVIGATOR_PLATFORMS
        assert "Linux x86_64" in _NAVIGATOR_PLATFORMS


# ---------------------------------------------------------------------------
# FingerprintSpoofer (unit tests without browser)
# ---------------------------------------------------------------------------

class TestFingerprintSpoofer:
    def test_init_with_default_profile(self):
        class MockBrowser:
            def execute_js(self, js):
                return None

        spoofer = FingerprintSpoofer(MockBrowser())
        assert not spoofer.is_applied
        assert isinstance(spoofer.profile, SpoofProfile)

    def test_init_with_custom_profile(self):
        class MockBrowser:
            def execute_js(self, js):
                return None

        custom = SpoofProfile(
            canvas_noise_seed=12345,
            webgl_vendor="Test Vendor",
            webgl_renderer="Test Renderer",
        )
        spoofer = FingerprintSpoofer(MockBrowser(), profile=custom)
        assert spoofer.profile.canvas_noise_seed == 12345
        assert spoofer.profile.webgl_vendor == "Test Vendor"

    def test_summary_structure(self):
        class MockBrowser:
            def execute_js(self, js):
                return None

        spoofer = FingerprintSpoofer(MockBrowser())
        summary = spoofer.summary()
        assert "profile_hash" in summary
        assert "applied" in summary
        assert "webgl_vendor" in summary
        assert "webgl_renderer" in summary
        assert summary["applied"] is False
