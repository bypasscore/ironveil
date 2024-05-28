"""
Tests for ironveil.core.engine

Validates audit engine initialization, configuration integration,
finding management, result scoring, and lifecycle hooks.
"""

import time
from unittest.mock import MagicMock, patch

import pytest

from ironveil.core.config import Config
from ironveil.core.engine import (
    AuditEngine,
    AuditFinding,
    AuditPhase,
    AuditResult,
)


# ---------------------------------------------------------------------------
# AuditFinding
# ---------------------------------------------------------------------------

class TestAuditFinding:
    def test_creation(self):
        finding = AuditFinding(
            phase=AuditPhase.DETECTION,
            module="bot_detector",
            title="WebDriver flag detected",
            description="navigator.webdriver is true",
            severity="high",
        )
        assert finding.phase == AuditPhase.DETECTION
        assert finding.module == "bot_detector"
        assert finding.severity == "high"
        assert finding.timestamp > 0

    def test_data_defaults_to_empty(self):
        finding = AuditFinding(
            phase=AuditPhase.DETECTION,
            module="test",
            title="Test",
            description="Test",
            severity="info",
        )
        assert finding.data == {}
        assert finding.remediation == ""


# ---------------------------------------------------------------------------
# AuditResult
# ---------------------------------------------------------------------------

class TestAuditResult:
    def _make_result(self, findings=None):
        result = AuditResult(
            audit_id="test123",
            target_url="https://example.com",
            started_at=time.time() - 60,
            completed_at=time.time(),
        )
        if findings:
            result.findings = findings
        return result

    def test_duration(self):
        result = self._make_result()
        assert result.duration_seconds == pytest.approx(60, abs=2)

    def test_risk_score_empty(self):
        result = self._make_result()
        assert result.risk_score == 0.0

    def test_risk_score_with_findings(self):
        findings = [
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "critical"),
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "high"),
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "low"),
        ]
        result = self._make_result(findings)
        score = result.risk_score
        assert score > 0
        assert score <= 10.0

    def test_finding_counts(self):
        findings = [
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "critical"),
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "critical"),
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "medium"),
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "info"),
        ]
        result = self._make_result(findings)
        counts = result.finding_counts
        assert counts["critical"] == 2
        assert counts["medium"] == 1
        assert counts["info"] == 1
        assert "high" not in counts

    def test_risk_score_capped_at_10(self):
        findings = [
            AuditFinding(AuditPhase.DETECTION, "m", "t", "d", "critical")
            for _ in range(50)
        ]
        result = self._make_result(findings)
        assert result.risk_score <= 10.0


# ---------------------------------------------------------------------------
# AuditPhase
# ---------------------------------------------------------------------------

class TestAuditPhase:
    def test_all_phases_have_values(self):
        phases = list(AuditPhase)
        assert len(phases) >= 7
        assert AuditPhase.INIT in phases
        assert AuditPhase.COMPLETE in phases
        assert AuditPhase.FAILED in phases

    def test_phase_values_are_strings(self):
        for phase in AuditPhase:
            assert isinstance(phase.value, str)


# ---------------------------------------------------------------------------
# AuditEngine
# ---------------------------------------------------------------------------

class TestAuditEngine:
    def test_initialization_default_config(self):
        engine = AuditEngine()
        assert engine.audit_id is not None
        assert len(engine.audit_id) == 12
        assert engine.result is None

    def test_initialization_custom_config(self):
        config = Config(auto_discover=False, load_env=False)
        config.set("general.project_name", "Test Audit")
        engine = AuditEngine(config)
        assert engine.config.get("general.project_name") == "Test Audit"

    def test_register_hook(self):
        engine = AuditEngine()
        callback = MagicMock()
        engine.register_hook("on_finding", callback)
        assert callback in engine._hooks["on_finding"]

    def test_register_hook_invalid_event(self):
        engine = AuditEngine()
        callback = MagicMock()
        engine.register_hook("nonexistent_event", callback)
        # Should not crash, just ignored

    def test_fire_hooks(self):
        engine = AuditEngine()
        callback = MagicMock()
        engine.register_hook("on_finding", callback)
        engine._fire_hooks("on_finding", finding="test_data")
        callback.assert_called_once_with(finding="test_data")

    def test_fire_hooks_error_handling(self):
        engine = AuditEngine()

        def bad_callback(**kwargs):
            raise ValueError("Oops")

        engine.register_hook("on_finding", bad_callback)
        # Should not raise
        engine._fire_hooks("on_finding", finding="test")

    def test_multiple_hooks_same_event(self):
        engine = AuditEngine()
        cb1 = MagicMock()
        cb2 = MagicMock()
        engine.register_hook("before_phase", cb1)
        engine.register_hook("before_phase", cb2)
        engine._fire_hooks("before_phase", phase=AuditPhase.INIT)
        cb1.assert_called_once()
        cb2.assert_called_once()


# ---------------------------------------------------------------------------
# Config integration
# ---------------------------------------------------------------------------

class TestConfigIntegration:
    def test_default_config_values(self):
        config = Config(auto_discover=False, load_env=False)
        assert config.get("detection.bot_detection_tests") is True
        assert config.get("browser.headless") is True
        assert config.get("session.max_concurrent_sessions") == 5

    def test_config_override(self):
        config = Config(auto_discover=False, load_env=False)
        config.set("browser.headless", False)
        engine = AuditEngine(config)
        assert engine.config.get("browser.headless") is False

    def test_config_validation_warnings(self):
        config = Config(auto_discover=False, load_env=False)
        config.set("general.parallel_workers", 0)
        warnings = config.validate()
        assert any("parallel_workers" in w for w in warnings)
