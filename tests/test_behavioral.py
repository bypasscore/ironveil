"""
Tests for ironveil.detection.behavioral

Validates mouse movement analysis, click timing analysis, keystroke
dynamics analysis, and the combined behavioral analyzer.
"""

import statistics
import time

import pytest

from ironveil.detection.behavioral import (
    BehavioralMetrics,
    ClickTimingAnalyzer,
    KeystrokeAnalyzer,
    KeystrokeEvent,
    MouseAnalyzer,
    MouseEvent,
    _curvature,
    _euclidean,
    _path_length,
)


# ---------------------------------------------------------------------------
# Geometry helpers
# ---------------------------------------------------------------------------

class TestGeometryHelpers:
    def test_euclidean_zero(self):
        assert _euclidean((0, 0), (0, 0)) == 0.0

    def test_euclidean_unit(self):
        assert _euclidean((0, 0), (3, 4)) == pytest.approx(5.0)

    def test_path_length_single_point(self):
        assert _path_length([(1, 2)]) == 0.0

    def test_path_length_straight(self):
        points = [(0, 0), (3, 0), (6, 0)]
        assert _path_length(points) == pytest.approx(6.0)

    def test_path_length_triangle(self):
        points = [(0, 0), (3, 0), (3, 4)]
        assert _path_length(points) == pytest.approx(7.0)

    def test_curvature_straight_line(self):
        points = [(0, 0), (1, 0), (2, 0), (3, 0)]
        curvatures = _curvature(points)
        assert len(curvatures) == 2
        for c in curvatures:
            assert c == pytest.approx(3.14159, abs=0.01)  # pi (straight = 180 degrees)

    def test_curvature_right_angle(self):
        points = [(0, 0), (1, 0), (1, 1)]
        curvatures = _curvature(points)
        assert len(curvatures) == 1
        assert curvatures[0] == pytest.approx(1.5708, abs=0.01)  # pi/2


# ---------------------------------------------------------------------------
# MouseAnalyzer
# ---------------------------------------------------------------------------

class TestMouseAnalyzer:
    def _make_linear_events(self, n: int = 50) -> list:
        """Create perfectly linear, constant-speed mouse events (bot-like)."""
        events = []
        for i in range(n):
            events.append(MouseEvent(x=i * 10.0, y=i * 5.0, timestamp=i * 0.02))
        return events

    def _make_human_events(self, n: int = 50) -> list:
        """Create events with variable speed and curvature (human-like)."""
        import random
        random.seed(42)
        events = []
        t = 0.0
        x, y = 100.0, 100.0
        for i in range(n):
            x += random.gauss(8, 3)
            y += random.gauss(4, 5)
            t += random.uniform(0.01, 0.05)
            events.append(MouseEvent(x=x, y=y, timestamp=t))
        return events

    def test_linear_movement_detected_as_bot(self):
        analyzer = MouseAnalyzer()
        analyzer.load_events(self._make_linear_events())
        result = analyzer.analyze_movement()
        assert "bot_probability" in result
        # Linear movement should have high bot probability
        assert result["bot_probability"] >= 0.2

    def test_human_movement_lower_bot_score(self):
        analyzer = MouseAnalyzer()
        analyzer.load_events(self._make_human_events())
        result = analyzer.analyze_movement()
        assert result["bot_probability"] < 0.5

    def test_insufficient_data(self):
        analyzer = MouseAnalyzer()
        analyzer.load_events([MouseEvent(0, 0, 0)])
        result = analyzer.analyze_movement()
        assert "error" in result

    def test_event_count_matches(self):
        events = self._make_linear_events(30)
        analyzer = MouseAnalyzer()
        analyzer.load_events(events)
        result = analyzer.analyze_movement()
        assert result["event_count"] == 30


# ---------------------------------------------------------------------------
# ClickTimingAnalyzer
# ---------------------------------------------------------------------------

class TestClickTimingAnalyzer:
    def test_regular_clicks_detected_as_bot(self):
        """Perfectly regular click intervals -> high bot score."""
        analyzer = ClickTimingAnalyzer()
        for i in range(20):
            analyzer.add_click(i * 0.5)  # exactly 500ms apart
        result = analyzer.analyze()
        assert result["bot_probability"] >= 0.5

    def test_variable_clicks_lower_score(self):
        """Variable intervals -> lower bot score."""
        import random
        random.seed(123)
        analyzer = ClickTimingAnalyzer()
        t = 0.0
        for _ in range(20):
            t += random.uniform(0.3, 2.0)
            analyzer.add_click(t)
        result = analyzer.analyze()
        assert result["bot_probability"] < 0.5

    def test_insufficient_clicks(self):
        analyzer = ClickTimingAnalyzer()
        analyzer.add_click(0.0)
        analyzer.add_click(1.0)
        result = analyzer.analyze()
        assert "error" in result

    def test_click_count_correct(self):
        analyzer = ClickTimingAnalyzer()
        for i in range(10):
            analyzer.add_click(float(i))
        result = analyzer.analyze()
        assert result["click_count"] == 10


# ---------------------------------------------------------------------------
# KeystrokeAnalyzer
# ---------------------------------------------------------------------------

class TestKeystrokeAnalyzer:
    def test_constant_dwell_is_bot(self):
        """Identical dwell times -> likely bot."""
        analyzer = KeystrokeAnalyzer()
        t = 0.0
        for c in "hello world test":
            analyzer.add_event(KeystrokeEvent(key=c, press_time=t, release_time=t + 0.08))
            t += 0.15
        result = analyzer.analyze()
        assert result["bot_probability"] >= 0.3

    def test_variable_dwell_is_human(self):
        """Variable dwell and flight times -> more human-like."""
        import random
        random.seed(99)
        analyzer = KeystrokeAnalyzer()
        t = 0.0
        for c in "testing human keystroke patterns":
            dwell = random.uniform(0.05, 0.2)
            flight = random.uniform(0.05, 0.3)
            analyzer.add_event(KeystrokeEvent(key=c, press_time=t, release_time=t + dwell))
            t += dwell + flight
        result = analyzer.analyze()
        assert result["bot_probability"] < 0.5

    def test_insufficient_keystrokes(self):
        analyzer = KeystrokeAnalyzer()
        analyzer.add_event(KeystrokeEvent("a", 0.0, 0.1))
        result = analyzer.analyze()
        assert "error" in result

    def test_dwell_computation(self):
        event = KeystrokeEvent(key="x", press_time=1.0, release_time=1.15)
        assert event.dwell_time == pytest.approx(0.15)
