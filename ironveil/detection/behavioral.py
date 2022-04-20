"""
IronVeil Behavioral Analysis Testing

Tests a platform's ability to detect automated behavior by analyzing
mouse movement patterns, click timing distributions, scroll behavior,
keystroke dynamics, and session-level behavioral signals.
"""

import logging
import math
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ironveil.detection.behavioral")


@dataclass
class MouseEvent:
    """A recorded mouse movement or click event."""
    x: float
    y: float
    timestamp: float
    event_type: str = "move"  # move, click, dblclick

    @property
    def position(self) -> Tuple[float, float]:
        return (self.x, self.y)


@dataclass
class KeystrokeEvent:
    """A recorded keystroke event with timing."""
    key: str
    press_time: float
    release_time: float

    @property
    def dwell_time(self) -> float:
        return self.release_time - self.press_time


@dataclass
class BehavioralMetrics:
    """Aggregated behavioral metrics from a session."""
    mouse_speed_mean: float = 0.0
    mouse_speed_std: float = 0.0
    mouse_straightness_ratio: float = 0.0
    click_interval_mean: float = 0.0
    click_interval_std: float = 0.0
    scroll_speed_mean: float = 0.0
    keystroke_dwell_mean: float = 0.0
    keystroke_dwell_std: float = 0.0
    keystroke_flight_mean: float = 0.0
    keystroke_flight_std: float = 0.0
    session_idle_ratio: float = 0.0
    total_events: int = 0
    anomaly_score: float = 0.0


def _euclidean(p1: Tuple[float, float], p2: Tuple[float, float]) -> float:
    """Euclidean distance between two 2D points."""
    return math.sqrt((p2[0] - p1[0]) ** 2 + (p2[1] - p1[1]) ** 2)


def _path_length(points: List[Tuple[float, float]]) -> float:
    """Total path length through a series of points."""
    if len(points) < 2:
        return 0.0
    return sum(_euclidean(points[i], points[i + 1]) for i in range(len(points) - 1))


def _curvature(points: List[Tuple[float, float]]) -> List[float]:
    """Approximate curvature at each interior point."""
    curvatures: List[float] = []
    for i in range(1, len(points) - 1):
        a = _euclidean(points[i - 1], points[i])
        b = _euclidean(points[i], points[i + 1])
        c = _euclidean(points[i - 1], points[i + 1])
        if a * b == 0:
            curvatures.append(0.0)
            continue
        cos_angle = max(-1.0, min(1.0, (a**2 + b**2 - c**2) / (2 * a * b)))
        angle = math.acos(cos_angle)
        curvatures.append(angle)
    return curvatures


class MouseAnalyzer:
    """Analyzes mouse movement patterns for signs of automation."""

    # Thresholds derived from real human behavior studies
    HUMAN_SPEED_RANGE = (50.0, 2500.0)  # px/sec
    HUMAN_STRAIGHTNESS_MIN = 0.6
    HUMAN_CURVATURE_STD_MIN = 0.05
    BOT_CONSTANT_SPEED_THRESHOLD = 0.05  # relative std dev

    def __init__(self) -> None:
        self._events: List[MouseEvent] = []

    def add_event(self, event: MouseEvent) -> None:
        self._events.append(event)

    def load_events(self, events: List[MouseEvent]) -> None:
        self._events = list(events)

    def analyze_movement(self) -> Dict[str, Any]:
        """Analyze recorded mouse events for bot-like patterns."""
        moves = [e for e in self._events if e.event_type == "move"]
        if len(moves) < 3:
            return {"error": "Insufficient mouse data", "bot_probability": 0.5}

        # Speed analysis
        speeds = self._compute_speeds(moves)
        speed_mean = statistics.mean(speeds) if speeds else 0.0
        speed_std = statistics.stdev(speeds) if len(speeds) >= 2 else 0.0

        # Straightness: direct distance vs path length
        points = [e.position for e in moves]
        direct = _euclidean(points[0], points[-1])
        path = _path_length(points)
        straightness = direct / path if path > 0 else 1.0

        # Curvature analysis
        curvatures = _curvature(points)
        curv_std = statistics.stdev(curvatures) if len(curvatures) >= 2 else 0.0

        # Bot probability scoring
        bot_score = 0.0

        # Constant speed is a strong bot indicator
        if speed_mean > 0 and (speed_std / speed_mean) < self.BOT_CONSTANT_SPEED_THRESHOLD:
            bot_score += 0.35
        # Perfectly straight lines
        if straightness > 0.98:
            bot_score += 0.25
        # No curvature variation
        if curv_std < self.HUMAN_CURVATURE_STD_MIN:
            bot_score += 0.2
        # Speed outside human range
        if speed_mean < self.HUMAN_SPEED_RANGE[0] or speed_mean > self.HUMAN_SPEED_RANGE[1]:
            bot_score += 0.2

        return {
            "event_count": len(moves),
            "speed_mean": round(speed_mean, 2),
            "speed_std": round(speed_std, 2),
            "straightness": round(straightness, 4),
            "curvature_std": round(curv_std, 4),
            "bot_probability": round(min(1.0, bot_score), 3),
        }

    def _compute_speeds(self, moves: List[MouseEvent]) -> List[float]:
        speeds: List[float] = []
        for i in range(1, len(moves)):
            dt = moves[i].timestamp - moves[i - 1].timestamp
            if dt <= 0:
                continue
            dist = _euclidean(moves[i - 1].position, moves[i].position)
            speeds.append(dist / dt)
        return speeds


class ClickTimingAnalyzer:
    """Analyzes click timing distributions."""

    HUMAN_INTERVAL_RANGE = (0.15, 10.0)  # seconds
    BOT_REGULARITY_THRESHOLD = 0.02  # coefficient of variation

    def __init__(self) -> None:
        self._clicks: List[float] = []

    def add_click(self, timestamp: float) -> None:
        self._clicks.append(timestamp)

    def analyze(self) -> Dict[str, Any]:
        if len(self._clicks) < 3:
            return {"error": "Insufficient click data", "bot_probability": 0.5}

        self._clicks.sort()
        intervals = [self._clicks[i + 1] - self._clicks[i] for i in range(len(self._clicks) - 1)]
        mean_interval = statistics.mean(intervals)
        std_interval = statistics.stdev(intervals) if len(intervals) >= 2 else 0.0
        cv = std_interval / mean_interval if mean_interval > 0 else 0.0

        bot_score = 0.0
        if cv < self.BOT_REGULARITY_THRESHOLD:
            bot_score += 0.5
        if mean_interval < self.HUMAN_INTERVAL_RANGE[0]:
            bot_score += 0.3
        if all(abs(iv - mean_interval) < 0.01 for iv in intervals):
            bot_score += 0.2

        return {
            "click_count": len(self._clicks),
            "interval_mean": round(mean_interval, 4),
            "interval_std": round(std_interval, 4),
            "coefficient_of_variation": round(cv, 4),
            "bot_probability": round(min(1.0, bot_score), 3),
        }


class KeystrokeAnalyzer:
    """Analyzes keystroke dynamics for bot detection."""

    def __init__(self) -> None:
        self._events: List[KeystrokeEvent] = []

    def add_event(self, event: KeystrokeEvent) -> None:
        self._events.append(event)

    def analyze(self) -> Dict[str, Any]:
        if len(self._events) < 5:
            return {"error": "Insufficient keystroke data", "bot_probability": 0.5}

        dwells = [e.dwell_time for e in self._events]
        flights: List[float] = []
        for i in range(1, len(self._events)):
            flight = self._events[i].press_time - self._events[i - 1].release_time
            if flight >= 0:
                flights.append(flight)

        dwell_mean = statistics.mean(dwells)
        dwell_std = statistics.stdev(dwells) if len(dwells) >= 2 else 0.0
        flight_mean = statistics.mean(flights) if flights else 0.0
        flight_std = statistics.stdev(flights) if len(flights) >= 2 else 0.0

        bot_score = 0.0
        if dwell_std < 0.005:
            bot_score += 0.4
        if flight_std < 0.005:
            bot_score += 0.3
        if dwell_mean < 0.02:
            bot_score += 0.3

        return {
            "keystroke_count": len(self._events),
            "dwell_mean": round(dwell_mean, 5),
            "dwell_std": round(dwell_std, 5),
            "flight_mean": round(flight_mean, 5),
            "flight_std": round(flight_std, 5),
            "bot_probability": round(min(1.0, bot_score), 3),
        }


class BehavioralAnalyzer:
    """Orchestrator for all behavioral analysis modules."""

    def __init__(self, browser: Any) -> None:
        self.browser = browser
        self.mouse = MouseAnalyzer()
        self.clicks = ClickTimingAnalyzer()
        self.keystrokes = KeystrokeAnalyzer()

    def inject_collectors(self) -> None:
        """Inject JavaScript event collectors into the page."""
        js = """
        window.__iv_events = {mouse: [], clicks: [], keys: []};
        document.addEventListener('mousemove', e => {
            window.__iv_events.mouse.push({x: e.clientX, y: e.clientY, t: performance.now()});
        });
        document.addEventListener('click', e => {
            window.__iv_events.clicks.push(performance.now());
        });
        document.addEventListener('keydown', e => {
            window.__iv_events.keys.push({key: e.key, t: performance.now(), type: 'down'});
        });
        document.addEventListener('keyup', e => {
            window.__iv_events.keys.push({key: e.key, t: performance.now(), type: 'up'});
        });
        """
        self.browser.execute_js(js)
        logger.debug("Behavioral event collectors injected")

    def collect_events(self) -> Dict[str, int]:
        """Pull collected events from the browser."""
        raw = self.browser.execute_js("return JSON.stringify(window.__iv_events || {})")
        import json
        data = json.loads(raw) if isinstance(raw, str) else (raw or {})

        for m in data.get("mouse", []):
            self.mouse.add_event(MouseEvent(m["x"], m["y"], m["t"] / 1000))
        for c in data.get("clicks", []):
            self.clicks.add_click(c / 1000)

        return {
            "mouse_events": len(data.get("mouse", [])),
            "click_events": len(data.get("clicks", [])),
            "key_events": len(data.get("keys", [])),
        }

    def full_analysis(self) -> Dict[str, Any]:
        """Run all behavioral analyzers and produce a combined report."""
        mouse_report = self.mouse.analyze_movement()
        click_report = self.clicks.analyze()
        keystroke_report = self.keystrokes.analyze()

        # Combined score
        scores = [
            mouse_report.get("bot_probability", 0.5),
            click_report.get("bot_probability", 0.5),
            keystroke_report.get("bot_probability", 0.5),
        ]
        combined = statistics.mean(scores)

        return {
            "mouse": mouse_report,
            "clicks": click_report,
            "keystrokes": keystroke_report,
            "combined_bot_probability": round(combined, 3),
            "assessment": "LIKELY_BOT" if combined > 0.6 else "LIKELY_HUMAN" if combined < 0.3 else "INCONCLUSIVE",
        }
