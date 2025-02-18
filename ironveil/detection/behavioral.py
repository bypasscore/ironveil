"""
IronVeil Behavioral Analysis Testing

Tests a platform's ability to detect automated behavior by analyzing
mouse movement patterns, click timing distributions, scroll behavior,
keystroke dynamics, and session-level behavioral signals.

Includes ML-based pattern detection using feature extraction and
statistical learning for improved bot/human classification.
"""

import logging
import math
import random
import statistics
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

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

        # ML-enhanced classification
        ml_classifier = MLPatternDetector()
        ml_result = ml_classifier.classify(
            mouse_events=self.mouse._events,
            click_timestamps=[],
            keystroke_events=self.keystrokes._events,
        )

        # Combined score: weighted average of heuristic and ML
        heuristic_scores = [
            mouse_report.get("bot_probability", 0.5),
            click_report.get("bot_probability", 0.5),
            keystroke_report.get("bot_probability", 0.5),
        ]
        heuristic_combined = statistics.mean(heuristic_scores)
        ml_score = ml_result.get("bot_probability", 0.5)

        # 60% ML, 40% heuristic when ML has sufficient data
        if ml_result.get("sufficient_data", False):
            combined = 0.6 * ml_score + 0.4 * heuristic_combined
        else:
            combined = heuristic_combined

        return {
            "mouse": mouse_report,
            "clicks": click_report,
            "keystrokes": keystroke_report,
            "ml_classification": ml_result,
            "combined_bot_probability": round(combined, 3),
            "assessment": "LIKELY_BOT" if combined > 0.6 else "LIKELY_HUMAN" if combined < 0.3 else "INCONCLUSIVE",
        }


class MLPatternDetector:
    """ML-based behavioral pattern detection.

    Uses feature extraction from mouse, click, and keystroke data
    combined with a lightweight statistical model (Mahalanobis distance
    from known human behavior distributions) for classification.
    """

    # Reference human behavior distributions (mean, std) derived from studies
    HUMAN_FEATURES: Dict[str, Tuple[float, float]] = {
        "mouse_speed_mean": (450.0, 200.0),
        "mouse_speed_std": (180.0, 80.0),
        "mouse_acceleration_mean": (1200.0, 600.0),
        "mouse_jerk_mean": (5000.0, 3000.0),
        "mouse_curvature_mean": (1.8, 0.5),
        "mouse_curvature_std": (0.6, 0.3),
        "mouse_straightness": (0.75, 0.12),
        "click_interval_cv": (0.45, 0.15),
        "keystroke_dwell_cv": (0.35, 0.12),
        "keystroke_flight_cv": (0.50, 0.18),
    }

    def extract_features(
        self,
        mouse_events: List[MouseEvent],
        click_timestamps: List[float],
        keystroke_events: List[KeystrokeEvent],
    ) -> Dict[str, float]:
        """Extract behavioral features from raw event data."""
        features: Dict[str, float] = {}

        # Mouse features
        moves = [e for e in mouse_events if e.event_type == "move"]
        if len(moves) >= 5:
            speeds = self._compute_speeds(moves)
            accelerations = self._compute_accelerations(speeds, moves)
            points = [(e.x, e.y) for e in moves]
            curvatures = _curvature(points) if len(points) >= 3 else []

            features["mouse_speed_mean"] = float(np.mean(speeds)) if speeds else 0.0
            features["mouse_speed_std"] = float(np.std(speeds)) if speeds else 0.0
            features["mouse_acceleration_mean"] = float(np.mean(np.abs(accelerations))) if len(accelerations) > 0 else 0.0
            features["mouse_jerk_mean"] = float(np.mean(np.abs(np.diff(accelerations)))) if len(accelerations) > 1 else 0.0
            features["mouse_curvature_mean"] = float(np.mean(curvatures)) if curvatures else 0.0
            features["mouse_curvature_std"] = float(np.std(curvatures)) if curvatures else 0.0

            direct = _euclidean(points[0], points[-1])
            path = _path_length(points)
            features["mouse_straightness"] = direct / path if path > 0 else 1.0

        # Click features
        if len(click_timestamps) >= 3:
            sorted_clicks = sorted(click_timestamps)
            intervals = np.diff(sorted_clicks)
            mean_iv = float(np.mean(intervals))
            features["click_interval_cv"] = float(np.std(intervals) / mean_iv) if mean_iv > 0 else 0.0

        # Keystroke features
        if len(keystroke_events) >= 5:
            dwells = np.array([e.dwell_time for e in keystroke_events])
            flights = []
            for i in range(1, len(keystroke_events)):
                f = keystroke_events[i].press_time - keystroke_events[i - 1].release_time
                if f >= 0:
                    flights.append(f)
            flights_arr = np.array(flights) if flights else np.array([0.0])

            dwell_mean = float(np.mean(dwells))
            features["keystroke_dwell_cv"] = float(np.std(dwells) / dwell_mean) if dwell_mean > 0 else 0.0
            flight_mean = float(np.mean(flights_arr))
            features["keystroke_flight_cv"] = float(np.std(flights_arr) / flight_mean) if flight_mean > 0 else 0.0

        return features

    def classify(
        self,
        mouse_events: List[MouseEvent],
        click_timestamps: List[float],
        keystroke_events: List[KeystrokeEvent],
    ) -> Dict[str, Any]:
        """Classify behavior as bot or human using ML features."""
        features = self.extract_features(mouse_events, click_timestamps, keystroke_events)

        if len(features) < 3:
            return {
                "bot_probability": 0.5,
                "sufficient_data": False,
                "features_extracted": len(features),
                "method": "insufficient_data",
            }

        # Compute Mahalanobis-like distance from human distribution
        distances: List[float] = []
        for feat_name, feat_val in features.items():
            if feat_name in self.HUMAN_FEATURES:
                human_mean, human_std = self.HUMAN_FEATURES[feat_name]
                if human_std > 0:
                    z = abs(feat_val - human_mean) / human_std
                    distances.append(z)

        if not distances:
            return {
                "bot_probability": 0.5,
                "sufficient_data": False,
                "features_extracted": len(features),
                "method": "no_reference_features",
            }

        avg_distance = float(np.mean(distances))
        max_distance = float(np.max(distances))

        # Sigmoid mapping: higher distance from human = higher bot probability
        bot_prob = 1.0 / (1.0 + math.exp(-0.8 * (avg_distance - 2.0)))

        # Boost if any feature is extremely anomalous
        if max_distance > 5.0:
            bot_prob = min(1.0, bot_prob + 0.15)

        return {
            "bot_probability": round(bot_prob, 3),
            "sufficient_data": True,
            "features_extracted": len(features),
            "avg_z_distance": round(avg_distance, 3),
            "max_z_distance": round(max_distance, 3),
            "method": "mahalanobis_sigmoid",
            "features": {k: round(v, 4) for k, v in features.items()},
        }

    @staticmethod
    def _compute_speeds(moves: List[MouseEvent]) -> List[float]:
        speeds: List[float] = []
        for i in range(1, len(moves)):
            dt = moves[i].timestamp - moves[i - 1].timestamp
            if dt <= 0:
                continue
            dist = _euclidean(moves[i - 1].position, moves[i].position)
            speeds.append(dist / dt)
        return speeds

    @staticmethod
    def _compute_accelerations(speeds: List[float], moves: List[MouseEvent]) -> np.ndarray:
        if len(speeds) < 2:
            return np.array([])
        speed_arr = np.array(speeds)
        dt_arr = np.array([
            moves[i + 1].timestamp - moves[i].timestamp
            for i in range(1, min(len(moves) - 1, len(speeds)))
        ])
        dt_arr = np.where(dt_arr <= 0, 1e-6, dt_arr)
        min_len = min(len(speed_arr) - 1, len(dt_arr))
        if min_len <= 0:
            return np.array([])
        return np.diff(speed_arr[:min_len + 1]) / dt_arr[:min_len]
