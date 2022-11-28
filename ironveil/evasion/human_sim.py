"""
IronVeil Human Behavior Simulation

Generates realistic human-like interactions: Bezier curve mouse movements,
natural typing with variable cadence, scroll patterns, and page-reading
behavior. Used to test how well a platform detects simulated humans.
"""

import logging
import math
import random
import time
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

logger = logging.getLogger("ironveil.evasion.human_sim")


@dataclass
class Point:
    """2D coordinate with optional timestamp."""
    x: float
    y: float
    t: float = 0.0


def _bezier_curve(
    start: Tuple[float, float],
    end: Tuple[float, float],
    control_points: int = 2,
    num_steps: int = 50,
) -> List[Tuple[float, float]]:
    """Generate points along a Bezier curve between start and end.

    Control points are randomly placed to create natural-looking curves
    that mimic human hand movement.
    """
    sx, sy = start
    ex, ey = end
    dx, dy = ex - sx, ey - sy

    # Generate random control points between start and end
    controls: List[Tuple[float, float]] = []
    for i in range(control_points):
        t_pos = (i + 1) / (control_points + 1)
        cx = sx + dx * t_pos + random.gauss(0, abs(dx) * 0.15)
        cy = sy + dy * t_pos + random.gauss(0, abs(dy) * 0.15)
        controls.append((cx, cy))

    all_points = [start] + controls + [end]
    n = len(all_points) - 1

    # De Casteljau's algorithm
    path: List[Tuple[float, float]] = []
    for step in range(num_steps + 1):
        t = step / num_steps
        pts = list(all_points)
        for r in range(n):
            pts = [
                (pts[i][0] * (1 - t) + pts[i + 1][0] * t,
                 pts[i][1] * (1 - t) + pts[i + 1][1] * t)
                for i in range(len(pts) - 1)
            ]
        path.append(pts[0])

    return path


def _add_noise(
    path: List[Tuple[float, float]], amplitude: float = 1.5
) -> List[Tuple[float, float]]:
    """Add small Gaussian noise to simulate hand tremor."""
    noisy: List[Tuple[float, float]] = []
    for x, y in path:
        nx = x + random.gauss(0, amplitude)
        ny = y + random.gauss(0, amplitude)
        noisy.append((nx, ny))
    return noisy


def _assign_timing(
    path: List[Tuple[float, float]],
    total_duration: float,
    easing: str = "ease_in_out",
) -> List[Point]:
    """Assign timestamps to path points using an easing function."""
    n = len(path)
    timed: List[Point] = []
    for i, (x, y) in enumerate(path):
        t_norm = i / max(n - 1, 1)
        if easing == "ease_in_out":
            t_eased = 0.5 * (1 - math.cos(math.pi * t_norm))
        elif easing == "ease_in":
            t_eased = t_norm ** 2
        elif easing == "ease_out":
            t_eased = 1 - (1 - t_norm) ** 2
        else:
            t_eased = t_norm
        timed.append(Point(x, y, t_eased * total_duration))
    return timed


class MouseSimulator:
    """Simulates realistic mouse movement using Bezier curves."""

    def __init__(
        self,
        control_points: int = 3,
        noise_amplitude: float = 1.5,
        easing: str = "ease_in_out",
    ) -> None:
        self.control_points = control_points
        self.noise_amplitude = noise_amplitude
        self.easing = easing

    def generate_path(
        self,
        start: Tuple[float, float],
        end: Tuple[float, float],
        duration: Optional[float] = None,
        steps: int = 60,
    ) -> List[Point]:
        """Generate a human-like mouse path between two points."""
        dist = math.sqrt((end[0] - start[0]) ** 2 + (end[1] - start[1]) ** 2)
        if duration is None:
            # Human movement time: Fitts' law approximation
            duration = 0.2 + 0.15 * math.log2(max(dist, 1) / 10 + 1)
            duration *= random.uniform(0.85, 1.15)

        raw = _bezier_curve(start, end, self.control_points, steps)
        noisy = _add_noise(raw, self.noise_amplitude)
        timed = _assign_timing(noisy, duration, self.easing)

        logger.debug(
            "Mouse path: (%.0f,%.0f)->(%.0f,%.0f), %d points, %.2fs",
            start[0], start[1], end[0], end[1], len(timed), duration,
        )
        return timed

    def generate_idle_jitter(
        self, center: Tuple[float, float], duration: float = 2.0, frequency: float = 5.0
    ) -> List[Point]:
        """Small jitter movements while the 'user' is idle over a spot."""
        points: List[Point] = []
        num_points = int(duration * frequency)
        for i in range(num_points):
            x = center[0] + random.gauss(0, 2.0)
            y = center[1] + random.gauss(0, 2.0)
            t = (i / frequency)
            points.append(Point(x, y, t))
        return points


class TypingSimulator:
    """Simulates natural human typing with variable cadence."""

    # WPM -> chars per second (assuming 5 chars per word)
    WPM_TO_CPS = 5.0 / 60.0

    def __init__(
        self,
        wpm_range: Tuple[int, int] = (45, 85),
        error_rate: float = 0.02,
        think_pause_chance: float = 0.05,
    ) -> None:
        self.wpm_range = wpm_range
        self.error_rate = error_rate
        self.think_pause_chance = think_pause_chance

    def generate_keystrokes(self, text: str) -> List[Tuple[str, float, float]]:
        """Generate (key, press_time, release_time) tuples for typing *text*."""
        wpm = random.uniform(*self.wpm_range)
        base_interval = 1.0 / (wpm * self.WPM_TO_CPS)

        events: List[Tuple[str, float, float]] = []
        current_time = 0.0

        for i, char in enumerate(text):
            # Interval variation
            interval = base_interval * random.lognormvariate(0, 0.25)

            # Longer pause at word boundaries
            if char == " ":
                interval *= random.uniform(1.2, 2.0)

            # Occasional thinking pause
            if random.random() < self.think_pause_chance:
                interval += random.uniform(0.3, 1.5)

            # Dwell time (key hold duration)
            dwell = random.uniform(0.05, 0.15)

            # Simulate occasional typo + backspace
            if random.random() < self.error_rate and char.isalpha():
                wrong_key = chr(ord(char) + random.choice([-1, 1]))
                press = current_time + interval
                release = press + dwell
                events.append((wrong_key, press, release))
                current_time = release

                # Pause before correction
                pause = random.uniform(0.2, 0.6)
                press = current_time + pause
                release = press + random.uniform(0.04, 0.1)
                events.append(("Backspace", press, release))
                current_time = release

            press = current_time + interval
            release = press + dwell
            events.append((char, press, release))
            current_time = release

        logger.debug("Generated %d keystrokes for %d chars at %.0f WPM",
                     len(events), len(text), wpm)
        return events


class ScrollSimulator:
    """Simulates human-like scrolling behavior."""

    def __init__(self, smooth: bool = True) -> None:
        self.smooth = smooth

    def generate_scroll_sequence(
        self,
        total_distance: int,
        direction: str = "down",
    ) -> List[Tuple[int, float]]:
        """Generate a sequence of (scroll_delta, delay) tuples."""
        sign = 1 if direction == "down" else -1
        remaining = abs(total_distance)
        sequence: List[Tuple[int, float]] = []

        while remaining > 0:
            if self.smooth:
                chunk = random.randint(40, 120)
            else:
                chunk = random.randint(80, 300)

            chunk = min(chunk, remaining)

            # Variable delay between scroll events
            delay = random.uniform(0.01, 0.06) if self.smooth else random.uniform(0.1, 0.4)

            # Occasional pause (reading)
            if random.random() < 0.08:
                delay += random.uniform(0.5, 3.0)

            sequence.append((chunk * sign, delay))
            remaining -= chunk

        logger.debug("Scroll sequence: %d events, total %dpx %s",
                     len(sequence), total_distance, direction)
        return sequence


class HumanSimulator:
    """Orchestrates all human simulation components."""

    def __init__(
        self,
        browser: Any,
        mouse_control_points: int = 3,
        wpm_range: Tuple[int, int] = (45, 85),
    ) -> None:
        self.browser = browser
        self.mouse = MouseSimulator(control_points=mouse_control_points)
        self.typing = TypingSimulator(wpm_range=wpm_range)
        self.scroll = ScrollSimulator()

    def move_to(self, x: float, y: float, from_pos: Optional[Tuple[float, float]] = None) -> None:
        """Move the mouse to (x, y) with a human-like path."""
        start = from_pos or (random.uniform(100, 500), random.uniform(100, 500))
        path = self.mouse.generate_path(start, (x, y))
        for point in path:
            self.browser.execute_js(
                f"document.dispatchEvent(new MouseEvent('mousemove', "
                f"{{clientX: {point.x}, clientY: {point.y}}}));"
            )
            time.sleep(max(0.001, point.t - (path[0].t if path else 0)))

    def click_at(self, x: float, y: float) -> None:
        """Move to and click at (x, y)."""
        self.move_to(x, y)
        time.sleep(random.uniform(0.05, 0.15))
        self.browser.execute_js(
            f"document.elementFromPoint({x}, {y})?.click();"
        )

    def type_text(self, selector: str, text: str) -> None:
        """Type text into an element with human-like keystrokes."""
        keystrokes = self.typing.generate_keystrokes(text)
        base_time = time.time()
        for key, press_t, release_t in keystrokes:
            wait = press_t - (time.time() - base_time)
            if wait > 0:
                time.sleep(wait)
            if key == "Backspace":
                self.browser.execute_js(
                    f"document.querySelector('{selector}').value = "
                    f"document.querySelector('{selector}').value.slice(0, -1);"
                )
            else:
                self.browser.execute_js(
                    f"document.querySelector('{selector}').value += '{key}';"
                )

    def scroll_page(self, distance: int = 500, direction: str = "down") -> None:
        """Scroll the page with human-like behavior."""
        sequence = self.scroll.generate_scroll_sequence(distance, direction)
        for delta, delay in sequence:
            self.browser.execute_js(f"window.scrollBy(0, {delta});")
            time.sleep(delay)

    def random_pause(self, min_sec: float = 0.5, max_sec: float = 3.0) -> None:
        """Simulate a natural pause (reading, thinking)."""
        pause = random.uniform(min_sec, max_sec)
        time.sleep(pause)
