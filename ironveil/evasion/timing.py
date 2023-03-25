"""
IronVeil Timing Evasion

Generates human-like timing patterns for audit operations: randomized
delays between actions, session length variation, break patterns,
circadian rhythm simulation, and rate-limit-aware request scheduling.
"""

import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("ironveil.evasion.timing")


@dataclass
class TimingProfile:
    """Describes a timing persona for an audit session."""
    name: str = "default"
    min_action_delay: float = 0.3
    max_action_delay: float = 3.0
    page_read_wpm: float = 250.0
    session_length_minutes: Tuple[float, float] = (15.0, 90.0)
    break_interval_minutes: Tuple[float, float] = (10.0, 30.0)
    break_duration_minutes: Tuple[float, float] = (2.0, 10.0)
    active_hours: Tuple[int, int] = (8, 23)  # 24h format
    request_burst_max: int = 5
    burst_cooldown_seconds: Tuple[float, float] = (2.0, 8.0)


# Pre-defined profiles
PROFILES: Dict[str, TimingProfile] = {
    "casual": TimingProfile(
        name="casual",
        min_action_delay=0.8,
        max_action_delay=5.0,
        page_read_wpm=200.0,
        session_length_minutes=(10.0, 45.0),
        break_interval_minutes=(8.0, 20.0),
        break_duration_minutes=(3.0, 15.0),
        request_burst_max=3,
    ),
    "focused": TimingProfile(
        name="focused",
        min_action_delay=0.3,
        max_action_delay=2.0,
        page_read_wpm=350.0,
        session_length_minutes=(30.0, 120.0),
        break_interval_minutes=(20.0, 45.0),
        break_duration_minutes=(1.0, 5.0),
        request_burst_max=8,
    ),
    "slow": TimingProfile(
        name="slow",
        min_action_delay=1.5,
        max_action_delay=8.0,
        page_read_wpm=150.0,
        session_length_minutes=(5.0, 30.0),
        break_interval_minutes=(5.0, 15.0),
        break_duration_minutes=(5.0, 20.0),
        request_burst_max=2,
    ),
    "aggressive": TimingProfile(
        name="aggressive",
        min_action_delay=0.1,
        max_action_delay=0.8,
        page_read_wpm=500.0,
        session_length_minutes=(60.0, 240.0),
        break_interval_minutes=(30.0, 60.0),
        break_duration_minutes=(0.5, 2.0),
        request_burst_max=15,
        burst_cooldown_seconds=(0.5, 2.0),
    ),
}


def get_profile(name: str) -> TimingProfile:
    """Retrieve a named timing profile or raise KeyError."""
    if name not in PROFILES:
        available = ", ".join(PROFILES.keys())
        raise KeyError(f"Unknown timing profile '{name}'. Available: {available}")
    return PROFILES[name]


class DelayGenerator:
    """Generates randomized delays following configurable distributions."""

    def __init__(self, profile: Optional[TimingProfile] = None) -> None:
        self.profile = profile or PROFILES["casual"]

    def action_delay(self) -> float:
        """Random delay between user actions (log-normal distribution)."""
        mu = math.log(
            (self.profile.min_action_delay + self.profile.max_action_delay) / 2
        )
        sigma = 0.5
        delay = random.lognormvariate(mu, sigma)
        return max(self.profile.min_action_delay,
                   min(self.profile.max_action_delay, delay))

    def page_read_delay(self, word_count: int) -> float:
        """Estimate reading time based on word count and WPM with variation."""
        base_time = word_count / self.profile.page_read_wpm * 60
        # Add variation +-30%
        return base_time * random.uniform(0.7, 1.3)

    def click_delay(self) -> float:
        """Short delay simulating reaction time before a click."""
        return random.uniform(0.1, 0.4)

    def form_field_delay(self) -> float:
        """Delay between filling form fields (tab/click + think)."""
        return random.uniform(0.5, 2.5)

    def page_transition_delay(self) -> float:
        """Delay after navigating to a new page (orientation time)."""
        return random.uniform(1.0, 4.0)


class SessionTimer:
    """Tracks session timing and enforces break patterns."""

    def __init__(self, profile: Optional[TimingProfile] = None) -> None:
        self.profile = profile or PROFILES["casual"]
        self._session_start: float = 0.0
        self._session_target_length: float = 0.0
        self._last_break: float = 0.0
        self._next_break_at: float = 0.0
        self._total_active_time: float = 0.0
        self._total_break_time: float = 0.0
        self._action_count: int = 0
        self._active = False

    def start(self) -> None:
        """Start or restart the session timer."""
        self._session_start = time.time()
        self._last_break = self._session_start
        self._session_target_length = random.uniform(
            *self.profile.session_length_minutes
        ) * 60
        self._next_break_at = self._session_start + random.uniform(
            *self.profile.break_interval_minutes
        ) * 60
        self._active = True
        logger.info(
            "Session timer started (target length: %.0f min, first break at: %.0f min)",
            self._session_target_length / 60,
            (self._next_break_at - self._session_start) / 60,
        )

    def tick(self) -> None:
        """Call after each action to update counters."""
        self._action_count += 1

    @property
    def elapsed(self) -> float:
        """Seconds since session start."""
        if self._session_start == 0:
            return 0.0
        return time.time() - self._session_start

    @property
    def should_take_break(self) -> bool:
        """Whether it's time for a break."""
        return self._active and time.time() >= self._next_break_at

    @property
    def should_end_session(self) -> bool:
        """Whether the session has exceeded its target length."""
        return self._active and self.elapsed >= self._session_target_length

    def take_break(self) -> float:
        """Calculate break duration, update timers. Returns seconds to wait."""
        duration = random.uniform(*self.profile.break_duration_minutes) * 60
        self._total_break_time += duration
        self._last_break = time.time()
        self._next_break_at = time.time() + duration + random.uniform(
            *self.profile.break_interval_minutes
        ) * 60
        logger.info("Break scheduled: %.0f seconds", duration)
        return duration

    def summary(self) -> Dict[str, Any]:
        return {
            "active": self._active,
            "elapsed_minutes": round(self.elapsed / 60, 1),
            "target_length_minutes": round(self._session_target_length / 60, 1),
            "total_break_time_minutes": round(self._total_break_time / 60, 1),
            "action_count": self._action_count,
            "should_break": self.should_take_break,
            "should_end": self.should_end_session,
        }


class RateLimitAwareScheduler:
    """Schedules requests to stay under detected or configured rate limits."""

    def __init__(
        self,
        max_requests_per_minute: int = 30,
        burst_size: int = 5,
        burst_cooldown: Tuple[float, float] = (2.0, 5.0),
    ) -> None:
        self.max_rpm = max_requests_per_minute
        self.burst_size = burst_size
        self.burst_cooldown = burst_cooldown
        self._request_times: List[float] = []
        self._burst_count = 0

    def wait_if_needed(self) -> float:
        """Block until it's safe to send another request. Returns wait time."""
        now = time.time()
        # Clean old entries
        cutoff = now - 60
        self._request_times = [t for t in self._request_times if t > cutoff]

        waited = 0.0

        # Check rate limit
        if len(self._request_times) >= self.max_rpm:
            oldest = self._request_times[0]
            wait = 60 - (now - oldest) + random.uniform(0.5, 2.0)
            if wait > 0:
                logger.debug("Rate limit approaching, waiting %.1fs", wait)
                time.sleep(wait)
                waited += wait

        # Burst management
        self._burst_count += 1
        if self._burst_count >= self.burst_size:
            cooldown = random.uniform(*self.burst_cooldown)
            logger.debug("Burst cooldown: %.1fs", cooldown)
            time.sleep(cooldown)
            waited += cooldown
            self._burst_count = 0

        self._request_times.append(time.time())
        return waited

    @property
    def current_rpm(self) -> float:
        """Requests in the last 60 seconds."""
        cutoff = time.time() - 60
        return sum(1 for t in self._request_times if t > cutoff)

    def reset(self) -> None:
        self._request_times.clear()
        self._burst_count = 0


class TimingEvasion:
    """Orchestrates all timing evasion components."""

    def __init__(
        self,
        profile: Optional[TimingProfile] = None,
        max_rpm: int = 30,
    ) -> None:
        self.profile = profile or PROFILES["casual"]
        self.delays = DelayGenerator(self.profile)
        self.session = SessionTimer(self.profile)
        self.scheduler = RateLimitAwareScheduler(
            max_requests_per_minute=max_rpm,
            burst_size=self.profile.request_burst_max,
            burst_cooldown=self.profile.burst_cooldown_seconds,
        )

    def start_session(self) -> None:
        self.session.start()

    def before_action(self) -> float:
        """Call before each audit action. Returns total time waited."""
        total_wait = 0.0

        # Check if session should end
        if self.session.should_end_session:
            logger.info("Session target length reached")

        # Check if break needed
        if self.session.should_take_break:
            break_time = self.session.take_break()
            logger.info("Taking a break for %.0f seconds", break_time)
            time.sleep(break_time)
            total_wait += break_time

        # Action delay
        delay = self.delays.action_delay()
        time.sleep(delay)
        total_wait += delay

        # Rate limit
        total_wait += self.scheduler.wait_if_needed()

        self.session.tick()
        return total_wait

    def summary(self) -> Dict[str, Any]:
        return {
            "profile": self.profile.name,
            "session": self.session.summary(),
            "current_rpm": self.scheduler.current_rpm,
        }
