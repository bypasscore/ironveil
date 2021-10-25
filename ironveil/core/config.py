"""
IronVeil Configuration System

YAML-based configuration loading with environment variable overrides,
defaults management, and validation for audit parameters.
"""

import os
import copy
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml
from dotenv import load_dotenv

logger = logging.getLogger("ironveil.config")

# Default config search paths
DEFAULT_CONFIG_PATHS: List[str] = [
    "./config/default.yaml",
    "./ironveil.yaml",
    os.path.expanduser("~/.ironveil/config.yaml"),
    "/etc/ironveil/config.yaml",
]

# Environment variable prefix
ENV_PREFIX = "IRONVEIL_"


class ConfigValidationError(Exception):
    """Raised when configuration values fail validation."""
    pass


class ConfigNotFoundError(FileNotFoundError):
    """Raised when no configuration file can be located."""
    pass


def _deep_merge(base: Dict, override: Dict) -> Dict:
    """Recursively merge *override* into *base*, returning a new dict."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = copy.deepcopy(value)
    return merged


def _set_nested(data: Dict, keys: List[str], value: Any) -> None:
    """Set a value in a nested dict using a list of keys."""
    for key in keys[:-1]:
        data = data.setdefault(key, {})
    data[keys[-1]] = value


def _cast_env_value(value: str) -> Union[str, int, float, bool]:
    """Attempt to cast an env-var string to a native Python type."""
    if value.lower() in ("true", "yes", "1"):
        return True
    if value.lower() in ("false", "no", "0"):
        return False
    try:
        return int(value)
    except ValueError:
        pass
    try:
        return float(value)
    except ValueError:
        pass
    return value


class Config:
    """Central configuration object for IronVeil.

    Load order (later wins):
        1. Built-in defaults
        2. YAML file(s)
        3. Environment variables prefixed with ``IRONVEIL_``
        4. Programmatic overrides via :meth:`set`
    """

    BUILTIN_DEFAULTS: Dict[str, Any] = {
        "general": {
            "project_name": "Untitled Audit",
            "output_dir": "./reports",
            "log_level": "INFO",
            "parallel_workers": 4,
        },
        "session": {
            "proxy_rotation": True,
            "proxy_list_file": None,
            "fingerprint_rotation": True,
            "max_concurrent_sessions": 5,
            "session_timeout": 300,
            "cookie_persistence": True,
        },
        "detection": {
            "bot_detection_tests": True,
            "behavioral_analysis": True,
            "fingerprint_analysis": True,
            "captcha_analysis": True,
        },
        "evasion": {
            "human_simulation": True,
            "fingerprint_spoofing": True,
            "timing_evasion": True,
            "mouse_bezier_points": 12,
            "typing_wpm_range": [45, 85],
        },
        "platform": {
            "api_probing": True,
            "integrity_checks": True,
            "rate_limit_test_requests": 100,
            "rng_sample_size": 10000,
        },
        "reporting": {
            "html_report": True,
            "json_export": True,
            "include_screenshots": True,
            "risk_score_threshold": 3.0,
        },
        "browser": {
            "engine": "playwright",
            "headless": True,
            "viewport_width": 1920,
            "viewport_height": 1080,
            "user_agent": None,
        },
    }

    def __init__(
        self,
        config_path: Optional[str] = None,
        load_env: bool = True,
        auto_discover: bool = True,
    ) -> None:
        self._data: Dict[str, Any] = copy.deepcopy(self.BUILTIN_DEFAULTS)
        self._source_file: Optional[str] = None

        if load_env:
            load_dotenv()

        # Load YAML
        if config_path:
            self._load_yaml(config_path)
        elif auto_discover:
            self._auto_discover()

        # Apply env overrides
        if load_env:
            self._apply_env_overrides()

        logger.info("Configuration loaded (source=%s)", self._source_file or "defaults")

    # ------------------------------------------------------------------
    # YAML loading
    # ------------------------------------------------------------------

    def _load_yaml(self, path: str) -> None:
        """Load a single YAML file and merge it into current data."""
        resolved = Path(path).resolve()
        if not resolved.exists():
            raise ConfigNotFoundError(f"Config file not found: {resolved}")
        with open(resolved, "r", encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
        if not isinstance(raw, dict):
            raise ConfigValidationError("YAML root must be a mapping")
        self._data = _deep_merge(self._data, raw)
        self._source_file = str(resolved)
        logger.debug("Merged YAML from %s", resolved)

    def _auto_discover(self) -> None:
        """Try each default path until one is found."""
        for candidate in DEFAULT_CONFIG_PATHS:
            resolved = Path(candidate).resolve()
            if resolved.exists():
                self._load_yaml(str(resolved))
                return
        logger.debug("No config file discovered; using built-in defaults")

    # ------------------------------------------------------------------
    # Environment variable overrides
    # ------------------------------------------------------------------

    def _apply_env_overrides(self) -> None:
        """Read ``IRONVEIL_*`` env vars and apply them.

        Nesting is expressed with double underscores:
            ``IRONVEIL_SESSION__MAX_CONCURRENT_SESSIONS=10``
        maps to ``session.max_concurrent_sessions = 10``.
        """
        for key, value in os.environ.items():
            if not key.startswith(ENV_PREFIX):
                continue
            parts = key[len(ENV_PREFIX):].lower().split("__")
            casted = _cast_env_value(value)
            _set_nested(self._data, parts, casted)
            logger.debug("Env override: %s = %r", ".".join(parts), casted)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, dotpath: str, default: Any = None) -> Any:
        """Retrieve a config value using dot notation (e.g. ``session.proxy_rotation``)."""
        keys = dotpath.split(".")
        node = self._data
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

    def set(self, dotpath: str, value: Any) -> None:
        """Programmatically override a config value."""
        keys = dotpath.split(".")
        _set_nested(self._data, keys, value)

    def section(self, name: str) -> Dict[str, Any]:
        """Return an entire top-level section as a dict."""
        return copy.deepcopy(self._data.get(name, {}))

    def as_dict(self) -> Dict[str, Any]:
        """Return the full configuration as a plain dict."""
        return copy.deepcopy(self._data)

    def validate(self) -> List[str]:
        """Run basic validation rules; return a list of warning messages."""
        warnings: List[str] = []
        if self.get("general.parallel_workers", 1) < 1:
            warnings.append("parallel_workers must be >= 1")
        if self.get("session.session_timeout", 0) < 30:
            warnings.append("session_timeout should be >= 30 seconds")
        rng = self.get("evasion.typing_wpm_range", [45, 85])
        if isinstance(rng, list) and len(rng) == 2 and rng[0] >= rng[1]:
            warnings.append("typing_wpm_range lower bound must be < upper bound")
        if self.get("platform.rng_sample_size", 0) < 100:
            warnings.append("rng_sample_size should be >= 100 for meaningful results")
        return warnings

    @property
    def source_file(self) -> Optional[str]:
        return self._source_file

    def __repr__(self) -> str:
        return f"<Config source={self._source_file!r} sections={list(self._data.keys())}>"
