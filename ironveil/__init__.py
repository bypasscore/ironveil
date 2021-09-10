"""
IronVeil — Casino and iGaming Security Audit Framework

A comprehensive security auditing framework for casino and iGaming platforms.
Tests platform integrity against bot detection bypass, behavioral analysis
evasion, CAPTCHA circumvention, and automated gameplay detection.

Built for authorized security assessments of iGaming platforms.

Copyright (c) BypassCore Labs
Licensed under the MIT License.
"""

__version__ = "0.1.0"
__author__ = "BypassCore Labs"
__license__ = "MIT"
__email__ = "labs@bypasscore.com"

from typing import Dict, List, Optional, Any
import logging
import sys
import os

# Configure package-level logging
logger = logging.getLogger("ironveil")
logger.setLevel(logging.INFO)

_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(
    logging.Formatter(
        "[%(asctime)s] %(name)s %(levelname)s — %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
logger.addHandler(_handler)


# ---------------------------------------------------------------------------
# Public helpers exposed at package level
# ---------------------------------------------------------------------------

_REGISTERED_MODULES: Dict[str, Any] = {}


def register_module(name: str, module: Any) -> None:
    """Register an audit module so the engine can discover it at runtime."""
    _REGISTERED_MODULES[name] = module
    logger.debug("Registered module: %s", name)


def get_module(name: str) -> Optional[Any]:
    """Retrieve a previously registered audit module by name."""
    return _REGISTERED_MODULES.get(name)


def list_modules() -> List[str]:
    """Return the names of all registered audit modules."""
    return sorted(_REGISTERED_MODULES.keys())


def get_version() -> str:
    """Return the current IronVeil version string."""
    return __version__


def get_data_dir() -> str:
    """Return the default data directory, creating it if needed."""
    data_dir = os.path.join(os.path.expanduser("~"), ".ironveil")
    os.makedirs(data_dir, exist_ok=True)
    return data_dir


def configure_logging(level: str = "INFO", logfile: Optional[str] = None) -> None:
    """Reconfigure package-level logging.

    Parameters
    ----------
    level:
        One of DEBUG, INFO, WARNING, ERROR, CRITICAL.
    logfile:
        Optional path to a log file.  When provided a ``FileHandler`` is
        attached alongside the existing stream handler.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    if logfile:
        fh = logging.FileHandler(logfile)
        fh.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(name)s %(levelname)s — %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        logger.addHandler(fh)
        logger.info("Logging to file: %s", logfile)


__all__ = [
    "__version__",
    "__author__",
    "__license__",
    "register_module",
    "get_module",
    "list_modules",
    "get_version",
    "get_data_dir",
    "configure_logging",
]
