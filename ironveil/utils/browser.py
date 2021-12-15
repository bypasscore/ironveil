"""
IronVeil Browser Automation Utilities

Provides a unified wrapper around Selenium for browser automation
during security audits. Handles page loading, JavaScript execution,
screenshot capture, and element interaction.
"""

import logging
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("ironveil.utils.browser")


class BrowserError(Exception):
    """Raised when a browser automation operation fails."""
    pass


class BrowserConfig:
    """Configuration for browser instances."""

    def __init__(
        self,
        headless: bool = True,
        viewport: Tuple[int, int] = (1920, 1080),
        user_agent: Optional[str] = None,
        proxy: Optional[str] = None,
        timeout: int = 30,
        language: str = "en-US",
        timezone: Optional[str] = None,
        disable_images: bool = False,
        extra_args: Optional[List[str]] = None,
    ) -> None:
        self.headless = headless
        self.viewport = viewport
        self.user_agent = user_agent
        self.proxy = proxy
        self.timeout = timeout
        self.language = language
        self.timezone = timezone
        self.disable_images = disable_images
        self.extra_args = extra_args or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headless": self.headless,
            "viewport": self.viewport,
            "user_agent": self.user_agent,
            "proxy": self.proxy,
            "timeout": self.timeout,
            "language": self.language,
            "timezone": self.timezone,
        }


class BrowserWrapper:
    """Unified browser automation wrapper.

    Wraps Selenium WebDriver, providing convenience methods for
    audit operations.  Playwright support will be added later.
    """

    def __init__(self, config: Optional[BrowserConfig] = None) -> None:
        self.config = config or BrowserConfig()
        self._driver: Any = None
        self._page_load_count = 0
        self._screenshots: List[str] = []

    def launch(self) -> None:
        """Launch the browser with the configured options."""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            from selenium.webdriver.chrome.service import Service

            options = Options()
            if self.config.headless:
                options.add_argument("--headless=new")
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument(f"--window-size={self.config.viewport[0]},{self.config.viewport[1]}")
            options.add_argument(f"--lang={self.config.language}")

            if self.config.user_agent:
                options.add_argument(f"--user-agent={self.config.user_agent}")
            if self.config.proxy:
                options.add_argument(f"--proxy-server={self.config.proxy}")
            if self.config.disable_images:
                prefs = {"profile.managed_default_content_settings.images": 2}
                options.add_experimental_option("prefs", prefs)
            for arg in self.config.extra_args:
                options.add_argument(arg)

            self._driver = webdriver.Chrome(options=options)
            self._driver.set_page_load_timeout(self.config.timeout)
            self._driver.implicitly_wait(self.config.timeout)
            logger.info("Browser launched (headless=%s)", self.config.headless)
        except ImportError:
            raise BrowserError("selenium is not installed — run `pip install selenium`")
        except Exception as exc:
            raise BrowserError(f"Failed to launch browser: {exc}") from exc

    def navigate(self, url: str, wait: float = 0) -> None:
        """Navigate to *url* and optionally wait."""
        self._ensure_driver()
        logger.debug("Navigating to %s", url)
        self._driver.get(url)
        self._page_load_count += 1
        if wait > 0:
            time.sleep(wait)

    def current_url(self) -> str:
        self._ensure_driver()
        return self._driver.current_url

    def page_source(self) -> str:
        self._ensure_driver()
        return self._driver.page_source

    def title(self) -> str:
        self._ensure_driver()
        return self._driver.title

    def execute_js(self, script: str, *args: Any) -> Any:
        """Execute JavaScript in the browser context."""
        self._ensure_driver()
        return self._driver.execute_script(script, *args)

    def screenshot(self, path: str) -> str:
        """Save a screenshot and return the file path."""
        self._ensure_driver()
        self._driver.save_screenshot(path)
        self._screenshots.append(path)
        logger.debug("Screenshot saved: %s", path)
        return path

    def find_element(self, css: str) -> Any:
        """Find a single element by CSS selector."""
        self._ensure_driver()
        from selenium.webdriver.common.by import By
        return self._driver.find_element(By.CSS_SELECTOR, css)

    def find_elements(self, css: str) -> List[Any]:
        """Find all elements matching a CSS selector."""
        self._ensure_driver()
        from selenium.webdriver.common.by import By
        return self._driver.find_elements(By.CSS_SELECTOR, css)

    def get_cookies(self) -> List[Dict[str, Any]]:
        """Return all cookies from the current browser session."""
        self._ensure_driver()
        return self._driver.get_cookies()

    def add_cookie(self, cookie: Dict[str, Any]) -> None:
        self._ensure_driver()
        self._driver.add_cookie(cookie)

    def delete_all_cookies(self) -> None:
        self._ensure_driver()
        self._driver.delete_all_cookies()

    def get_console_logs(self) -> List[Dict[str, Any]]:
        """Retrieve browser console logs (Chrome only)."""
        self._ensure_driver()
        try:
            return self._driver.get_log("browser")
        except Exception:
            return []

    def get_network_entries(self) -> List[Dict[str, Any]]:
        """Retrieve performance/network entries via JS."""
        self._ensure_driver()
        entries = self.execute_js(
            "return window.performance.getEntriesByType('resource').map(e => ({"
            "  name: e.name, duration: e.duration, transferSize: e.transferSize,"
            "  initiatorType: e.initiatorType"
            "}))"
        )
        return entries or []

    def close(self) -> None:
        """Close the browser."""
        if self._driver:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None
            logger.info("Browser closed (pages_loaded=%d)", self._page_load_count)

    @property
    def page_load_count(self) -> int:
        return self._page_load_count

    def _ensure_driver(self) -> None:
        if self._driver is None:
            raise BrowserError("Browser not launched — call .launch() first")

    def __enter__(self):
        self.launch()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
