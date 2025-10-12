"""
IronVeil Browser Automation Utilities

Provides a unified wrapper around Selenium and Playwright for browser
automation during security audits. Handles page loading, JavaScript
execution, screenshot capture, and element interaction.

Supports both Selenium WebDriver and Playwright backends, selected
via the ``engine`` parameter in BrowserConfig.
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
        engine: str = "playwright",
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
        self.engine = engine  # "playwright" or "selenium"
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
            "engine": self.engine,
            "headless": self.headless,
            "viewport": self.viewport,
            "user_agent": self.user_agent,
            "proxy": self.proxy,
            "timeout": self.timeout,
            "language": self.language,
            "timezone": self.timezone,
        }


class _PlaywrightBackend:
    """Playwright-based browser backend."""

    def __init__(self, config: BrowserConfig) -> None:
        self.config = config
        self._playwright: Any = None
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None

    def launch(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise BrowserError("playwright is not installed — run `pip install playwright && playwright install`")

        try:
            self._playwright = sync_playwright().start()
            launch_args = list(self.config.extra_args)

            browser_kwargs: Dict[str, Any] = {
                "headless": self.config.headless,
                "args": launch_args,
            }

            if self.config.proxy:
                browser_kwargs["proxy"] = {"server": self.config.proxy}

            self._browser = self._playwright.chromium.launch(**browser_kwargs)

            context_kwargs: Dict[str, Any] = {
                "viewport": {"width": self.config.viewport[0], "height": self.config.viewport[1]},
                "locale": self.config.language,
            }
            if self.config.user_agent:
                context_kwargs["user_agent"] = self.config.user_agent
            if self.config.timezone:
                context_kwargs["timezone_id"] = self.config.timezone

            self._context = self._browser.new_context(**context_kwargs)
            self._context.set_default_timeout(self.config.timeout * 1000)

            if self.config.disable_images:
                self._context.route("**/*.{png,jpg,jpeg,gif,svg,webp}", lambda route: route.abort())

            self._page = self._context.new_page()
            logger.info("Playwright browser launched (headless=%s)", self.config.headless)
        except ImportError:
            raise
        except Exception as exc:
            raise BrowserError(f"Failed to launch Playwright browser: {exc}") from exc

    def navigate(self, url: str, wait: float = 0) -> None:
        self._page.goto(url, wait_until="domcontentloaded")
        if wait > 0:
            time.sleep(wait)

    def current_url(self) -> str:
        return self._page.url

    def page_source(self) -> str:
        return self._page.content()

    def title(self) -> str:
        return self._page.title()

    def execute_js(self, script: str, *args: Any) -> Any:
        # Playwright uses evaluate, which expects an expression, not a "return" statement.
        # Strip leading "return " if present for Selenium-style scripts.
        clean = script.strip()
        if clean.startswith("return "):
            clean = clean[7:]
        return self._page.evaluate(clean)

    def screenshot(self, path: str) -> str:
        self._page.screenshot(path=path, full_page=False)
        return path

    def find_element(self, css: str) -> Any:
        return self._page.query_selector(css)

    def find_elements(self, css: str) -> List[Any]:
        return self._page.query_selector_all(css)

    def get_cookies(self) -> List[Dict[str, Any]]:
        return self._context.cookies()

    def add_cookie(self, cookie: Dict[str, Any]) -> None:
        self._context.add_cookies([cookie])

    def delete_all_cookies(self) -> None:
        self._context.clear_cookies()

    def get_console_logs(self) -> List[Dict[str, Any]]:
        # Playwright handles console via event listeners; return empty for now
        return []

    def get_network_entries(self) -> List[Dict[str, Any]]:
        entries = self._page.evaluate(
            "window.performance.getEntriesByType('resource').map(e => ({"
            "  name: e.name, duration: e.duration, transferSize: e.transferSize,"
            "  initiatorType: e.initiatorType"
            "}))"
        )
        return entries or []

    def close(self) -> None:
        if self._context:
            try:
                self._context.close()
            except Exception:
                pass
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass
        self._page = None
        self._context = None
        self._browser = None
        self._playwright = None

    @property
    def is_alive(self) -> bool:
        return self._page is not None


class _SeleniumBackend:
    """Selenium-based browser backend."""

    def __init__(self, config: BrowserConfig) -> None:
        self.config = config
        self._driver: Any = None

    def launch(self) -> None:
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options

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
            logger.info("Selenium browser launched (headless=%s)", self.config.headless)
        except ImportError:
            raise BrowserError("selenium is not installed — run `pip install selenium`")
        except Exception as exc:
            raise BrowserError(f"Failed to launch Selenium browser: {exc}") from exc

    def navigate(self, url: str, wait: float = 0) -> None:
        self._driver.get(url)
        if wait > 0:
            time.sleep(wait)

    def current_url(self) -> str:
        return self._driver.current_url

    def page_source(self) -> str:
        return self._driver.page_source

    def title(self) -> str:
        return self._driver.title

    def execute_js(self, script: str, *args: Any) -> Any:
        return self._driver.execute_script(script, *args)

    def screenshot(self, path: str) -> str:
        self._driver.save_screenshot(path)
        return path

    def find_element(self, css: str) -> Any:
        from selenium.webdriver.common.by import By
        return self._driver.find_element(By.CSS_SELECTOR, css)

    def find_elements(self, css: str) -> List[Any]:
        from selenium.webdriver.common.by import By
        return self._driver.find_elements(By.CSS_SELECTOR, css)

    def get_cookies(self) -> List[Dict[str, Any]]:
        return self._driver.get_cookies()

    def add_cookie(self, cookie: Dict[str, Any]) -> None:
        self._driver.add_cookie(cookie)

    def delete_all_cookies(self) -> None:
        self._driver.delete_all_cookies()

    def get_console_logs(self) -> List[Dict[str, Any]]:
        try:
            return self._driver.get_log("browser")
        except Exception:
            return []

    def get_network_entries(self) -> List[Dict[str, Any]]:
        entries = self._driver.execute_script(
            "return window.performance.getEntriesByType('resource').map(e => ({"
            "  name: e.name, duration: e.duration, transferSize: e.transferSize,"
            "  initiatorType: e.initiatorType"
            "}))"
        )
        return entries or []

    def close(self) -> None:
        if self._driver:
            try:
                self._driver.quit()
            except Exception:
                pass
            self._driver = None

    @property
    def is_alive(self) -> bool:
        return self._driver is not None


class BrowserWrapper:
    """Unified browser automation wrapper.

    Supports both Playwright and Selenium backends, selected via
    ``BrowserConfig.engine``. Provides a consistent API regardless
    of the underlying automation library.
    """

    def __init__(self, config: Optional[BrowserConfig] = None) -> None:
        self.config = config or BrowserConfig()
        self._backend: Any = None
        self._page_load_count = 0
        self._screenshots: List[str] = []

    def launch(self) -> None:
        """Launch the browser with the configured engine and options."""
        if self.config.engine == "playwright":
            self._backend = _PlaywrightBackend(self.config)
        elif self.config.engine == "selenium":
            self._backend = _SeleniumBackend(self.config)
        else:
            raise BrowserError(f"Unknown browser engine: {self.config.engine}. Use 'playwright' or 'selenium'.")
        self._backend.launch()

    def navigate(self, url: str, wait: float = 0) -> None:
        """Navigate to *url* and optionally wait."""
        self._ensure_backend()
        logger.debug("Navigating to %s", url)
        self._backend.navigate(url, wait)
        self._page_load_count += 1

    def current_url(self) -> str:
        self._ensure_backend()
        return self._backend.current_url()

    def page_source(self) -> str:
        self._ensure_backend()
        return self._backend.page_source()

    def title(self) -> str:
        self._ensure_backend()
        return self._backend.title()

    def execute_js(self, script: str, *args: Any) -> Any:
        """Execute JavaScript in the browser context."""
        self._ensure_backend()
        return self._backend.execute_js(script, *args)

    def screenshot(self, path: str) -> str:
        """Save a screenshot and return the file path."""
        self._ensure_backend()
        self._backend.screenshot(path)
        self._screenshots.append(path)
        logger.debug("Screenshot saved: %s", path)
        return path

    def find_element(self, css: str) -> Any:
        """Find a single element by CSS selector."""
        self._ensure_backend()
        return self._backend.find_element(css)

    def find_elements(self, css: str) -> List[Any]:
        """Find all elements matching a CSS selector."""
        self._ensure_backend()
        return self._backend.find_elements(css)

    def get_cookies(self) -> List[Dict[str, Any]]:
        """Return all cookies from the current browser session."""
        self._ensure_backend()
        return self._backend.get_cookies()

    def add_cookie(self, cookie: Dict[str, Any]) -> None:
        self._ensure_backend()
        self._backend.add_cookie(cookie)

    def delete_all_cookies(self) -> None:
        self._ensure_backend()
        self._backend.delete_all_cookies()

    def get_console_logs(self) -> List[Dict[str, Any]]:
        """Retrieve browser console logs."""
        self._ensure_backend()
        return self._backend.get_console_logs()

    def get_network_entries(self) -> List[Dict[str, Any]]:
        """Retrieve performance/network entries via JS."""
        self._ensure_backend()
        return self._backend.get_network_entries()

    def close(self) -> None:
        """Close the browser."""
        if self._backend:
            self._backend.close()
            engine_name = self.config.engine
            self._backend = None
            logger.info("Browser closed (%s, pages_loaded=%d)", engine_name, self._page_load_count)

    @property
    def page_load_count(self) -> int:
        return self._page_load_count

    @property
    def engine(self) -> str:
        return self.config.engine

    def _ensure_backend(self) -> None:
        if self._backend is None:
            raise BrowserError("Browser not launched — call .launch() first")

    def __enter__(self):
        self.launch()
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()
