"""
BaseScraper: shared HTTP session, retry logic, rate limiting, and parsing helpers.

Uses curl_cffi when available (real Chrome TLS fingerprint → bypasses many
bot-detection layers). Falls back to requests + custom headers if curl_cffi
is not installed.
"""

import logging
import random
import time
from typing import Optional
from urllib.parse import urlencode, urljoin

from bs4 import BeautifulSoup

import config

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Try to import curl_cffi; fall back to requests
# ---------------------------------------------------------------------------
try:
    from curl_cffi import requests as cffi_requests

    _USE_CFFI = True
    logger.debug("curl_cffi available — using Chrome impersonation")
except ImportError:  # pragma: no cover
    import requests as cffi_requests  # type: ignore[no-reuse-declared]

    _USE_CFFI = False
    logger.warning(
        "curl_cffi not installed — falling back to requests. "
        "Install with: pip install curl_cffi"
    )


# ---------------------------------------------------------------------------
# BaseScraper
# ---------------------------------------------------------------------------
class BaseScraper:
    """Abstract base for all retailer scrapers."""

    # Subclasses set this so log messages include the site name
    SITE_NAME: str = "base"

    def __init__(self) -> None:
        self._session = self._build_session()

    # ------------------------------------------------------------------
    # Session setup
    # ------------------------------------------------------------------
    def _build_session(self):
        if _USE_CFFI:
            session = cffi_requests.Session(impersonate=config.IMPERSONATE)
        else:
            session = cffi_requests.Session()

        session.headers.update(self._random_headers())

        if config.PROXY:
            session.proxies = {
                "http": config.PROXY,
                "https": config.PROXY,
            }
            logger.debug("Proxy configured: %s", config.PROXY)

        return session

    @staticmethod
    def _random_headers() -> dict:
        ua = random.choice(config.USER_AGENTS)
        return {"User-Agent": ua, **config.COMMON_HEADERS}

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------
    def _get(
        self,
        url: str,
        params: Optional[dict] = None,
        retries: int = 3,
        timeout: int = 30,
    ) -> Optional[str]:
        """GET a URL with retries and exponential back-off.

        Returns the response text on success, None on failure.
        """
        self._session.headers.update(self._random_headers())

        for attempt in range(1, retries + 1):
            try:
                if _USE_CFFI:
                    resp = self._session.get(
                        url,
                        params=params,
                        timeout=timeout,
                        impersonate=config.IMPERSONATE,
                    )
                else:
                    resp = self._session.get(url, params=params, timeout=timeout)

                if resp.status_code == 200:
                    return resp.text
                elif resp.status_code in (429, 503):
                    wait = 2 ** attempt + random.uniform(1, 5)
                    logger.warning(
                        "[%s] Rate-limited (HTTP %d). Waiting %.1fs before retry %d/%d.",
                        self.SITE_NAME,
                        resp.status_code,
                        wait,
                        attempt,
                        retries,
                    )
                    time.sleep(wait)
                else:
                    logger.warning(
                        "[%s] Unexpected status %d for %s",
                        self.SITE_NAME,
                        resp.status_code,
                        url,
                    )
                    return None
            except Exception as exc:
                wait = 2 ** attempt
                logger.error(
                    "[%s] Request error on attempt %d/%d: %s. Waiting %ds.",
                    self.SITE_NAME,
                    attempt,
                    retries,
                    exc,
                    wait,
                )
                time.sleep(wait)

        logger.error("[%s] All %d retries exhausted for %s", self.SITE_NAME, retries, url)
        return None

    # ------------------------------------------------------------------
    # Rate-limit helper
    # ------------------------------------------------------------------
    def _polite_delay(self) -> None:
        delay = random.uniform(config.REQUEST_DELAY_MIN, config.REQUEST_DELAY_MAX)
        logger.debug("[%s] Sleeping %.1fs between requests.", self.SITE_NAME, delay)
        time.sleep(delay)

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_html(html: str) -> BeautifulSoup:
        return BeautifulSoup(html, "lxml")

    @staticmethod
    def _clean_price(raw: str) -> Optional[float]:
        """Strip currency symbols, commas, whitespace → float or None."""
        if not raw:
            return None
        cleaned = raw.replace("$", "").replace(",", "").strip()
        # Handle cases like "14.99\n" or "$14.99 with coupon"
        cleaned = cleaned.split()[0] if cleaned else ""
        try:
            return float(cleaned)
        except ValueError:
            return None
