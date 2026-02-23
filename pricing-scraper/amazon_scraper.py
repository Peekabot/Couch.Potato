"""
Amazon scraper: search results pages + direct product/ASIN pages.

Extracts per-listing:
  - asin
  - title
  - price (float USD)
  - price_raw (original string for audit)
  - currency
  - rating (float 0-5)
  - review_count (int)
  - url
  - source ("amazon")
  - timestamp (ISO-8601 UTC)
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlencode

from base_scraper import BaseScraper
import config

logger = logging.getLogger(__name__)

AMAZON_BASE = "https://www.amazon.com"
SEARCH_URL = f"{AMAZON_BASE}/s"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class AmazonListing:
    asin: str
    title: str
    price: Optional[float]
    price_raw: str
    currency: str
    rating: Optional[float]
    review_count: Optional[int]
    url: str
    source: str = "amazon"
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "asin": self.asin,
            "title": self.title,
            "price": self.price,
            "price_raw": self.price_raw,
            "currency": self.currency,
            "rating": self.rating,
            "review_count": self.review_count,
            "url": self.url,
            "timestamp": self.timestamp,
        }


# ---------------------------------------------------------------------------
# Scraper
# ---------------------------------------------------------------------------
class AmazonScraper(BaseScraper):
    SITE_NAME = "amazon"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def search(self, query: str, max_pages: int = 1) -> list[AmazonListing]:
        """Scrape search results for *query*. Returns a flat list of listings."""
        results: list[AmazonListing] = []
        page = 1

        while page <= max(1, max_pages):
            url = self._search_url(query, page)
            logger.info("[amazon] Searching page %d: %s", page, url)
            html = self._get(url)

            if not html:
                logger.warning("[amazon] No HTML returned for search page %d — stopping.", page)
                break

            if self._is_captcha_page(html):
                logger.error("[amazon] CAPTCHA detected on search page %d — stopping.", page)
                break

            listings = self._parse_search_results(html)

            if not listings:
                logger.info("[amazon] No listings found on page %d — end of results.", page)
                break

            logger.info("[amazon] Found %d listings on page %d.", len(listings), page)
            results.extend(listings)

            if page < max_pages:
                self._polite_delay()

            page += 1

        return results

    def scrape_product_page(self, url: str) -> Optional[AmazonListing]:
        """Scrape a single Amazon product page by URL."""
        logger.info("[amazon] Scraping product page: %s", url)
        html = self._get(url)

        if not html:
            return None

        if self._is_captcha_page(html):
            logger.error("[amazon] CAPTCHA detected on product page: %s", url)
            return None

        soup = self._parse_html(html)
        return self._parse_product_page(soup, url)

    # ------------------------------------------------------------------
    # URL builders
    # ------------------------------------------------------------------
    @staticmethod
    def _search_url(query: str, page: int = 1) -> str:
        params: dict = {"k": query}
        if page > 1:
            params["page"] = str(page)
        return f"{SEARCH_URL}?{urlencode(params)}"

    @staticmethod
    def _product_url(asin: str) -> str:
        return f"{AMAZON_BASE}/dp/{asin}"

    # ------------------------------------------------------------------
    # HTML guards
    # ------------------------------------------------------------------
    @staticmethod
    def _is_captcha_page(html: str) -> bool:
        markers = [
            "Type the characters you see in this image",
            "api-services-support@amazon.com",
            "robot check",
            "captcha",
        ]
        lower = html.lower()
        return any(m.lower() in lower for m in markers)

    # ------------------------------------------------------------------
    # Search results parser
    # ------------------------------------------------------------------
    def _parse_search_results(self, html: str) -> list[AmazonListing]:
        soup = self._parse_html(html)
        listings: list[AmazonListing] = []

        # Amazon wraps each result in a div with data-asin
        cards = soup.select("div[data-asin][data-component-type='s-search-result']")

        if not cards:
            # Broader fallback selector
            cards = soup.select("div[data-asin]")

        seen_asins: set[str] = set()

        for card in cards[: config.MAX_RESULTS_PER_SEARCH]:
            asin = card.get("data-asin", "").strip()
            if not asin or asin in seen_asins:
                continue
            seen_asins.add(asin)

            listing = self._extract_card(card, asin)
            if listing:
                listings.append(listing)

        return listings

    def _extract_card(self, card, asin: str) -> Optional[AmazonListing]:
        # ----- Title -----
        title_el = card.select_one("h2 a span") or card.select_one("h2 span")
        title = title_el.get_text(strip=True) if title_el else ""
        if not title:
            return None  # Skip ad-injected / empty cards

        # ----- URL -----
        link_el = card.select_one("h2 a")
        href = link_el.get("href", "") if link_el else ""
        product_url = f"{AMAZON_BASE}{href}" if href.startswith("/") else href
        if not product_url:
            product_url = self._product_url(asin)

        # ----- Price -----
        price_raw, price = self._extract_price_from_card(card)

        # ----- Rating -----
        rating, review_count = self._extract_rating_from_card(card)

        return AmazonListing(
            asin=asin,
            title=title,
            price=price,
            price_raw=price_raw,
            currency="USD",
            rating=rating,
            review_count=review_count,
            url=product_url,
        )

    @staticmethod
    def _extract_price_from_card(card) -> tuple[str, Optional[float]]:
        """Returns (raw_string, float_or_None)."""
        # Primary: aria-hidden offscreen span (most reliable)
        offscreen = card.select_one("span.a-price span.a-offscreen")
        if offscreen:
            raw = offscreen.get_text(strip=True)
            cleaned = raw.replace("$", "").replace(",", "")
            try:
                return raw, float(cleaned)
            except ValueError:
                pass

        # Fallback: whole + fraction spans
        whole = card.select_one("span.a-price-whole")
        frac = card.select_one("span.a-price-fraction")
        if whole:
            raw = f"${whole.get_text(strip=True)}{frac.get_text(strip=True) if frac else '00'}"
            cleaned = raw.replace("$", "").replace(",", "")
            try:
                return raw, float(cleaned)
            except ValueError:
                pass

        return "N/A", None

    @staticmethod
    def _extract_rating_from_card(card) -> tuple[Optional[float], Optional[int]]:
        rating: Optional[float] = None
        review_count: Optional[int] = None

        rating_el = card.select_one("span.a-icon-alt")
        if rating_el:
            text = rating_el.get_text(strip=True)  # e.g. "4.3 out of 5 stars"
            try:
                rating = float(text.split()[0])
            except (ValueError, IndexError):
                pass

        count_el = card.select_one("span[aria-label*='ratings']") or \
                   card.select_one("a[href*='customerReviews'] span")
        if count_el:
            raw = count_el.get("aria-label", "") or count_el.get_text(strip=True)
            digits = "".join(c for c in raw if c.isdigit())
            if digits:
                try:
                    review_count = int(digits)
                except ValueError:
                    pass

        return rating, review_count

    # ------------------------------------------------------------------
    # Product page parser
    # ------------------------------------------------------------------
    def _parse_product_page(self, soup, url: str) -> Optional[AmazonListing]:
        # ASIN from URL or meta tag
        asin = self._asin_from_url(url)
        if not asin:
            asin_el = soup.find("input", {"name": "ASIN"})
            asin = asin_el["value"].strip() if asin_el else "unknown"

        # Title
        title_el = soup.find("span", id="productTitle")
        title = title_el.get_text(strip=True) if title_el else "N/A"

        # Price — try several selectors in priority order
        price_raw, price = self._extract_price_from_product_page(soup)

        # Rating
        rating_el = soup.find("span", id="acrPopover")
        rating: Optional[float] = None
        if rating_el:
            title_attr = rating_el.get("title", "")
            try:
                rating = float(title_attr.split()[0])
            except (ValueError, IndexError):
                pass

        count_el = soup.find("span", id="acrCustomerReviewText")
        review_count: Optional[int] = None
        if count_el:
            digits = "".join(c for c in count_el.get_text() if c.isdigit())
            if digits:
                try:
                    review_count = int(digits)
                except ValueError:
                    pass

        return AmazonListing(
            asin=asin,
            title=title,
            price=price,
            price_raw=price_raw,
            currency="USD",
            rating=rating,
            review_count=review_count,
            url=url,
        )

    @staticmethod
    def _extract_price_from_product_page(soup) -> tuple[str, Optional[float]]:
        """Try several Amazon price selectors in priority order."""
        # 1. Featured/buybox offscreen price
        el = soup.select_one("#corePriceDisplay_desktop_feature_div span.a-offscreen")
        if not el:
            el = soup.select_one("#price_inside_buybox")
        if not el:
            el = soup.select_one("#priceblock_ourprice")
        if not el:
            el = soup.select_one("#priceblock_dealprice")
        if not el:
            # Catch-all: first offscreen price on the page
            el = soup.select_one("span.a-offscreen")

        if el:
            raw = el.get_text(strip=True)
            cleaned = raw.replace("$", "").replace(",", "")
            try:
                return raw, float(cleaned)
            except ValueError:
                pass

        # Whole + fraction fallback
        whole = soup.select_one("span.a-price-whole")
        frac = soup.select_one("span.a-price-fraction")
        if whole:
            raw = f"${whole.get_text(strip=True)}{frac.get_text(strip=True) if frac else '00'}"
            cleaned = raw.replace("$", "").replace(",", "")
            try:
                return raw, float(cleaned)
            except ValueError:
                pass

        return "N/A", None

    @staticmethod
    def _asin_from_url(url: str) -> str:
        """Extract ASIN from an Amazon product URL."""
        # Matches /dp/XXXXXXXXXX or /gp/product/XXXXXXXXXX
        import re
        match = re.search(r"/(?:dp|gp/product)/([A-Z0-9]{10})", url)
        return match.group(1) if match else ""
