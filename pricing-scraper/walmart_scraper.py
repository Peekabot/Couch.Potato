"""
Walmart scraper: search results + direct product pages.

Walmart's Next.js frontend embeds all product data in a
<script id="__NEXT_DATA__"> JSON blob, which is far more reliable
than DOM scraping and less brittle to layout changes.

Falls back to DOM parsing if the JSON path changes.

Extracts per-listing:
  - item_id    (Walmart item ID, analogous to Amazon ASIN)
  - title
  - price (float USD)
  - price_raw
  - currency
  - rating (float 0-5)
  - review_count (int)
  - url
  - source ("walmart")
  - timestamp (ISO-8601 UTC)
"""

import json
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlencode

from base_scraper import BaseScraper
import config

logger = logging.getLogger(__name__)

WALMART_BASE = "https://www.walmart.com"
SEARCH_URL = f"{WALMART_BASE}/search"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class WalmartListing:
    item_id: str
    title: str
    price: Optional[float]
    price_raw: str
    currency: str
    rating: Optional[float]
    review_count: Optional[int]
    url: str
    source: str = "walmart"
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "item_id": self.item_id,
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
class WalmartScraper(BaseScraper):
    SITE_NAME = "walmart"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def search(self, query: str, max_pages: int = 1) -> list[WalmartListing]:
        """Scrape Walmart search results for *query*."""
        results: list[WalmartListing] = []
        page = 1

        while page <= max(1, max_pages):
            url = self._search_url(query, page)
            logger.info("[walmart] Searching page %d: %s", page, url)
            html = self._get(url)

            if not html:
                logger.warning("[walmart] No HTML for search page %d — stopping.", page)
                break

            if self._is_blocked_page(html):
                logger.error("[walmart] Bot-block detected on search page %d.", page)
                break

            listings = self._parse_search_results(html)

            if not listings:
                logger.info("[walmart] No listings on page %d — end of results.", page)
                break

            logger.info("[walmart] Found %d listings on page %d.", len(listings), page)
            results.extend(listings)

            if page < max_pages:
                self._polite_delay()

            page += 1

        return results

    def scrape_product_page(self, url: str) -> Optional[WalmartListing]:
        """Scrape a single Walmart product page."""
        logger.info("[walmart] Scraping product page: %s", url)
        html = self._get(url)
        if not html:
            return None
        if self._is_blocked_page(html):
            logger.error("[walmart] Bot-block on product page: %s", url)
            return None

        # Try JSON first, then DOM
        listing = self._parse_product_from_json(html, url)
        if not listing:
            listing = self._parse_product_from_dom(html, url)
        return listing

    # ------------------------------------------------------------------
    # URL builders
    # ------------------------------------------------------------------
    @staticmethod
    def _search_url(query: str, page: int = 1) -> str:
        params: dict = {"q": query, "sort": "price_low"}
        if page > 1:
            params["page"] = str(page)
        return f"{SEARCH_URL}?{urlencode(params)}"

    @staticmethod
    def _product_url(item_id: str) -> str:
        return f"{WALMART_BASE}/ip/{item_id}"

    # ------------------------------------------------------------------
    # Guards
    # ------------------------------------------------------------------
    @staticmethod
    def _is_blocked_page(html: str) -> bool:
        markers = [
            "robot or human",
            "verify you are human",
            "access denied",
            "captcha",
            "blocked",
        ]
        lower = html.lower()
        return any(m in lower for m in markers)

    # ------------------------------------------------------------------
    # __NEXT_DATA__ extraction (primary method)
    # ------------------------------------------------------------------
    @staticmethod
    def _extract_next_data(html: str) -> Optional[dict]:
        """Extract the __NEXT_DATA__ JSON blob from the page."""
        match = re.search(
            r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
            html,
            re.DOTALL,
        )
        if not match:
            return None
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError as exc:
            logger.debug("Failed to parse __NEXT_DATA__: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Search results parser
    # ------------------------------------------------------------------
    def _parse_search_results(self, html: str) -> list[WalmartListing]:
        data = self._extract_next_data(html)
        if data:
            listings = self._listings_from_next_data_search(data)
            if listings:
                return listings[: config.MAX_RESULTS_PER_SEARCH]

        # Fallback: DOM
        return self._parse_search_dom(html)

    def _listings_from_next_data_search(self, data: dict) -> list[WalmartListing]:
        """Walk several known JSON paths for search result items."""
        items: list[Any] = []

        # Path 1: pageProps.initialData.searchResult.itemStacks[*].items
        try:
            stacks = (
                data["props"]["pageProps"]["initialData"]["searchResult"]["itemStacks"]
            )
            for stack in stacks:
                items.extend(stack.get("items", []))
        except (KeyError, TypeError):
            pass

        # Path 2: Direct items key (older layout)
        if not items:
            try:
                items = data["props"]["pageProps"]["initialData"]["searchResult"]["items"]
            except (KeyError, TypeError):
                pass

        return [self._item_dict_to_listing(item) for item in items if item]

    def _item_dict_to_listing(self, item: dict) -> Optional[WalmartListing]:
        try:
            item_id = str(item.get("usItemId") or item.get("id") or "")
            if not item_id:
                return None

            title = item.get("name", "") or item.get("title", "")
            if not title:
                return None

            # Price — multiple possible locations
            price_info = item.get("price") or item.get("priceInfo") or {}
            if isinstance(price_info, (int, float)):
                price = float(price_info)
                price_raw = f"${price:.2f}"
            else:
                current = (
                    price_info.get("currentPrice")
                    or price_info.get("price")
                    or price_info.get("priceDisplay")
                )
                if isinstance(current, dict):
                    price = float(current.get("price") or current.get("value") or 0) or None
                    price_raw = current.get("priceString", f"${price:.2f}" if price else "N/A")
                elif isinstance(current, (int, float)):
                    price = float(current)
                    price_raw = f"${price:.2f}"
                else:
                    price_raw_str = str(current) if current else "N/A"
                    price = self._clean_price(price_raw_str)
                    price_raw = price_raw_str

            # Rating
            rating_info = item.get("rating") or {}
            rating = None
            review_count = None
            if isinstance(rating_info, dict):
                try:
                    rating = float(rating_info.get("averageRating") or rating_info.get("rating") or 0) or None
                except (TypeError, ValueError):
                    pass
                try:
                    review_count = int(rating_info.get("numberOfReviews") or rating_info.get("reviewCount") or 0) or None
                except (TypeError, ValueError):
                    pass

            # URL
            canonical_url = item.get("canonicalUrl") or item.get("detailsPageURL") or ""
            if canonical_url and not canonical_url.startswith("http"):
                canonical_url = f"{WALMART_BASE}{canonical_url}"
            if not canonical_url:
                canonical_url = self._product_url(item_id)

            return WalmartListing(
                item_id=item_id,
                title=str(title),
                price=price,
                price_raw=price_raw,
                currency="USD",
                rating=rating,
                review_count=review_count,
                url=canonical_url,
            )
        except Exception as exc:
            logger.debug("Failed to parse Walmart item dict: %s", exc)
            return None

    def _parse_search_dom(self, html: str) -> list[WalmartListing]:
        """DOM fallback for search results — less reliable but better than nothing."""
        soup = self._parse_html(html)
        listings: list[WalmartListing] = []

        cards = soup.select("[data-item-id]") or soup.select("div[data-automation-id='product']")
        for card in cards[: config.MAX_RESULTS_PER_SEARCH]:
            item_id = card.get("data-item-id", "")
            title_el = card.select_one("[data-automation-id='product-title']") or card.select_one("span[class*='lh-title']")
            if not title_el:
                continue
            title = title_el.get_text(strip=True)

            price_el = card.select_one("[itemprop='price']") or card.select_one("[data-automation-id='product-price'] span")
            price_raw = price_el.get_text(strip=True) if price_el else "N/A"
            price = self._clean_price(price_raw)

            url_el = card.select_one("a[link-identifier]") or card.select_one("a[href*='/ip/']")
            href = url_el.get("href", "") if url_el else ""
            product_url = f"{WALMART_BASE}{href}" if href.startswith("/") else href or self._product_url(item_id)

            listings.append(
                WalmartListing(
                    item_id=item_id or "unknown",
                    title=title,
                    price=price,
                    price_raw=price_raw,
                    currency="USD",
                    rating=None,
                    review_count=None,
                    url=product_url,
                )
            )

        return listings

    # ------------------------------------------------------------------
    # Product page parsers
    # ------------------------------------------------------------------
    def _parse_product_from_json(self, html: str, url: str) -> Optional[WalmartListing]:
        data = self._extract_next_data(html)
        if not data:
            return None

        try:
            product = (
                data["props"]["pageProps"]["initialData"]["data"]["product"]
            )
        except (KeyError, TypeError):
            # Try alternate path
            try:
                product = data["props"]["pageProps"]["product"]
            except (KeyError, TypeError):
                return None

        if not product:
            return None

        item_id = str(product.get("usItemId") or product.get("id") or "")
        title = product.get("name") or product.get("title") or "N/A"

        price_info = product.get("priceInfo") or product.get("price") or {}
        if isinstance(price_info, dict):
            current = price_info.get("currentPrice") or {}
            if isinstance(current, dict):
                price = float(current.get("price") or current.get("value") or 0) or None
                price_raw = current.get("priceString", f"${price:.2f}" if price else "N/A")
            else:
                price_raw = str(current) if current else "N/A"
                price = self._clean_price(price_raw)
        else:
            price_raw = str(price_info) if price_info else "N/A"
            price = self._clean_price(price_raw)

        rating_info = product.get("averageRating") or product.get("rating") or {}
        rating = None
        review_count = None
        if isinstance(rating_info, dict):
            try:
                rating = float(rating_info.get("averageRating") or 0) or None
                review_count = int(rating_info.get("numberOfReviews") or 0) or None
            except (TypeError, ValueError):
                pass
        elif isinstance(rating_info, (int, float)):
            rating = float(rating_info) or None

        return WalmartListing(
            item_id=item_id,
            title=str(title),
            price=price,
            price_raw=price_raw,
            currency="USD",
            rating=rating,
            review_count=review_count,
            url=url,
        )

    def _parse_product_from_dom(self, html: str, url: str) -> Optional[WalmartListing]:
        """DOM fallback for single product pages."""
        soup = self._parse_html(html)

        item_id_match = re.search(r"/ip/(?:[^/]+/)?(\d+)", url)
        item_id = item_id_match.group(1) if item_id_match else "unknown"

        title_el = soup.select_one("h1[itemprop='name']") or soup.select_one("h1.prod-ProductTitle")
        title = title_el.get_text(strip=True) if title_el else "N/A"

        price_el = (
            soup.select_one("[itemprop='price']")
            or soup.select_one("span.price-characteristic")
            or soup.select_one("[data-automation-id='product-price'] span")
        )
        price_raw = price_el.get_text(strip=True) if price_el else "N/A"
        price = self._clean_price(price_raw)

        return WalmartListing(
            item_id=item_id,
            title=title,
            price=price,
            price_raw=price_raw,
            currency="USD",
            rating=None,
            review_count=None,
            url=url,
        )
