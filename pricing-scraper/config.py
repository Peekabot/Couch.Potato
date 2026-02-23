"""
Pricing scraper configuration: target products, rate limits, user-agent pool.
"""

import os

# ---------------------------------------------------------------------------
# Target search queries
# ---------------------------------------------------------------------------
SEARCH_QUERIES = [
    "cms50dl pulse oximeter",
    "contec pulse oximeter cms50dl",
    "pulse oximeter cms50d",
]

# Specific ASINs / product page URLs to monitor directly
AMAZON_DIRECT_URLS = [
    "https://www.amazon.com/CONTEC-CMS50DL-Oximeter-Carrying-Silicone/dp/B072JCXXTD",
]

WALMART_DIRECT_URLS: list[str] = []   # populated at runtime from search hits

# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------
# Seconds to wait between individual page requests (uniformly sampled)
REQUEST_DELAY_MIN = 8
REQUEST_DELAY_MAX = 25

# Max results per search results page to parse (top-N cards)
MAX_RESULTS_PER_SEARCH = 20

# Max search pages to walk per query (0 = first page only)
MAX_SEARCH_PAGES = 1

# ---------------------------------------------------------------------------
# HTTP / browser impersonation
# ---------------------------------------------------------------------------
# curl_cffi impersonate target — simulates a real Chrome TLS fingerprint.
# Other valid values: "chrome110", "chrome107", "edge99", "safari15_5"
IMPERSONATE = "chrome124"

# Rotating user-agent strings (fallback when curl_cffi handles headers itself)
USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/123.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/121.0.0.0 Safari/537.36"
    ),
]

COMMON_HEADERS = {
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

# ---------------------------------------------------------------------------
# Proxy (optional)
# ---------------------------------------------------------------------------
# Set SCRAPER_PROXY env var to a proxy URL, e.g.:
#   export SCRAPER_PROXY="http://user:pass@residential-proxy.example.com:8080"
# Leave unset / empty to scrape directly (fine for low-volume local use).
PROXY = os.getenv("SCRAPER_PROXY", "")

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
OUTPUT_DIR = os.getenv("SCRAPER_OUTPUT_DIR", "output")
CSV_FILENAME = "prices.csv"
JSON_FILENAME = "prices.json"
