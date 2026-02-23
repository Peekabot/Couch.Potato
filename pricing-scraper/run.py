#!/usr/bin/env python3
"""
run.py — CLI entry point for the pulse oximeter pricing scraper.

Usage examples
--------------
# Run everything (Amazon + Walmart, default queries, page 1):
python run.py

# Amazon only:
python run.py --sites amazon

# Walmart only, two search pages:
python run.py --sites walmart --pages 2

# Custom query:
python run.py --query "contec cms50d pulse oximeter"

# Scrape direct product pages instead of / in addition to search:
python run.py --direct

# Dry-run: print what would be scraped, don't save:
python run.py --dry-run

# Override output dir:
SCRAPER_OUTPUT_DIR=/tmp/prices python run.py
"""

import argparse
import logging
import sys
import time

import config
from amazon_scraper import AmazonScraper
from walmart_scraper import WalmartScraper
from storage import save_results, print_summary

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("run")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scrape pulse oximeter prices from Amazon and Walmart.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--sites",
        nargs="+",
        choices=["amazon", "walmart"],
        default=["amazon", "walmart"],
        help="Which sites to scrape (default: both).",
    )
    parser.add_argument(
        "--query",
        nargs="+",
        default=None,
        help=(
            "Override search query/queries. "
            "Defaults to queries in config.SEARCH_QUERIES."
        ),
    )
    parser.add_argument(
        "--pages",
        type=int,
        default=config.MAX_SEARCH_PAGES or 1,
        metavar="N",
        help="Number of search result pages to scrape per query (default: 1).",
    )
    parser.add_argument(
        "--direct",
        action="store_true",
        help="Also scrape direct product URLs defined in config.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and print results without saving to disk.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    args = build_parser().parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    queries = args.query or config.SEARCH_QUERIES
    sites = args.sites
    pages = max(1, args.pages)

    all_results = []

    # ------------------------------------------------------------------
    # Amazon
    # ------------------------------------------------------------------
    if "amazon" in sites:
        scraper = AmazonScraper()

        for query in queries:
            logger.info("--- Amazon search: %r ---", query)
            results = scraper.search(query, max_pages=pages)
            all_results.extend(results)
            if len(queries) > 1:
                _inter_query_delay()

        if args.direct and config.AMAZON_DIRECT_URLS:
            for url in config.AMAZON_DIRECT_URLS:
                logger.info("--- Amazon direct: %s ---", url)
                result = scraper.scrape_product_page(url)
                if result:
                    all_results.append(result)
                _inter_query_delay()

    # ------------------------------------------------------------------
    # Walmart
    # ------------------------------------------------------------------
    if "walmart" in sites:
        # Delay between sites to avoid looking like a bot sweep
        if "amazon" in sites and all_results:
            logger.info("Pausing before switching to Walmart...")
            _inter_query_delay()

        scraper = WalmartScraper()

        for query in queries:
            logger.info("--- Walmart search: %r ---", query)
            results = scraper.search(query, max_pages=pages)
            all_results.extend(results)
            if len(queries) > 1:
                _inter_query_delay()

        if args.direct and config.WALMART_DIRECT_URLS:
            for url in config.WALMART_DIRECT_URLS:
                logger.info("--- Walmart direct: %s ---", url)
                result = scraper.scrape_product_page(url)
                if result:
                    all_results.append(result)
                _inter_query_delay()

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------
    print_summary(all_results)

    if not args.dry_run and all_results:
        paths = save_results(all_results)
        logger.info("Results written to: %s", paths)
    elif args.dry_run:
        logger.info("--dry-run: skipping file save.")
    else:
        logger.warning("No results collected — nothing to save.")


def _inter_query_delay() -> None:
    """Short polite pause between separate queries / site transitions."""
    import random
    delay = random.uniform(config.REQUEST_DELAY_MIN, config.REQUEST_DELAY_MAX)
    logger.debug("Inter-query delay: %.1fs", delay)
    time.sleep(delay)


if __name__ == "__main__":
    main()
