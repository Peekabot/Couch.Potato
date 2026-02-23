"""
Storage: write, append, and de-duplicate scrape results.

Supports two output formats:
  - CSV  (prices.csv)  — human-friendly, Excel-compatible
  - JSON (prices.json) — machine-readable, append-friendly newline-delimited format

De-duplication key: (source, asin/item_id, date) — so re-running on the same
day updates the row rather than bloating the file with duplicates.
"""

import csv
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Union

import config

logger = logging.getLogger(__name__)

# All possible field names across both scrapers — keeps a stable column order.
FIELDNAMES = [
    "source",
    "asin",
    "item_id",
    "title",
    "price",
    "price_raw",
    "currency",
    "rating",
    "review_count",
    "url",
    "timestamp",
]


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def save_results(results: list) -> dict[str, Path]:
    """
    Persist a list of AmazonListing / WalmartListing objects.

    Appends to existing files; de-duplicates on (source, id, date).
    Returns a dict of {"csv": path, "json": path}.
    """
    if not results:
        logger.info("No results to save.")
        return {}

    output_dir = Path(config.OUTPUT_DIR)
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = [_to_row(r) for r in results]

    csv_path = output_dir / config.CSV_FILENAME
    json_path = output_dir / config.JSON_FILENAME

    _write_csv(rows, csv_path)
    _write_jsonl(rows, json_path)

    return {"csv": csv_path, "json": json_path}


def load_csv(path: Union[str, Path] = None) -> list[dict]:
    """Load the CSV file and return a list of row dicts."""
    path = Path(path or Path(config.OUTPUT_DIR) / config.CSV_FILENAME)
    if not path.exists():
        return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def cheapest_by_source(rows: list[dict]) -> dict[str, dict]:
    """Return the cheapest listing per source from a list of row dicts."""
    best: dict[str, dict] = {}
    for row in rows:
        src = row.get("source", "unknown")
        try:
            price = float(row["price"]) if row.get("price") not in (None, "", "N/A", "None") else None
        except (TypeError, ValueError):
            price = None

        if price is None:
            continue

        if src not in best or price < float(best[src]["price"]):
            best[src] = {**row, "price": price}

    return best


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _to_row(listing) -> dict:
    """Convert a dataclass listing to a flat dict with all FIELDNAMES keys."""
    d = listing.to_dict()
    # Normalise: Amazon uses 'asin', Walmart uses 'item_id'
    row: dict = {}
    for field in FIELDNAMES:
        row[field] = d.get(field, "")
    return row


def _dedup_key(row: dict) -> str:
    """Stable key for de-duplication: source + product ID + calendar date."""
    product_id = row.get("asin") or row.get("item_id") or row.get("url", "")
    date_str = row.get("timestamp", "")[:10]  # YYYY-MM-DD
    return f"{row.get('source','')}/{product_id}/{date_str}"


def _write_csv(new_rows: list[dict], path: Path) -> None:
    """Append-with-dedup: load existing rows, merge new ones, write back."""
    existing: dict[str, dict] = {}

    if path.exists():
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                existing[_dedup_key(row)] = row

    before = len(existing)
    for row in new_rows:
        existing[_dedup_key(row)] = row  # newer scrape wins

    added = len(existing) - before
    updated = len(new_rows) - added

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(existing.values())

    logger.info(
        "CSV saved → %s  (%d added, %d updated, %d total rows)",
        path,
        added,
        updated,
        len(existing),
    )


def _write_jsonl(new_rows: list[dict], path: Path) -> None:
    """
    Newline-delimited JSON (JSONL).

    Each line is one JSON object. On re-run, existing lines are indexed
    by de-dup key and newer records overwrite older ones in-place.
    """
    existing: dict[str, dict] = {}

    if path.exists():
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    existing[_dedup_key(row)] = row
                except json.JSONDecodeError:
                    pass

    for row in new_rows:
        existing[_dedup_key(row)] = row

    with open(path, "w", encoding="utf-8") as f:
        for row in existing.values():
            f.write(json.dumps(row) + "\n")

    logger.info("JSONL saved → %s  (%d total records)", path, len(existing))


def print_summary(results: list) -> None:
    """Print a quick console summary of scraped results."""
    if not results:
        print("No results.")
        return

    rows = [_to_row(r) for r in results]
    best = cheapest_by_source(rows)

    print(f"\n{'='*60}")
    print(f"  Scraped {len(rows)} listings")
    print(f"{'='*60}")

    for src, row in best.items():
        print(f"\n  [{src.upper()}] cheapest:")
        print(f"    Title : {row.get('title', 'N/A')[:70]}")
        print(f"    Price : ${row.get('price', 'N/A')}")
        print(f"    URL   : {row.get('url', 'N/A')[:80]}")

    print(f"\n{'='*60}\n")
