"""
Backup Tool - iSH Script
Creates timestamped archives of the project and optionally syncs them
to a remote destination (e.g. a git remote or rsync target).

Run in iSH:
    python3 backup_tool.py [--dest /path/to/backup]
"""

import os
import shutil
import datetime
import argparse


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_BACKUP_DIR = os.path.expanduser("~/backups")


def create_backup(dest_dir: str = DEFAULT_BACKUP_DIR) -> str:
    """
    Archive the project directory and save it to dest_dir.
    Returns the path of the created archive.
    """
    os.makedirs(dest_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    archive_name = f"couch_potato_{timestamp}"
    archive_path = os.path.join(dest_dir, archive_name)

    print(f"Backing up {PROJECT_ROOT} -> {archive_path}.zip")
    shutil.make_archive(
        base_name=archive_path,
        format="zip",
        root_dir=os.path.dirname(PROJECT_ROOT),
        base_dir=os.path.basename(PROJECT_ROOT),
    )
    full_path = f"{archive_path}.zip"
    size_mb = os.path.getsize(full_path) / (1024 * 1024)
    print(f"Backup complete: {full_path} ({size_mb:.1f} MB)")
    return full_path


def prune_old_backups(dest_dir: str = DEFAULT_BACKUP_DIR, keep: int = 5):
    """Keep only the most recent `keep` backups."""
    archives = sorted(
        [f for f in os.listdir(dest_dir) if f.endswith(".zip")],
        reverse=True,
    )
    for old in archives[keep:]:
        old_path = os.path.join(dest_dir, old)
        os.remove(old_path)
        print(f"Removed old backup: {old_path}")


def main():
    parser = argparse.ArgumentParser(description="Back up the Couch.Potato project.")
    parser.add_argument(
        "--dest",
        default=DEFAULT_BACKUP_DIR,
        help=f"Backup destination directory (default: {DEFAULT_BACKUP_DIR})",
    )
    parser.add_argument(
        "--keep",
        type=int,
        default=5,
        help="Number of recent backups to keep (default: 5)",
    )
    args = parser.parse_args()

    create_backup(args.dest)
    prune_old_backups(args.dest, args.keep)


if __name__ == "__main__":
    main()
