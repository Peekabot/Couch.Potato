#!/bin/sh
# daily_backup.sh
# Add to crontab in iSH:
#   0 2 * * * /path/to/daily_backup.sh >> /var/log/couch_backup.log 2>&1

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../../.." && pwd)"

echo "=== $(date) ==="
python3 "$PROJECT_DIR/ish/scripts/backup_tool.py" --keep 7
