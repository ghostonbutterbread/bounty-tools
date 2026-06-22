#!/usr/bin/env python3
import os
import sys
from pathlib import Path
from datetime import datetime, timedelta

# Configuration
SNAPSHOT_DIR = os.path.expanduser("~/memory/snapshots/")
ARCHIVE_DIR = os.path.expanduser("~/memory/snapshots/archive/")
CLEANUP_DAYS_LOW = 7
CLEANUP_DAYS_MEDIUM = 30
CLEANUP_DAYS_HIGH = 90


PRIORITY_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}

def get_snapshot_priority(snapshot_file: Path) -> str | None:
    try:
        with open(snapshot_file, "r", encoding="utf-8") as f:
            for line in f:
                if "priority_threshold:" in line:
                    return line.split(": ")[1].strip()
    except FileNotFoundError:
        return None
    return None

def cleanup_snapshots():
    now = datetime.now().astimezone()

    # 1. List all snapshots in ~/memory/snapshots/
    snapshot_dir = Path(SNAPSHOT_DIR)
    if not snapshot_dir.exists():
        return
    snapshots = sorted(snapshot_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)

    # 2. For each snapshot:
    for snapshot_file in snapshots:
        age = now - datetime.fromtimestamp(snapshot_file.stat().st_mtime).astimezone()
        priority = get_snapshot_priority(snapshot_file)

        if not priority:
            continue # Skip if no priority

        # - If age > 7 days AND priority = LOW → delete
        if age > timedelta(days=CLEANUP_DAYS_LOW) and priority == "LOW":
            try:
                snapshot_file.unlink()
                print(f"Deleted (LOW): {snapshot_file}")
            except OSError as e:
                print(f"Error deleting (LOW): {snapshot_file} - {e}", file=sys.stderr)

        # - If age > 30 days AND priority = MEDIUM → delete
        elif age > timedelta(days=CLEANUP_DAYS_MEDIUM) and priority == "MEDIUM":
            try:
                snapshot_file.unlink()
                print(f"Deleted (MEDIUM): {snapshot_file}")
            except OSError as e:
                print(f"Error deleting (MEDIUM): {snapshot_file} - {e}", file=sys.stderr)

        # - If age > 90 days AND priority = HIGH → archive (move to ~/memory/snapshots/archive/)
        elif age > timedelta(days=CLEANUP_DAYS_HIGH) and priority == "HIGH":
            archive_dir = Path(ARCHIVE_DIR)
            archive_dir.mkdir(parents=True, exist_ok=True)
            try:
                snapshot_file.rename(archive_dir / snapshot_file.name)
                print(f"Archived (HIGH): {snapshot_file} -> {archive_dir / snapshot_file.name}")
            except OSError as e:
                print(f"Error archiving (HIGH): {snapshot_file} - {e}", file=sys.stderr)

    # 3. Also check ~/memory/snapshots/archive/
    archive_dir = Path(ARCHIVE_DIR)
    if not archive_dir.exists():
        return
    archived_snapshots = sorted(archive_dir.glob("*.md"), key=lambda path: path.stat().st_mtime, reverse=True)
    for snapshot_file in archived_snapshots:
        age = now - datetime.fromtimestamp(snapshot_file.stat().st_mtime).astimezone()
        if age > timedelta(days=180):
            try:
                snapshot_file.unlink()
                print(f"Deleted from archive: {snapshot_file}")
            except OSError as e:
                print(f"Error deleting archived: {snapshot_file} - {e}", file=sys.stderr)


if __name__ == "__main__":
    cleanup_snapshots()
    print("clean up context executed successfully")
