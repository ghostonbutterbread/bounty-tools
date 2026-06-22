"""Shared canonical storage helpers for high-volume recon artifacts."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_FAMILY = "web_bounty"
DEFAULT_LANE = "web"
BOUNTY_CORE_PATH = Path(os.environ.get("BOUNTY_CORE_PATH", str(Path.home() / "projects" / "bounty-core")))


@dataclass(frozen=True)
class ReconBucket:
    """Resolved recon artifact bucket."""

    program: str
    family: str
    lane: str
    recon_root: Path
    bucket: Path
    layout: dict[str, Any]


def safe_slug(value: str | None, default: str = "default") -> str:
    """Return a filesystem-safe slug while preserving readable separators."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip(".-_")
    return cleaned or default


def normalize_program(value: str | None, default: str = "recon") -> str:
    return safe_slug(value, default=default)


def normalize_family(value: str | None) -> str:
    family = str(value or DEFAULT_FAMILY).strip().lower()
    return "web_bounty" if family in {"web", "bounty_recon"} else family


def normalize_lane(value: str | None) -> str:
    return safe_slug(str(value or DEFAULT_LANE).lower(), default=DEFAULT_LANE)


def _load_resolve_storage():
    try:
        from bounty_core import resolve_storage
        return resolve_storage
    except Exception:
        if BOUNTY_CORE_PATH.exists() and str(BOUNTY_CORE_PATH) not in sys.path:
            sys.path.insert(0, str(BOUNTY_CORE_PATH))
        try:
            from bounty_core import resolve_storage
            return resolve_storage
        except Exception:
            return None


def resolve_recon_root(
    program: str,
    *,
    family: str = DEFAULT_FAMILY,
    lane: str = DEFAULT_LANE,
    create: bool = True,
) -> tuple[Path, dict[str, Any]]:
    """Resolve the canonical recon root for a program/family/lane."""
    normalized_program = normalize_program(program)
    normalized_family = normalize_family(family)
    normalized_lane = normalize_lane(lane)
    resolve_storage = _load_resolve_storage()
    if resolve_storage is not None:
        layout = resolve_storage(
            normalized_program,
            family=normalized_family,
            lane=normalized_lane,
            create=create,
        )
        layout_dict = layout.to_dict() if hasattr(layout, "to_dict") else dict(layout)
        recon_root_value = layout_dict.get("recon_root")
        if recon_root_value:
            recon_root = Path(recon_root_value)
        else:
            recon_root = Path(layout_dict["canonical_root"]) / "recon"
    else:
        base_root = Path.home() / "Shared"
        lane_root = base_root / normalized_family / normalized_program / normalized_lane
        recon_root = lane_root / "recon"
        layout_dict = {
            "program": normalized_program,
            "family": normalized_family,
            "lane": normalized_lane,
            "root_mode": "shared-default-fallback",
            "base_root": str(base_root),
            "canonical_root": str(lane_root),
            "recon_root": str(recon_root),
        }

    if create:
        recon_root.mkdir(parents=True, exist_ok=True)
    return recon_root, layout_dict


def recon_bucket(
    program: str,
    *,
    family: str = DEFAULT_FAMILY,
    lane: str = DEFAULT_LANE,
    parts: list[str] | tuple[str, ...] = (),
    create: bool = True,
) -> ReconBucket:
    """Resolve and optionally create a canonical recon sub-bucket."""
    recon_root, layout = resolve_recon_root(program, family=family, lane=lane, create=create)
    safe_parts = [safe_slug(part) for part in parts if str(part or "").strip()]
    bucket = recon_root.joinpath(*safe_parts)
    if create:
        bucket.mkdir(parents=True, exist_ok=True)
    return ReconBucket(
        program=layout["program"],
        family=layout["family"],
        lane=layout["lane"],
        recon_root=recon_root,
        bucket=bucket,
        layout=layout,
    )


def atomic_write_text(path: Path, content: str) -> Path:
    """Write text through a temporary file and replace the destination."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(content)
        temp_path = Path(handle.name)
    temp_path.replace(path)
    return path


def atomic_write_json(path: Path, payload: Any, *, compact: bool = False) -> Path:
    separators = (",", ":") if compact else None
    text = json.dumps(payload, indent=None if compact else 2, separators=separators, sort_keys=False)
    return atomic_write_text(path, text + "\n")
