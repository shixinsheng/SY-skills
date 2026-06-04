#!/usr/bin/env python3
"""Read-only disk usage scanner and local cleanup report service.

The disk usage scan reads filesystem metadata and does not modify files. The
Downloads duplicate-content panel hashes local file bytes only to compare
content. The serve command enables user-initiated actions for paths that
appeared in a scan JSON file.
"""

from __future__ import annotations

import argparse
import ctypes
import dataclasses
import hashlib
import html
import http.server
import json
import os
import platform
import posixpath
import shutil
import subprocess
import sys
import time
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Any


TIER_AUTO = "可自动清理"
TIER_REVIEW = "需人工判断"
TIER_CAUTION = "谨慎清理"

TIER_META = {
    TIER_AUTO: {"key": "auto", "color": "#31f6b1", "soft": "rgba(49, 246, 177, .13)"},
    TIER_REVIEW: {"key": "review", "color": "#ffd166", "soft": "rgba(255, 209, 102, .14)"},
    TIER_CAUTION: {"key": "caution", "color": "#ff4d7d", "soft": "rgba(255, 77, 125, .13)"},
}

ARCHIVE_EXTENSIONS = {
    ".zip",
    ".7z",
    ".rar",
    ".tar",
    ".gz",
    ".bz2",
    ".xz",
    ".tgz",
    ".dmg",
    ".iso",
    ".msi",
    ".pkg",
    ".exe",
}
MEDIA_EXTENSIONS = {
    ".mov",
    ".mp4",
    ".m4v",
    ".avi",
    ".mkv",
    ".wav",
    ".aiff",
    ".flac",
    ".jpg",
    ".jpeg",
    ".png",
    ".heic",
    ".raw",
}
DOCUMENT_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".xls",
    ".xlsx",
    ".ppt",
    ".pptx",
    ".pages",
    ".numbers",
    ".key",
    ".txt",
    ".md",
    ".rtf",
}
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".tif", ".tiff", ".bmp", ".svg"}
VIDEO_EXTENSIONS = {".mov", ".mp4", ".m4v", ".avi", ".mkv", ".webm", ".wmv", ".flv"}
CONTENT_DUPLICATE_EXTENSIONS = DOCUMENT_EXTENSIONS | IMAGE_EXTENSIONS | VIDEO_EXTENSIONS
DATABASE_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".mdb", ".accdb"}
VM_EXTENSIONS = {".vmdk", ".vdi", ".qcow2", ".vhd", ".vhdx", ".pvm", ".vmwarevm"}


@dataclasses.dataclass
class ScanRecord:
    id: str
    path: str
    name: str
    kind: str
    size: int
    files: int
    dirs: int
    modified: float | None
    tier: str
    category: str
    reason: str
    review_command: str
    trash_command: str
    direct_delete_command: str
    errors: int = 0


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if value < 1000 or unit == "PB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1000
    return f"{size} B"


def stable_id(path: str) -> str:
    return hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest()[:16]


def quote_shell(path: str) -> str:
    if os.name == "nt":
        return "'" + path.replace("'", "''") + "'"
    return "'" + path.replace("'", "'\"'\"'") + "'"


def default_roots() -> list[str]:
    if os.name == "nt":
        drives: list[str] = []
        bitmask = ctypes.windll.kernel32.GetLogicalDrives() if hasattr(ctypes, "windll") else 0
        for index in range(26):
            if bitmask & (1 << index):
                drives.append(f"{chr(65 + index)}:\\")
        return drives or [str(Path.home())]
    return ["/"]


def normalize_path(path: str) -> str:
    return str(Path(path).expanduser().absolute())


def collect_disk_usage(roots: list[str]) -> list[dict[str, Any]]:
    disks: list[dict[str, Any]] = []
    seen_devices: set[int] = set()
    for root in roots:
        try:
            normalized = normalize_path(root)
            stat_result = os.stat(normalized)
            if stat_result.st_dev in seen_devices:
                continue
            seen_devices.add(stat_result.st_dev)
            usage = shutil.disk_usage(normalized)
            used = usage.total - usage.free
            disks.append(
                {
                    "root": normalized,
                    "total": usage.total,
                    "used": used,
                    "free": usage.free,
                    "percent_used": round((used / usage.total) * 100, 1) if usage.total else 0,
                }
            )
        except OSError:
            continue
    return disks


def classify(path: str, kind: str) -> tuple[str, str, str]:
    normalized = path.replace("\\", "/")
    lower = normalized.lower()
    name = Path(path).name
    lower_name = name.lower()
    suffix = Path(path).suffix.lower()

    caution_fragments = [
        "/system",
        "/windows",
        "/program files",
        "/program files (x86)",
        "/library/application support",
        "/appdata/roaming",
        "/appdata/local/packages",
        "/users/public",
        "/mail",
        ".photoslibrary",
        "/photo booth library",
        "/virtual machines",
        "/containers",
        "/group containers",
        "/.git",
    ]
    auto_fragments = [
        "/caches/",
        "/cache/",
        "/tmp/",
        "/temp/",
        "/logs/",
        "/.trash/",
        "/$recycle.bin/",
        "/node_modules/.cache/",
        "/.npm/",
        "/.yarn/cache/",
        "/.pnpm-store/",
        "/.cache/pip/",
        "/.gradle/caches/",
        "/deriveddata/",
        "/.next/cache/",
        "/target/debug/",
        "/target/release/",
    ]
    review_fragments = [
        "/downloads/",
        "/desktop/",
        "/documents/",
        "/backups/",
        "/backup/",
        "/node_modules/",
        "/.venv/",
        "/venv/",
    ]

    if suffix in VM_EXTENSIONS or suffix in DATABASE_EXTENSIONS:
        return TIER_CAUTION, "high-risk data", "Looks like a VM image or database; deleting can remove important state."
    if any(fragment in lower for fragment in caution_fragments):
        return TIER_CAUTION, "system or application data", "System, application, mail, photo, source-control, or stateful data needs manual verification."
    if any(fragment in lower for fragment in auto_fragments) or lower_name in {"cache", "caches", "tmp", "temp", "logs", ".trash"}:
        return TIER_AUTO, "cache or temporary data", "Usually rebuildable cache, temporary data, logs, or trash."
    if suffix in ARCHIVE_EXTENSIONS:
        return TIER_REVIEW, "archive or installer", "Installer/archive files are often removable after confirming they are no longer needed."
    if suffix in MEDIA_EXTENSIONS:
        return TIER_REVIEW, "large media", "Media files can be valuable; archive or delete only after checking."
    if any(fragment in lower for fragment in review_fragments) or lower_name in {"node_modules", "downloads", "backup", "backups"}:
        return TIER_REVIEW, "user data or project dependency", "Likely user-created data or reinstallable dependency; review before cleanup."
    if kind == "directory":
        return TIER_REVIEW, "large directory", "Large directory found; inspect contents before deciding."
    return TIER_REVIEW, "large file", "Large file found; inspect before deleting."


def commands_for(path: str, kind: str) -> tuple[str, str, str]:
    quoted = quote_shell(path)
    if os.name == "nt":
        review = f"Get-ChildItem -LiteralPath {quoted} -Force | Select-Object Name,Length,LastWriteTime"
        if kind == "directory":
            trash = (
                "Add-Type -AssemblyName Microsoft.VisualBasic; "
                f"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory({quoted}, 'OnlyErrorDialogs', 'SendToRecycleBin')"
            )
        else:
            trash = (
                "Add-Type -AssemblyName Microsoft.VisualBasic; "
                f"[Microsoft.VisualBasic.FileIO.FileSystem]::DeleteFile({quoted}, 'OnlyErrorDialogs', 'SendToRecycleBin')"
            )
        direct = f"Remove-Item -LiteralPath {quoted} -Recurse -Force"
    else:
        review = f"du -sh {quoted} && open -R {quoted}"
        trash = f"mkdir -p ~/.Trash && mv {quoted} ~/.Trash/"
        direct = f"rm -rf {quoted}"
    return review, trash, direct


def collect_download_archives() -> list[dict[str, Any]]:
    downloads = Path.home() / "Downloads"
    if not downloads.exists():
        return []
    archives: list[dict[str, Any]] = []
    stack = [downloads]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as iterator:
                for entry in iterator:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                        path = Path(entry.path)
                        if path.suffix.lower() not in ARCHIVE_EXTENSIONS:
                            continue
                        stat_result = entry.stat(follow_symlinks=False)
                        review, trash, direct = commands_for(str(path), "file")
                        archives.append(
                            {
                                "id": stable_id(str(path)),
                                "path": str(path),
                                "name": path.name,
                                "size": int(stat_result.st_size),
                                "modified": getattr(stat_result, "st_mtime", None),
                                "extension": path.suffix.lower(),
                                "review_command": review,
                                "trash_command": trash,
                                "direct_delete_command": direct,
                            }
                        )
                    except OSError:
                        continue
        except OSError:
            continue
    archives.sort(key=lambda item: item["size"], reverse=True)
    return archives


def content_duplicate_scan_roots(roots: list[str]) -> list[Path]:
    downloads = Path.home() / "Downloads"
    return [downloads] if downloads.exists() else []


def file_category_for_content_duplicate(suffix: str) -> str:
    suffix = suffix.lower()
    if suffix in DOCUMENT_EXTENSIONS:
        return "文档"
    if suffix in IMAGE_EXTENSIONS:
        return "图片"
    if suffix in VIDEO_EXTENSIONS:
        return "视频"
    return "文件"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_content_duplicate_files(roots: list[str]) -> list[dict[str, Any]]:
    by_size: dict[int, list[dict[str, Any]]] = {}
    for root in content_duplicate_scan_roots(roots):
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    for entry in iterator:
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                stack.append(Path(entry.path))
                                continue
                            if not entry.is_file(follow_symlinks=False):
                                continue
                            path = Path(entry.path)
                            suffix = path.suffix.lower()
                            if suffix not in CONTENT_DUPLICATE_EXTENSIONS:
                                continue
                            stat_result = entry.stat(follow_symlinks=False)
                            size = int(stat_result.st_size)
                            if size <= 0:
                                continue
                            category = file_category_for_content_duplicate(suffix)
                            review, trash, direct = commands_for(str(path), "file")
                            item = {
                                "id": stable_id(str(path)),
                                "path": str(path),
                                "name": path.name,
                                "size": size,
                                "modified": getattr(stat_result, "st_mtime", None),
                                "extension": suffix,
                                "category": category,
                                "review_command": review,
                                "trash_command": trash,
                                "direct_delete_command": direct,
                            }
                            by_size.setdefault(size, []).append(item)
                        except OSError:
                            continue
            except OSError:
                continue

    by_hash: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for same_size_items in by_size.values():
        if len(same_size_items) < 2:
            continue
        for item in same_size_items:
            try:
                digest = sha256_file(Path(item["path"]))
            except OSError:
                continue
            item["sha256"] = digest
            by_hash.setdefault((digest, item["category"]), []).append(item)

    result: list[dict[str, Any]] = []
    for (digest, category), items in by_hash.items():
        if len(items) < 2:
            continue
        items.sort(key=lambda item: (item["modified"] or 0, item["path"]))
        primary = items[0]
        candidates = items[1:]
        if not candidates:
            continue
        candidate_size = sum(item["size"] for item in candidates)
        result.append(
            {
                "id": stable_id("content-duplicate:" + digest + category),
                "sha256": digest,
                "category": category,
                "primary": primary,
                "candidates": candidates,
                "count": len(items),
                "candidate_count": len(candidates),
                "candidate_size": candidate_size,
            }
        )
    result.sort(key=lambda group: group["candidate_size"], reverse=True)
    return result[:100]


def scan_roots(roots: list[str], min_size: int, top: int, follow_symlinks: bool) -> tuple[list[ScanRecord], list[str]]:
    records: list[ScanRecord] = []
    errors: list[str] = []
    dir_info: dict[str, dict[str, Any]] = {}

    def add_file_to_parent(parent: str, size: int) -> None:
        if parent in dir_info:
            dir_info[parent]["size"] += size
            dir_info[parent]["files"] += 1

    for raw_root in roots:
        root = normalize_path(raw_root)
        stack: list[tuple[str, bool]] = [(root, False)]
        while stack:
            current, visited = stack.pop()
            try:
                stat_result = os.stat(current) if follow_symlinks else os.lstat(current)
            except OSError as exc:
                errors.append(f"{current}: {exc}")
                parent = str(Path(current).parent)
                if parent in dir_info:
                    dir_info[parent]["errors"] += 1
                continue

            is_dir = os.path.isdir(current) and (follow_symlinks or not os.path.islink(current))
            if not is_dir:
                size = int(getattr(stat_result, "st_size", 0) or 0)
                parent = str(Path(current).parent)
                add_file_to_parent(parent, size)
                if size >= min_size:
                    kind = "symlink" if os.path.islink(current) else "file"
                    tier, category, reason = classify(current, kind)
                    review, trash, direct = commands_for(current, kind)
                    records.append(
                        ScanRecord(
                            id=stable_id(current),
                            path=current,
                            name=Path(current).name or current,
                            kind=kind,
                            size=size,
                            files=1,
                            dirs=0,
                            modified=getattr(stat_result, "st_mtime", None),
                            tier=tier,
                            category=category,
                            reason=reason,
                            review_command=review,
                            trash_command=trash,
                            direct_delete_command=direct,
                        )
                    )
                continue

            if not visited:
                if current not in dir_info:
                    dir_info[current] = {"size": 0, "files": 0, "dirs": 0, "errors": 0, "modified": getattr(stat_result, "st_mtime", None)}
                stack.append((current, True))
                try:
                    with os.scandir(current) as iterator:
                        for entry in iterator:
                            stack.append((entry.path, False))
                except OSError as exc:
                    errors.append(f"{current}: {exc}")
                    dir_info[current]["errors"] += 1
                continue

            info = dir_info[current]
            parent = str(Path(current).parent)
            if parent in dir_info and parent != current:
                dir_info[parent]["size"] += info["size"]
                dir_info[parent]["files"] += info["files"]
                dir_info[parent]["dirs"] += info["dirs"] + 1
                dir_info[parent]["errors"] += info["errors"]
            if info["size"] >= min_size:
                tier, category, reason = classify(current, "directory")
                review, trash, direct = commands_for(current, "directory")
                records.append(
                    ScanRecord(
                        id=stable_id(current),
                        path=current,
                        name=Path(current).name or current,
                        kind="directory",
                        size=int(info["size"]),
                        files=int(info["files"]),
                        dirs=int(info["dirs"]),
                        modified=info["modified"],
                        tier=tier,
                        category=category,
                        reason=reason,
                        review_command=review,
                        trash_command=trash,
                        direct_delete_command=direct,
                        errors=int(info["errors"]),
                    )
                )

    records.sort(key=lambda item: item.size, reverse=True)
    return records[:top], errors


def report_payload(
    records: list[ScanRecord],
    errors: list[str],
    roots: list[str],
    include_content_duplicates: bool = True,
) -> dict[str, Any]:
    now = time.time()
    return {
        "schema": "storage-cleanup-report-v1",
        "generated_at": now,
        "generated_at_local": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now)),
        "platform": platform.platform(),
        "roots": roots,
        "disk_usage": collect_disk_usage(roots),
        "summary": {
            "items": len(records),
            "total_size": sum(item.size for item in records),
            "errors": len(errors),
        },
        "tiers": TIER_META,
        "items": [dataclasses.asdict(item) for item in records],
        "download_archives": collect_download_archives(),
        "content_duplicate_files": collect_content_duplicate_files(roots) if include_content_duplicates else [],
        "content_duplicate_scan_skipped": not include_content_duplicates,
        "errors": errors[:500],
    }


def html_report(payload: dict[str, Any]) -> str:
    payload = {**payload, "tiers": TIER_META}
    data = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClearSpace Report</title>
<style>
:root {{
  color-scheme: light;
  --bg: #eef6fb;
  --panel: #ffffff;
  --text: #102033;
  --text-soft: #29445f;
  --muted: #64748b;
  --line: rgba(148, 163, 184, .32);
  --line-strong: rgba(37, 99, 235, .28);
  --blue: #2f6df6;
  --blue-soft: #eaf4ff;
  --cyan: #16b6d6;
  --green: #15b981;
  --green-soft: #e9fbf3;
  --yellow: #d89414;
  --yellow-soft: #fff7e8;
  --red: #e04444;
  --red-soft: #fff0f0;
  --glass: rgba(255, 255, 255, .72);
  --shadow: 0 18px 50px rgba(22, 42, 80, .12);
  --shadow-soft: 0 6px 18px rgba(22, 42, 80, .08);
}}
* {{ box-sizing: border-box; }}
body {{ margin: 0; font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background:
  radial-gradient(circle at 10% -6%, rgba(57, 210, 197, .32), transparent 30%),
  radial-gradient(circle at 84% 0%, rgba(47, 109, 246, .24), transparent 32%),
  radial-gradient(circle at 70% 22%, rgba(21, 185, 129, .16), transparent 28%),
  linear-gradient(180deg, #fbfdff 0, var(--bg) 420px); color: var(--text); }}
header {{ padding: 26px 20px 10px; background: transparent; color: var(--text); }}
.header-inner {{ max-width: 1180px; margin: 0 auto; display: grid; gap: 16px; padding: 14px 18px 18px; border: 1px solid rgba(255,255,255,.78); border-radius: 8px; background: linear-gradient(135deg, rgba(255,255,255,.9), rgba(240,250,255,.74)); box-shadow: var(--shadow); backdrop-filter: blur(24px); position: relative; overflow: hidden; }}
.header-inner::before {{ content: ""; position: absolute; inset: -80px -100px auto auto; width: 300px; height: 220px; border-radius: 50%; background: radial-gradient(circle, rgba(31, 193, 177, .26), transparent 68%); pointer-events: none; }}
.app-chrome {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; position: relative; color: #64748b; font-size: 12px; font-weight: 800; }}
.window-dots {{ display: inline-flex; gap: 7px; }}
.window-dots span {{ width: 11px; height: 11px; border-radius: 999px; box-shadow: inset 0 0 0 1px rgba(15,23,42,.08); }}
.window-dots span:nth-child(1) {{ background: #ff5f57; }}
.window-dots span:nth-child(2) {{ background: #febc2e; }}
.window-dots span:nth-child(3) {{ background: #28c840; }}
.app-status {{ display: inline-flex; align-items: center; gap: 7px; }}
.app-status::before {{ content: ""; width: 7px; height: 7px; border-radius: 999px; background: var(--green); box-shadow: 0 0 0 4px rgba(21,185,129,.12); }}
.brand-row {{ display: flex; align-items: center; gap: 14px; position: relative; }}
.brand-mark {{ width: 52px; height: 52px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; color: white; background: linear-gradient(145deg, #43d2c5 0%, #2f6df6 72%); box-shadow: 0 16px 30px rgba(47, 109, 246, .24), inset 0 0 0 1px rgba(255,255,255,.38); }}
h1 {{ margin: 0; font-size: 32px; line-height: 1.06; letter-spacing: 0; }}
h2 {{ margin: 0; font-size: 18px; }}
.sub {{ color: var(--text-soft); max-width: 900px; margin-top: 4px; }}
.safety-pills {{ display: flex; gap: 8px; flex-wrap: wrap; }}
.safety-pill {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 999px; background: rgba(255,255,255,.68); color: #24415f; border: 1px solid rgba(148,163,184,.28); font-size: 12px; font-weight: 800; box-shadow: 0 1px 0 rgba(255,255,255,.88) inset; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 14px 20px 24px; }}
.toolbar, .panel-card, details.tier {{ background: var(--glass); border: 1px solid rgba(255,255,255,.78); border-radius: 8px; box-shadow: var(--shadow-soft); backdrop-filter: blur(18px); }}
.toolbar {{ display: flex; gap: 10px; align-items: center; padding: 10px; position: sticky; top: 10px; z-index: 2; }}
input, select, button {{ font: inherit; border: 1px solid var(--line); border-radius: 8px; padding: 8px 10px; background: rgba(255,255,255,.84); color: var(--text); }}
input, select {{ height: 38px; }}
input {{ flex: 1; min-width: 180px; }}
input:focus, select:focus, button:focus-visible {{ outline: 3px solid rgba(47,109,246,.16); outline-offset: 2px; border-color: rgba(47,109,246,.55); }}
button {{ cursor: pointer; display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 34px; font-weight: 800; transition: transform .14s ease, border-color .14s ease, background .14s ease, box-shadow .14s ease; }}
button:hover:not(:disabled) {{ transform: translateY(-1px); border-color: var(--line-strong); box-shadow: 0 10px 24px rgba(22, 42, 80, .11); }}
button.primary {{ background: linear-gradient(135deg, #32c7bd, #2f6df6); color: white; border-color: transparent; box-shadow: 0 14px 28px rgba(47, 109, 246, .22); }}
button.primary:hover:not(:disabled) {{ background: linear-gradient(135deg, #29b9b0, #2563eb); border-color: transparent; }}
button.danger {{ background: var(--red-soft); color: #991b1b; border-color: #fecaca; }}
button.danger:hover:not(:disabled) {{ background: #fee2e2; border-color: #fca5a5; }}
button.btn-keep.active {{ background: #f1f5f9; color: #334155; border-color: #cbd5e1; }}
button:disabled {{ opacity: .48; cursor: not-allowed; transform: none; box-shadow: none; }}
button, .actions button {{ white-space: nowrap; }}
.icon {{ width: 15px; height: 15px; flex: 0 0 auto; stroke-width: 2.1; }}
.icon-lg {{ width: 22px; height: 22px; }}
.dashboard {{ display: grid; grid-template-columns: 1.18fr 1fr 1fr; gap: 14px; margin: 16px 0; }}
.panel-card {{ overflow: hidden; margin: 16px 0; }}
.panel-card > summary {{ background: linear-gradient(180deg, rgba(255,255,255,.88), rgba(248,252,255,.7)); border-bottom: 1px solid var(--line); }}
.panel-card:not([open]) > summary {{ border-bottom: 0; }}
.panel-body {{ padding: 16px; }}
.dashboard-card {{ margin: 0; }}
.dashboard-card h2 {{ margin-bottom: 12px; }}
.dashboard-card:first-child {{ background: linear-gradient(145deg, rgba(255,255,255,.9), rgba(235,250,255,.82)); }}
.disk-meter {{ display: flex; height: 22px; border-radius: 999px; overflow: hidden; background: #dbe8f2; margin: 16px 0; box-shadow: inset 0 0 0 1px rgba(16, 32, 51, .08), 0 12px 28px rgba(47,109,246,.10); }}
.disk-segment {{ height: 100%; width: var(--segment-width); min-width: var(--segment-min, 0); background: var(--segment-color); }}
.disk-legend {{ display: grid; gap: 6px; margin-top: 12px; }}
.legend-row {{ display: grid; grid-template-columns: 12px 1fr auto; gap: 8px; align-items: center; color: #334155; }}
.legend-dot {{ width: 10px; height: 10px; border-radius: 999px; background: var(--dot-color); }}
.disk-numbers {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; }}
.disk-numbers strong {{ display: block; font-size: 20px; }}
.rank-list {{ display: grid; gap: 8px; }}
.rank-item {{ display: grid; grid-template-columns: 26px 1fr auto auto; gap: 8px; align-items: center; padding: 10px; border: 1px solid rgba(148,163,184,.24); border-radius: 8px; background: rgba(255,255,255,.64); }}
.rank-item:hover {{ background: rgba(255,255,255,.9); border-color: rgba(47,109,246,.24); }}
.rank-index {{ display: inline-flex; align-items: center; justify-content: center; width: 24px; height: 24px; border-radius: 999px; background: linear-gradient(135deg, #e6f7ff, #dbeafe); color: #2563eb; font-weight: 900; font-size: 12px; }}
.rank-path {{ overflow-wrap: anywhere; color: #334155; }}
.advice-list {{ margin: 0; padding-left: 18px; display: grid; gap: 8px; }}
.advice-list li {{ color: #334155; }}
.archive-panel {{ background: var(--glass); border: 1px solid rgba(255,255,255,.78); border-radius: 8px; margin: 16px 0; box-shadow: var(--shadow-soft); overflow: hidden; backdrop-filter: blur(18px); }}
.archive-panel > summary {{ background: linear-gradient(180deg, rgba(255,255,255,.88), rgba(248,252,255,.7)); border-bottom: 1px solid var(--line); }}
.archive-panel:not([open]) > summary {{ border-bottom: 0; }}
.archive-header {{ display: flex; justify-content: space-between; gap: 12px; align-items: start; margin-bottom: 12px; }}
.archive-summary {{ display: flex; gap: 10px; flex-wrap: wrap; color: var(--muted); }}
.archive-list {{ display: grid; gap: 8px; }}
.archive-item {{ display: grid; grid-template-columns: 1fr auto; gap: 10px; align-items: center; padding: 11px; border: 1px solid rgba(148,163,184,.24); border-radius: 8px; background: rgba(255,255,255,.62); }}
.archive-item:hover {{ background: rgba(255,255,255,.9); border-color: rgba(47,109,246,.24); }}
.archive-item.processed {{ color: #64748b; background: #f1f5f9; }}
.archive-item.processed .archive-path {{ text-decoration: line-through; }}
.archive-item.kept {{ color: var(--text); background: #f8fafc; }}
.archive-item.kept .archive-path {{ text-decoration: none; }}
.archive-path {{ overflow-wrap: anywhere; font-weight: 600; }}
.archive-meta {{ color: var(--muted); display: flex; gap: 8px; flex-wrap: wrap; margin-top: 3px; }}
.duplicate-group {{ border: 1px solid rgba(148,163,184,.24); border-radius: 8px; margin-top: 10px; overflow: hidden; background: rgba(255,255,255,.62); }}
.duplicate-group > summary {{ background: rgba(248,250,252,.72); }}
.duplicate-primary {{ padding: 10px; background: #f8fafc; border-top: 1px solid var(--line); }}
.duplicate-candidates {{ display: grid; gap: 8px; padding: 10px; border-top: 1px solid var(--line); }}
.stats {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px; margin: 16px 0; overflow: hidden; }}
.stat {{ padding: 12px; background: rgba(255,255,255,.66); border: 1px solid rgba(148,163,184,.22); border-radius: 8px; }}
.label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }}
.value {{ font-size: 22px; font-weight: 850; letter-spacing: 0; }}
.tier-overview {{ display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; margin: 16px 0; }}
.tier-card {{ border: 1px solid rgba(148,163,184,.24); border-left: 6px solid var(--tier-color); border-radius: 8px; background: linear-gradient(145deg, var(--tier-soft), rgba(255,255,255,.78)); padding: 14px; text-align: left; cursor: pointer; align-items: stretch; justify-content: start; display: block; min-height: 152px; box-shadow: 0 8px 24px rgba(22,42,80,.06); }}
.tier-card:hover {{ border-color: var(--tier-color); transform: translateY(-2px); }}
.tier-card.active {{ box-shadow: inset 0 0 0 2px var(--tier-color), 0 12px 28px rgba(22,42,80,.08); }}
.tier-card h2 {{ display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 10px; color: var(--tier-color); }}
.tier-card .metrics {{ display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-bottom: 10px; }}
.tier-card .metric {{ background: rgba(255,255,255,.72); border: 1px solid #ffffffaa; border-radius: 6px; padding: 8px; }}
.tier-card .metric strong {{ display: block; font-size: 18px; color: var(--text); }}
.tier-card .top-path {{ color: #334155; overflow-wrap: anywhere; }}
.notice {{ padding: 12px 14px; background: rgba(234,244,255,.78); border: 1px solid rgba(147,197,253,.38); border-radius: 8px; color: #1e3a8a; margin: 16px 0; backdrop-filter: blur(12px); }}
details.tier {{ margin: 16px 0; overflow: hidden; }}
summary {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 14px 16px; cursor: pointer; font-weight: 850; list-style: none; }}
summary::-webkit-details-marker {{ display: none; }}
summary::after {{ content: ""; width: 9px; height: 9px; border-right: 2px solid #64748b; border-bottom: 2px solid #64748b; transform: rotate(45deg); transition: transform .15s ease; margin-left: auto; flex: 0 0 auto; }}
details[open] > summary::after {{ transform: rotate(225deg); }}
summary:hover {{ background: rgba(255,255,255,.5); }}
.summary-title {{ display: inline-flex; align-items: center; gap: 8px; min-width: 0; }}
.summary-title > .icon {{ color: var(--blue); padding: 4px; width: 24px; height: 24px; border-radius: 7px; background: rgba(47,109,246,.08); }}
.summary-title .group-title {{ min-width: 0; }}
.summary-meta {{ display: inline-flex; align-items: center; gap: 10px; flex-wrap: wrap; justify-content: flex-end; margin-left: auto; }}
.summary-meta button {{ min-height: 30px; padding: 6px 9px; }}
.tier-count {{ color: var(--muted); font-weight: 500; }}
.path-group {{ border-top: 1px solid var(--line); }}
.path-group > summary {{ background: rgba(248,250,252,.72); border-left: 4px solid #cbd5e1; }}
.group-title {{ overflow-wrap: anywhere; }}
.group-subtitle {{ color: var(--muted); font-weight: 500; }}
.group-children {{ border-top: 1px solid var(--line); }}
.group-children .item {{ padding-left: 28px; }}
.single-item-wrap {{ border-top: 1px solid var(--line); }}
.single-item-wrap .item {{ border-top: 0; }}
.item {{ border-top: 1px solid var(--line); padding: 14px 16px; display: grid; grid-template-columns: 1fr auto; gap: 12px; }}
.item:hover {{ background: rgba(255,255,255,.56); }}
.item.processed {{ background: #f8fafc; color: #64748b; }}
.item.processed h3 {{ text-decoration: line-through; text-decoration-thickness: 1px; }}
.item.kept {{ color: var(--text); background: #f8fafc; }}
.item.kept h3 {{ text-decoration: none; }}
.item.missing {{ background: #f1f5f9; }}
.item h3 {{ margin: 0; font-size: 15px; overflow-wrap: anywhere; }}
.meta {{ color: var(--muted); display: flex; gap: 10px; flex-wrap: wrap; margin-top: 4px; }}
.reason {{ margin: 10px 0; color: #334155; }}
.actions {{ display: flex; gap: 8px; flex-wrap: wrap; align-items: start; justify-content: end; }}
.cmd {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; background: #f1f5f9; border: 1px solid var(--line); padding: 8px; border-radius: 6px; overflow-wrap: anywhere; margin-top: 8px; }}
.badge {{ display: inline-flex; align-items: center; gap: 5px; border-radius: 999px; padding: 3px 8px; color: white; font-size: 12px; font-weight: 800; }}
.status-badge {{ display: inline-flex; align-items: center; gap: 5px; border-radius: 999px; padding: 3px 8px; color: #334155; background: #e2e8f0; font-size: 12px; font-weight: 800; }}
.status-badge .icon {{ width: 13px; height: 13px; }}
.status-badge.trashed {{ color: #166534; background: #dcfce7; }}
.status-badge.deleted {{ color: #991b1b; background: #fee2e2; }}
.status-badge.missing {{ color: #475569; background: #e2e8f0; }}
.status-badge.kept {{ color: #334155; background: #e2e8f0; }}
.toast {{ position: fixed; right: 18px; bottom: 18px; z-index: 10; max-width: min(440px, calc(100vw - 36px)); padding: 12px 14px; border-radius: 8px; color: white; background: linear-gradient(135deg, #102033, #1f3b5f); box-shadow: 0 18px 42px rgba(16,32,51,.28); }}
.empty {{ padding: 18px; color: var(--muted); }}

/* Bold visual direction: high-contrast, minimal, colorful cleanup dashboard. */
:root {{
  color-scheme: dark;
  --bg: #080b16;
  --panel: #111827;
  --text: #f7fbff;
  --text-soft: #b9c8e9;
  --muted: #8da2c5;
  --line: rgba(255,255,255,.13);
  --line-strong: rgba(94,234,212,.45);
  --blue: #4d7cff;
  --blue-soft: rgba(77,124,255,.13);
  --cyan: #27e7d7;
  --green: #31f6b1;
  --green-soft: rgba(49,246,177,.13);
  --yellow: #ffd166;
  --yellow-soft: rgba(255,209,102,.14);
  --red: #ff4d7d;
  --red-soft: rgba(255,77,125,.13);
  --glass: rgba(13, 18, 35, .78);
  --shadow: 0 24px 80px rgba(0,0,0,.42);
  --shadow-soft: 0 16px 42px rgba(0,0,0,.26);
}}
body {{ background:
  radial-gradient(circle at 10% -10%, rgba(39,231,215,.36), transparent 25%),
  radial-gradient(circle at 92% 4%, rgba(255,77,125,.30), transparent 28%),
  radial-gradient(circle at 54% 16%, rgba(77,124,255,.28), transparent 32%),
  linear-gradient(180deg, #070a14 0, #0a1020 46%, #090c16 100%); color: var(--text); }}
header {{ color: var(--text); }}
.header-inner {{ border-color: rgba(255,255,255,.13); background:
  linear-gradient(135deg, rgba(15,23,42,.92), rgba(19,25,48,.68)),
  radial-gradient(circle at 88% 20%, rgba(39,231,215,.22), transparent 34%);
  box-shadow: 0 30px 100px rgba(0,0,0,.44), inset 0 1px 0 rgba(255,255,255,.10); }}
.header-inner::before {{ background: radial-gradient(circle, rgba(255,77,125,.26), transparent 68%); }}
.app-chrome {{ color: rgba(226,232,240,.72); }}
.brand-mark {{ border-radius: 8px; background: conic-gradient(from 210deg, #31f6b1, #27e7d7, #4d7cff, #ff4d7d, #31f6b1); box-shadow: 0 18px 46px rgba(39,231,215,.20), 0 0 50px rgba(77,124,255,.16), inset 0 0 0 1px rgba(255,255,255,.28); }}
.sub {{ color: var(--text-soft); }}
.safety-pill {{ color: #e8f7ff; background: rgba(255,255,255,.075); border-color: rgba(255,255,255,.12); box-shadow: inset 0 1px 0 rgba(255,255,255,.10); }}
.toolbar, .panel-card, details.tier, .archive-panel {{ background: var(--glass); border-color: rgba(255,255,255,.12); box-shadow: var(--shadow-soft); }}
.toolbar {{ background: rgba(10,15,30,.82); }}
input, select, button {{ color: var(--text); background: rgba(255,255,255,.07); border-color: rgba(255,255,255,.13); }}
input::placeholder {{ color: rgba(185,200,233,.64); }}
button {{ color: var(--text); }}
button.primary {{ background: linear-gradient(135deg, #31f6b1 0%, #27e7d7 44%, #4d7cff 100%); color: #06111c; box-shadow: 0 16px 36px rgba(39,231,215,.24); }}
button.primary:hover:not(:disabled) {{ background: linear-gradient(135deg, #66ffd0 0%, #3cf4e5 44%, #6f93ff 100%); }}
button.danger {{ color: #ffdce5; background: rgba(255,77,125,.11); border-color: rgba(255,77,125,.32); }}
button.danger:hover:not(:disabled) {{ background: rgba(255,77,125,.18); border-color: rgba(255,77,125,.5); }}
button.btn-keep.active {{ color: #d9f7ff; background: rgba(39,231,215,.10); border-color: rgba(39,231,215,.34); }}
.panel-card > summary, .archive-panel > summary {{ background: linear-gradient(180deg, rgba(255,255,255,.065), rgba(255,255,255,.035)); }}
summary:hover {{ background: rgba(255,255,255,.07); }}
summary::after {{ border-color: rgba(226,232,240,.78); }}
.summary-title > .icon {{ color: #27e7d7; background: rgba(39,231,215,.10); box-shadow: inset 0 0 0 1px rgba(39,231,215,.12); }}
.dashboard-card:first-child {{ background:
  radial-gradient(circle at 12% 12%, rgba(49,246,177,.16), transparent 30%),
  linear-gradient(145deg, rgba(16,24,46,.92), rgba(10,15,30,.82)); }}
.disk-meter {{ background: rgba(255,255,255,.11); box-shadow: inset 0 0 0 1px rgba(255,255,255,.09), 0 18px 36px rgba(39,231,215,.10); }}
.disk-numbers > div, .stat, .rank-item, .archive-item, .duplicate-group, .tier-card .metric {{ background: rgba(255,255,255,.055); border-color: rgba(255,255,255,.10); }}
.disk-numbers strong, .value {{ color: #ffffff; }}
.legend-row, .rank-path, .advice-list li, .tier-card .top-path, .reason, .archive-path, .group-title {{ color: #dbeafe; }}
.label, .tier-count, .group-subtitle, .archive-meta, .meta {{ color: var(--muted); }}
.rank-item:hover, .archive-item:hover, .item:hover {{ background: rgba(255,255,255,.085); border-color: rgba(39,231,215,.22); }}
.rank-index {{ color: #06111c; background: linear-gradient(135deg, #31f6b1, #27e7d7); }}
.tier-card {{ border-color: rgba(255,255,255,.12); background:
  radial-gradient(circle at 100% 0%, color-mix(in srgb, var(--tier-color) 22%, transparent), transparent 34%),
  linear-gradient(145deg, rgba(255,255,255,.075), rgba(255,255,255,.035)); box-shadow: 0 18px 50px rgba(0,0,0,.24); }}
.tier-card .metric strong {{ color: var(--text); }}
.notice {{ color: #d9f7ff; background: rgba(39,231,215,.08); border-color: rgba(39,231,215,.20); }}
.path-group > summary, .duplicate-group > summary {{ background: rgba(255,255,255,.045); }}
.item.processed, .archive-item.processed, .item.kept, .archive-item.kept, .item.missing {{ background: rgba(255,255,255,.045); color: var(--muted); }}
.status-badge {{ color: #dbeafe; background: rgba(255,255,255,.10); }}
.status-badge.trashed {{ color: #b8ffd8; background: rgba(49,246,177,.12); }}
.status-badge.deleted {{ color: #ffd4dd; background: rgba(255,77,125,.13); }}
.status-badge.missing {{ color: #dbeafe; background: rgba(255,255,255,.10); }}
.status-badge.kept {{ color: #d9f7ff; background: rgba(39,231,215,.10); }}
.comparison {{ margin: 16px 0 0; padding: 16px; border: 1px solid rgba(255,255,255,.12); border-radius: 8px; background:
  radial-gradient(circle at 82% 0%, rgba(77,124,255,.22), transparent 34%),
  linear-gradient(145deg, rgba(255,255,255,.075), rgba(255,255,255,.035)); }}
.comparison-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 14px; }}
.comparison-title {{ display: grid; gap: 2px; }}
.comparison-title strong {{ font-size: 16px; }}
.delta-pill {{ display: inline-flex; align-items: center; padding: 6px 10px; border-radius: 999px; font-weight: 900; color: #06111c; background: linear-gradient(135deg, #31f6b1, #27e7d7); box-shadow: 0 12px 28px rgba(39,231,215,.20); }}
.delta-pill.down {{ color: #fff; background: linear-gradient(135deg, #ff4d7d, #a855f7); }}
.compare-grid {{ display: grid; gap: 12px; }}
.compare-row {{ display: grid; grid-template-columns: 82px 1fr auto; gap: 10px; align-items: center; }}
.compare-name {{ color: var(--text-soft); font-weight: 850; }}
.compare-track {{ height: 18px; border-radius: 999px; overflow: hidden; background: rgba(255,255,255,.10); box-shadow: inset 0 0 0 1px rgba(255,255,255,.08); }}
.compare-fill {{ height: 100%; width: var(--free-width); min-width: 4px; border-radius: inherit; background: linear-gradient(90deg, #31f6b1, #27e7d7, #4d7cff); box-shadow: 0 0 24px rgba(39,231,215,.34); }}
.compare-row.scan .compare-fill {{ opacity: .56; filter: saturate(.8); }}
.compare-value {{ color: #fff; font-weight: 900; }}
.compare-caption {{ margin-top: 10px; color: var(--muted); font-size: 12px; }}
h1 {{ font-size: clamp(40px, 5vw, 76px); line-height: .9; letter-spacing: -.02em; }}
.sub {{ max-width: 720px; font-size: 15px; }}
.header-inner {{ padding: 18px 22px 24px; min-height: 190px; align-content: space-between; }}
.brand-row {{ align-items: end; }}
.brand-mark {{ width: 68px; height: 68px; }}
.icon-lg {{ width: 30px; height: 30px; }}
.dashboard {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }}
.dashboard-card:first-child {{ grid-column: 1 / -1; }}
.dashboard-card:first-child > summary {{ min-height: 72px; }}
.dashboard-card:first-child .summary-title span:last-child {{ font-size: 24px; }}
.dashboard-card:first-child .tier-count {{ font-size: 15px; }}
.disk-visual {{ display: grid; grid-template-columns: minmax(220px, 320px) 1fr; gap: 28px; align-items: center; }}
.disk-orb {{ width: min(320px, 100%); aspect-ratio: 1; border-radius: 50%; padding: 18px; background:
  conic-gradient(from 220deg, var(--green) 0 var(--free-percent), rgba(255,255,255,.12) var(--free-percent) 100%);
  box-shadow: 0 0 70px rgba(39,231,215,.18), inset 0 0 0 1px rgba(255,255,255,.10); position: relative; }}
.disk-orb::before {{ content: ""; position: absolute; inset: -10px; border-radius: inherit; background: conic-gradient(from 0deg, rgba(49,246,177,.34), rgba(77,124,255,.08), rgba(255,77,125,.22), rgba(49,246,177,.34)); filter: blur(22px); opacity: .74; z-index: -1; }}
.disk-orb-inner {{ height: 100%; border-radius: inherit; background: radial-gradient(circle at 34% 24%, rgba(255,255,255,.11), transparent 30%), #090e1d; display: grid; place-items: center; text-align: center; padding: 24px; box-shadow: inset 0 0 0 1px rgba(255,255,255,.12); }}
.orb-label {{ color: var(--muted); font-size: 12px; font-weight: 900; letter-spacing: .08em; text-transform: uppercase; }}
.orb-number {{ margin-top: 4px; font-size: clamp(42px, 7vw, 82px); line-height: .9; font-weight: 950; letter-spacing: -.06em; color: #fff; }}
.orb-sub {{ margin-top: 8px; color: var(--text-soft); font-weight: 850; }}
.disk-hero-copy {{ min-width: 0; }}
.hero-kicker {{ color: var(--green); font-size: 13px; font-weight: 950; letter-spacing: .1em; text-transform: uppercase; }}
.hero-line {{ margin: 6px 0 18px; font-size: clamp(28px, 4vw, 52px); line-height: .96; font-weight: 950; letter-spacing: -.045em; color: #fff; }}
.hero-line small {{ display: block; margin-top: 8px; color: #ff8aa8; font-size: 14px; line-height: 1.35; letter-spacing: 0; font-weight: 750; }}
.disk-numbers {{ grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 12px; }}
.disk-numbers > div {{ padding: 14px; border-radius: 8px; }}
.disk-numbers strong {{ font-size: 30px; letter-spacing: -.04em; }}
.disk-legend {{ grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px 12px; }}
.legend-row {{ grid-template-columns: 12px minmax(0, 1fr) auto; }}
.comparison {{ padding: 18px; margin-top: 18px; }}
.comparison-head {{ margin-bottom: 18px; }}
.comparison-title strong {{ font-size: 24px; letter-spacing: -.03em; }}
.comparison-stage {{ display: grid; grid-template-columns: 1fr auto 1fr; gap: 16px; align-items: center; }}
.compare-card {{ min-width: 0; border: 1px solid rgba(255,255,255,.11); border-radius: 8px; padding: 16px; background: linear-gradient(145deg, rgba(255,255,255,.08), rgba(255,255,255,.035)); }}
.compare-card.current {{ border-color: rgba(49,246,177,.26); box-shadow: 0 0 42px rgba(49,246,177,.08); }}
.mini-ring {{ width: 154px; max-width: 100%; aspect-ratio: 1; margin: 0 auto 12px; border-radius: 50%; padding: 12px; background: conic-gradient(from 220deg, var(--ring-color) 0 var(--free-percent), rgba(255,255,255,.12) var(--free-percent) 100%); box-shadow: 0 0 44px var(--ring-glow); }}
.mini-ring-inner {{ height: 100%; border-radius: inherit; background: #090e1d; display: grid; place-items: center; text-align: center; box-shadow: inset 0 0 0 1px rgba(255,255,255,.10); }}
.mini-ring-number {{ font-size: 28px; font-weight: 950; letter-spacing: -.04em; color: #fff; }}
.mini-ring-label {{ color: var(--muted); font-size: 11px; font-weight: 900; letter-spacing: .08em; text-transform: uppercase; }}
.compare-card-title {{ color: var(--text-soft); font-size: 13px; font-weight: 900; text-align: center; }}
.compare-free {{ margin-top: 2px; color: #fff; font-size: 32px; line-height: 1; font-weight: 950; letter-spacing: -.05em; text-align: center; }}
.compare-used {{ margin-top: 8px; color: var(--muted); font-size: 12px; text-align: center; }}
.compare-arrow {{ width: 74px; height: 74px; border-radius: 50%; display: grid; place-items: center; color: #06111c; font-size: 30px; font-weight: 950; background: linear-gradient(135deg, #31f6b1, #27e7d7, #4d7cff); box-shadow: 0 18px 44px rgba(39,231,215,.24); }}
.compare-arrow.down {{ color: #fff; background: linear-gradient(135deg, #ff4d7d, #a855f7); box-shadow: 0 18px 44px rgba(255,77,125,.22); }}
.delta-pill {{ font-size: 15px; }}
.stats {{ grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }}
.stat .value {{ font-size: 28px; letter-spacing: -.04em; }}
.rank-index {{ width: 30px; height: 30px; }}
.rank-item {{ grid-template-columns: 32px 1fr auto auto; padding: 12px; }}
.tier-card h2 {{ font-size: 21px; }}
.tier-card .metric strong {{ font-size: 26px; letter-spacing: -.04em; }}
@media (max-width: 760px) {{
  header {{ padding: 20px; }}
  main {{ padding: 12px; }}
  .toolbar {{ position: static; flex-direction: column; align-items: stretch; }}
  .dashboard {{ grid-template-columns: 1fr; }}
  .archive-header, .archive-item {{ grid-template-columns: 1fr; display: grid; }}
  .stats {{ grid-template-columns: 1fr 1fr; }}
  .tier-overview {{ grid-template-columns: 1fr; }}
  .rank-item {{ grid-template-columns: 26px 1fr; }}
  .rank-item strong, .rank-item button {{ grid-column: 2; justify-self: start; }}
  .compare-row {{ grid-template-columns: 1fr; }}
  .disk-visual, .comparison-stage {{ grid-template-columns: 1fr; }}
.compare-arrow {{ margin: 0 auto; transform: rotate(90deg); }}
  .disk-legend {{ grid-template-columns: 1fr; }}
  .item {{ grid-template-columns: 1fr; }}
  .actions {{ justify-content: start; }}
}}

/* Product brand system. */
.brand-row {{ gap: 28px; align-items: stretch; justify-content: space-between; }}
.brand-lockup {{ min-width: 0; display: flex; align-items: center; gap: 18px; }}
.brand-aside {{ width: min(360px, 34%); display: grid; align-content: center; gap: 16px; padding-left: 24px; border-left: 1px solid rgba(255,255,255,.12); }}
.brand-aside .sub {{ max-width: 360px; margin: 0; color: #c7d7ef; font-size: 14px; line-height: 1.65; }}
.brand-mark {{ width: 92px; height: 92px; border-radius: 8px; display: inline-flex; align-items: center; justify-content: center; position: relative; overflow: hidden; flex: 0 0 auto; background:
  radial-gradient(circle at 32% 20%, rgba(255,255,255,.28), transparent 30%),
  linear-gradient(145deg, rgba(49,246,177,.16), rgba(77,124,255,.10));
  box-shadow: 0 24px 64px rgba(39,231,215,.20), 0 0 72px rgba(77,124,255,.18), inset 0 0 0 1px rgba(255,255,255,.14); }}
.brand-mark::before {{ content: ""; position: absolute; inset: -1px; border-radius: inherit; padding: 1px; background: linear-gradient(135deg, rgba(49,246,177,.9), rgba(77,124,255,.6), rgba(255,77,125,.72)); -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0); -webkit-mask-composite: xor; mask-composite: exclude; pointer-events: none; }}
.logo-glyph {{ width: 68px; height: 68px; filter: drop-shadow(0 14px 24px rgba(39,231,215,.22)); }}
.logo-orbit {{ fill: none; stroke: url(#logoSweep); stroke-width: 1.9; opacity: .95; }}
.logo-core {{ fill: url(#logoCore); stroke: rgba(255,255,255,.28); stroke-width: .7; }}
.logo-ray {{ fill: none; stroke: #efffff; stroke-width: 2.6; stroke-linecap: round; opacity: .96; }}
.logo-spark {{ fill: #31f6b1; filter: drop-shadow(0 0 8px rgba(49,246,177,.8)); }}
.brand-copy {{ min-width: 0; display: grid; gap: 6px; }}
.brand-eyebrow {{ color: #31f6b1; font-size: 12px; font-weight: 950; letter-spacing: .22em; text-transform: uppercase; }}
.wordmark {{ margin: 0; font-size: clamp(48px, 6.4vw, 88px); line-height: .82; letter-spacing: -.075em; font-weight: 950; color: #fff; font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
.wordmark span:first-child {{ color: #f8fbff; }}
.wordmark span:last-child {{ margin-left: .035em; color: transparent; background: linear-gradient(100deg, #31f6b1 0%, #27e7d7 36%, #7da0ff 78%); -webkit-background-clip: text; background-clip: text; text-shadow: 0 0 34px rgba(39,231,215,.16); }}
.brand-copy .sub {{ max-width: 680px; color: #b9c8e9; font-size: 15px; font-weight: 650; }}

/* Typography comfort pass: keep hierarchy, reduce visual heaviness. */
.app-chrome, .safety-pill, button, .badge, .status-badge {{ font-weight: 650; }}
summary {{ font-weight: 720; }}
.rank-index {{ font-weight: 760; }}
.value, .stat .value, .disk-numbers strong, .tier-card .metric strong {{ font-weight: 760; letter-spacing: -.025em; }}
.orb-label, .mini-ring-label, .brand-eyebrow, .hero-kicker {{ font-weight: 720; letter-spacing: .12em; }}
.orb-number {{ font-weight: 800; letter-spacing: -.045em; }}
.hero-line {{ font-weight: 780; letter-spacing: -.032em; }}
.hero-line small {{ font-weight: 520; }}
.orb-sub, .compare-name, .compare-value, .compare-card-title {{ font-weight: 650; }}
.comparison-title strong {{ font-weight: 730; letter-spacing: -.02em; }}
.mini-ring-number {{ font-weight: 760; letter-spacing: -.025em; }}
.compare-free {{ font-weight: 780; letter-spacing: -.035em; }}
.compare-arrow, .delta-pill {{ font-weight: 760; }}
.tier-card h2 {{ font-weight: 720; }}
.wordmark {{ font-weight: 780; letter-spacing: -.052em; }}
.brand-copy .sub, .brand-aside .sub {{ font-weight: 450; }}
@media (max-width: 760px) {{
  .brand-row {{ align-items: start; gap: 18px; display: grid; }}
  .brand-lockup {{ align-items: start; }}
  .brand-aside {{ width: 100%; padding-left: 0; border-left: 0; padding-top: 14px; border-top: 1px solid rgba(255,255,255,.12); }}
  .brand-mark {{ width: 74px; height: 74px; }}
  .logo-glyph {{ width: 54px; height: 54px; }}
  .wordmark {{ font-size: 44px; line-height: .9; }}
}}
</style>
</head>
<body>
<header>
  <div class="header-inner">
    <div class="app-chrome">
      <div class="window-dots" aria-hidden="true"><span></span><span></span><span></span></div>
      <div class="app-status">只读报告已生成</div>
    </div>
    <div class="brand-row">
      <div class="brand-lockup">
        <div class="brand-mark" aria-hidden="true">
          <svg class="logo-glyph" viewBox="0 0 96 96" aria-hidden="true">
            <defs>
              <linearGradient id="logoSweep" x1="10" y1="10" x2="86" y2="86">
                <stop offset="0" stop-color="#31f6b1"></stop>
                <stop offset=".52" stop-color="#27e7d7"></stop>
                <stop offset="1" stop-color="#7da0ff"></stop>
              </linearGradient>
              <radialGradient id="logoCore" cx="35%" cy="25%" r="75%">
                <stop offset="0" stop-color="#ffffff" stop-opacity=".95"></stop>
                <stop offset=".28" stop-color="#31f6b1"></stop>
                <stop offset=".68" stop-color="#4d7cff"></stop>
                <stop offset="1" stop-color="#111827"></stop>
              </radialGradient>
            </defs>
            <path class="logo-orbit" d="M16 51C16 30.6 30.9 15 50.8 15c16.2 0 29.2 9.8 31.4 24.4"></path>
            <path class="logo-orbit" d="M80 45c0 20.4-14.9 36-34.8 36C29 81 16 71.2 13.8 56.6"></path>
            <path class="logo-core" d="M48 20 73 34.5v29L48 78 23 63.5v-29L48 20Z"></path>
            <path class="logo-ray" d="M35 39h30"></path>
            <path class="logo-ray" d="M31 49h25"></path>
            <path class="logo-ray" d="M39 59h21"></path>
            <circle class="logo-spark" cx="74" cy="29" r="3.2"></circle>
            <circle class="logo-spark" cx="20" cy="64" r="2.4"></circle>
          </svg>
        </div>
        <div class="brand-copy">
          <div class="brand-eyebrow">Storage Intelligence</div>
          <h1 class="wordmark"><span>Clear</span><span>Space</span></h1>
        </div>
      </div>
      <div class="brand-aside">
        <div class="sub">把杂乱磁盘转成可读、可判断、可行动的空间视图。扫描只读，处理动作由你确认。</div>
        <div class="safety-pills">
          <span class="safety-pill">扫描不改动文件</span>
          <span class="safety-pill">默认移到废纸篓</span>
          <span class="safety-pill">直接删除需再次确认</span>
        </div>
      </div>
    </div>
  </div>
</header>
<main>
  <section class="toolbar">
    <input id="filter" placeholder="筛选路径、分类、原因">
    <select id="tierFilter">
      <option value="">全部级别</option>
      <option>{TIER_AUTO}</option>
      <option>{TIER_REVIEW}</option>
      <option>{TIER_CAUTION}</option>
    </select>
    <select id="sorter">
      <option value="size-desc">按大小降序</option>
      <option value="size-asc">按大小升序</option>
      <option value="name">按名称</option>
      <option value="tier">按级别</option>
    </select>
  </section>
  <section class="dashboard" id="dashboard"></section>
  <section id="downloadArchives"></section>
  <section id="similarNames"></section>
  <section id="tierOverview"></section>
  <div class="notice" id="serviceNotice"></div>
  <section id="groups"></section>
</main>
<script>
const report = {data};
const tierOrder = ["{TIER_AUTO}", "{TIER_REVIEW}", "{TIER_CAUTION}"];
const tierClass = {{"{TIER_AUTO}":"green","{TIER_REVIEW}":"yellow","{TIER_CAUTION}":"red"}};
const deleteEnabled = location.protocol === "http:" && (location.hostname === "127.0.0.1" || location.hostname === "localhost");
const actionKey = `storage-cleanup-actions:${{report.generated_at}}:${{report.roots.join("|")}}`;
let itemActions = loadActions();
let currentDiskUsage = null;

function icon(name) {{
  const icons = {{
    archive: '<path d="M21 8v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8"></path><path d="M3 8l2-5h14l2 5"></path><path d="M10 12h4"></path>',
    bookmark: '<path d="M19 21l-7-4-7 4V5a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v16Z"></path>',
    check: '<path d="M20 6L9 17l-5-5"></path>',
    copy: '<rect x="9" y="9" width="13" height="13" rx="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>',
    disk: '<ellipse cx="12" cy="6" rx="8" ry="3"></ellipse><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"></path><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"></path>',
    duplicate: '<rect x="8" y="8" width="12" height="12" rx="2"></rect><path d="M4 16V6a2 2 0 0 1 2-2h10"></path>',
    folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2Z"></path>',
    list: '<path d="M8 6h13"></path><path d="M8 12h13"></path><path d="M8 18h13"></path><path d="M3 6h.01"></path><path d="M3 12h.01"></path><path d="M3 18h.01"></path>',
    locate: '<path d="M12 2v4"></path><path d="M12 18v4"></path><path d="M2 12h4"></path><path d="M18 12h4"></path><circle cx="12" cy="12" r="4"></circle>',
    shield: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"></path><path d="M9 12l2 2 4-4"></path>',
    spark: '<path d="M13 2l1.8 5.2L20 9l-5.2 1.8L13 16l-1.8-5.2L6 9l5.2-1.8L13 2Z"></path><path d="M5 15l.8 2.2L8 18l-2.2.8L5 21l-.8-2.2L2 18l2.2-.8L5 15Z"></path>',
    trash: '<path d="M3 6h18"></path><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"></path>',
    warning: '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"></path><path d="M12 9v4"></path><path d="M12 17h.01"></path>'
  }};
  return `<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" aria-hidden="true">${{icons[name] || ""}}</svg>`;
}}
function buttonLabel(iconName, label) {{
  return `${{icon(iconName)}}<span>${{esc(label)}}</span>`;
}}
function statusIcon(status) {{
  if (status === "trashed") return "trash";
  if (status === "deleted") return "warning";
  if (status === "missing") return "warning";
  if (status === "kept") return "bookmark";
  return "check";
}}
function statusBadgeHtml(state) {{
  if (!state) return "";
  return `<span class="status-badge ${{esc(state.status)}}">${{icon(statusIcon(state.status))}}<span>${{esc(statusText(state.status))}}</span></span>`;
}}
function humanSize(size) {{
  let value = Number(size || 0);
  for (const unit of ["B","KB","MB","GB","TB","PB"]) {{
    if (value < 1000 || unit === "PB") return unit === "B" ? `${{Math.round(value)}} B` : `${{value.toFixed(1)}} ${{unit}}`;
    value /= 1000;
  }}
}}
function esc(text) {{
  return String(text ?? "").replace(/[&<>"']/g, c => ({{"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}}[c]));
}}
function primaryDisk() {{
  return (report.disk_usage || [])[0] || null;
}}
function currentDisk() {{
  return (currentDiskUsage || [])[0] || null;
}}
function diskChangeHtml(scanDisk, liveDisk) {{
  if (!scanDisk) return "";
  if (!deleteEnabled) {{
    const scanFreePercent = scanDisk.total ? Math.max(0, Math.min(100, (scanDisk.free / scanDisk.total) * 100)) : 0;
    return `<div class="comparison">
      <div class="comparison-head">
        <div class="comparison-title"><strong>清理前后对比</strong><span class="compare-caption">启动本地服务后，这里会显示当前可用空间的实时变化。</span></div>
        <span class="delta-pill">等待实时数据</span>
      </div>
      <div class="comparison-stage">
        <div class="compare-card scan">
          <div class="mini-ring" style="--free-percent:${{scanFreePercent}}%; --ring-color:#4d7cff; --ring-glow:rgba(77,124,255,.18)">
            <div class="mini-ring-inner"><div><div class="mini-ring-number">${{scanFreePercent.toFixed(0)}}%</div><div class="mini-ring-label">可用</div></div></div>
          </div>
          <div class="compare-card-title">扫描时</div>
          <div class="compare-free">${{humanSize(scanDisk.free)}}</div>
          <div class="compare-used">已用 ${{humanSize(scanDisk.used)}}</div>
        </div>
        <div class="compare-arrow">?</div>
        <div class="compare-card current">
          <div class="mini-ring" style="--free-percent:${{scanFreePercent}}%; --ring-color:#31f6b1; --ring-glow:rgba(49,246,177,.18)">
            <div class="mini-ring-inner"><div><div class="mini-ring-number">--</div><div class="mini-ring-label">实时</div></div></div>
          </div>
          <div class="compare-card-title">当前</div>
          <div class="compare-free">启动服务查看</div>
          <div class="compare-used">静态报告只显示扫描时数据</div>
        </div>
      </div>
    </div>`;
  }}
  if (!liveDisk) {{
    return `<div class="notice" style="margin:14px 0 0">正在读取当前可用空间...</div>`;
  }}
  const delta = Number(liveDisk.free || 0) - Number(scanDisk.free || 0);
  const label = delta > 0 ? `已增加 ${{humanSize(delta)}}` : delta < 0 ? `已减少 ${{humanSize(Math.abs(delta))}}` : "暂无变化";
  const scanFreePercent = scanDisk.total ? Math.max(0, Math.min(100, (scanDisk.free / scanDisk.total) * 100)) : 0;
  const liveFreePercent = liveDisk.total ? Math.max(0, Math.min(100, (liveDisk.free / liveDisk.total) * 100)) : 0;
  const arrowClass = delta < 0 ? " down" : "";
  const arrow = delta > 0 ? "↑" : delta < 0 ? "↓" : "→";
  return `<div class="comparison">
    <div class="comparison-head">
      <div class="comparison-title"><strong>清理前后对比</strong><span class="compare-caption">按真实磁盘可用空间展示，不用估算体积代替。</span></div>
      <span class="delta-pill${{arrowClass}}">${{label}}</span>
    </div>
    <div class="comparison-stage">
      <div class="compare-card scan">
        <div class="mini-ring" style="--free-percent:${{scanFreePercent}}%; --ring-color:#4d7cff; --ring-glow:rgba(77,124,255,.18)">
          <div class="mini-ring-inner"><div><div class="mini-ring-number">${{scanFreePercent.toFixed(0)}}%</div><div class="mini-ring-label">可用</div></div></div>
        </div>
        <div class="compare-card-title">扫描时</div>
        <div class="compare-free">${{humanSize(scanDisk.free)}}</div>
        <div class="compare-used">已用 ${{humanSize(scanDisk.used)}}</div>
      </div>
      <div class="compare-arrow${{arrowClass}}">${{arrow}}</div>
      <div class="compare-card current">
        <div class="mini-ring" style="--free-percent:${{liveFreePercent}}%; --ring-color:#31f6b1; --ring-glow:rgba(49,246,177,.20)">
          <div class="mini-ring-inner"><div><div class="mini-ring-number">${{liveFreePercent.toFixed(0)}}%</div><div class="mini-ring-label">可用</div></div></div>
        </div>
        <div class="compare-card-title">当前</div>
        <div class="compare-free">${{humanSize(liveDisk.free)}}</div>
        <div class="compare-used">已用 ${{humanSize(liveDisk.used)}}</div>
      </div>
    </div>
  </div>`;
}}
async function refreshDiskUsage(rerender = false) {{
  if (!deleteEnabled) return;
  try {{
    const response = await fetch("/api/disk-usage");
    if (!response.ok) throw new Error("disk usage failed");
    const result = await response.json();
    currentDiskUsage = result.disk_usage || null;
    if (rerender) render();
  }} catch {{
    currentDiskUsage = null;
    if (rerender) render();
  }}
}}
function diskColor(percent) {{
  if (percent >= 95) return "var(--red)";
  if (percent >= 85) return "var(--yellow)";
  return "var(--green)";
}}
function tierDiskBreakdown(items, disk) {{
  const parents = buildPathGroups(items).map(group => group.parent);
  const byTier = Object.fromEntries(tierOrder.map(tier => [tier, 0]));
  for (const item of parents) byTier[item.tier] = (byTier[item.tier] || 0) + item.size;
  const tierTotal = Object.values(byTier).reduce((sum, value) => sum + value, 0);
  const otherUsed = disk ? Math.max(0, disk.used - tierTotal) : 0;
  const free = disk ? Math.max(0, disk.free) : 0;
  return {{
    tiers: byTier,
    otherUsed,
    free,
    tierTotal,
  }};
}}
function percentOfDisk(size, disk) {{
  return disk && disk.total ? (size / disk.total) * 100 : 0;
}}
function diskSegmentHtml(label, size, color, disk) {{
  const percent = percentOfDisk(size, disk);
  const width = Math.max(0, Math.min(100, percent));
  const minWidth = width > 0 && width < 1 ? "3px" : "0";
  return `<div class="disk-segment" title="${{esc(label)}} · ${{humanSize(size)}} · ${{percent.toFixed(1)}}%" style="--segment-width:${{width}}%; --segment-min:${{minWidth}}; --segment-color:${{color}}"></div>`;
}}
function diskLegendRow(label, size, color, disk) {{
  const percent = percentOfDisk(size, disk);
  return `<div class="legend-row"><span class="legend-dot" style="--dot-color:${{color}}"></span><span>${{esc(label)}} · ${{humanSize(size)}}</span><strong>${{percent.toFixed(1)}}%</strong></div>`;
}}
function topProjects(items) {{
  return buildPathGroups(items).map(group => group.parent).sort((a, b) => b.size - a.size).slice(0, 6);
}}
function executionAdvice(items) {{
  const disk = primaryDisk();
  const autoTop = items.filter(item => item.tier === "{TIER_AUTO}" && !itemState(item)).sort((a, b) => b.size - a.size)[0];
  const reviewTop = items.filter(item => item.tier === "{TIER_REVIEW}" && !itemState(item)).sort((a, b) => b.size - a.size)[0];
  const advice = [];
  if (disk && disk.percent_used >= 95) advice.push(`磁盘已用 ${{disk.percent_used}}%，先释放 15GB 以上再做大文件操作。`);
  else if (disk && disk.percent_used >= 85) advice.push(`磁盘已用 ${{disk.percent_used}}%，建议先清理缓存和下载目录。`);
  else advice.push("磁盘压力不高，优先处理明确无用的缓存和安装包。");
  if (autoTop) advice.push(`先处理绿色项：${{humanSize(autoTop.size)}} · ${{autoTop.path}}。`);
  if (reviewTop) advice.push(`再人工确认黄色项：${{humanSize(reviewTop.size)}} · ${{reviewTop.path}}。`);
  advice.push("移到废纸篓后需要清空废纸篓，空间才会真正释放。");
  return advice.slice(0, 4);
}}
function renderDashboard(items) {{
  const disk = primaryDisk();
  const liveDisk = currentDisk();
  const percent = disk ? Math.min(100, Math.max(0, Number(disk.percent_used || 0))) : 0;
  const freePercent = disk && disk.total ? Math.max(0, Math.min(100, (disk.free / disk.total) * 100)) : 0;
  const top = topProjects(items);
  const breakdown = disk ? tierDiskBreakdown(items, disk) : null;
  const tierSegments = disk && breakdown ? tierOrder.map(tier => diskSegmentHtml(tier, breakdown.tiers[tier] || 0, report.tiers[tier]?.color || "#64748b", disk)).join("") : "";
  const otherColor = "#94a3b8";
  const freeColor = "#e2e8f0";
  const usageLegend = disk && breakdown ? [
    ...tierOrder.map(tier => diskLegendRow(tier, breakdown.tiers[tier] || 0, report.tiers[tier]?.color || "#64748b", disk)),
    diskLegendRow("其他已用空间", breakdown.otherUsed, otherColor, disk),
    diskLegendRow("剩余空间", breakdown.free, freeColor, disk),
  ].join("") : "";
  const scanStats = `
    <div class="stats" style="margin:14px 0 0">
      <div class="stat"><div class="label">报告项目</div><div class="value">${{items.length}}</div></div>
      <div class="stat"><div class="label">合计体积</div><div class="value">${{humanSize(items.reduce((s, i) => s + i.size, 0))}}</div></div>
      <div class="stat"><div class="label">扫描错误</div><div class="value">${{report.summary.errors}}</div></div>
      <div class="stat"><div class="label">生成时间</div><div class="value" style="font-size:16px">${{esc(report.generated_at_local)}}</div></div>
    </div>`;
  const diskHtml = disk ? `
    <div class="disk-visual">
      <div class="disk-orb" style="--free-percent:${{freePercent}}%">
        <div class="disk-orb-inner">
          <div>
            <div class="orb-label">可用空间</div>
            <div class="orb-number">${{freePercent.toFixed(0)}}%</div>
            <div class="orb-sub">${{humanSize(disk.free)}} 可用</div>
          </div>
        </div>
      </div>
      <div class="disk-hero-copy">
        <div class="hero-kicker">磁盘空间状态</div>
        <div class="hero-line">${{humanSize(disk.free)}}<small>当前报告显示的扫描时剩余空间。下方色带展示三档建议在总容量中的占比。</small></div>
        <div class="disk-meter">
          ${{tierSegments}}
          ${{diskSegmentHtml("其他已用空间", breakdown.otherUsed, otherColor, disk)}}
          ${{diskSegmentHtml("剩余空间", breakdown.free, freeColor, disk)}}
        </div>
        <div class="disk-numbers">
          <div><span class="label">总容量</span><strong>${{humanSize(disk.total)}}</strong></div>
          <div><span class="label">已使用</span><strong>${{humanSize(disk.used)}}</strong></div>
          <div><span class="label">剩余</span><strong>${{humanSize(disk.free)}}</strong></div>
        </div>
      </div>
    </div>
    <div class="disk-legend">${{usageLegend}}</div>
    ${{diskChangeHtml(disk, liveDisk)}}
    ${{scanStats}}
    <div class="label" style="margin-top:10px">容量采用 macOS 一致的十进制 GB。色块按总容量占比展示，分级数据按总目录去重统计。</div>` : `<div class="empty">当前报告没有磁盘容量数据，请重新扫描。</div>${{scanStats}}`;
  document.getElementById("dashboard").innerHTML = `
    <details class="panel-card dashboard-card" open>
      <summary><span class="summary-title">${{icon("disk")}}<span>磁盘总览</span></span><span class="tier-count">${{liveDisk ? `${{humanSize(liveDisk.free)}} 当前可用` : disk ? `${{humanSize(disk.free)}} 扫描时可用` : "需要重新扫描"}}</span></summary>
      <div class="panel-body">${{diskHtml}}</div>
    </details>
    <details class="panel-card dashboard-card" open>
      <summary><span class="summary-title">${{icon("list")}}<span>占用空间 TOP6</span></span><span class="tier-count">${{top.length}} 项</span></summary>
      <div class="panel-body"><div class="rank-list">${{top.map((item, index) => `<div class="rank-item"><span class="rank-index">${{index + 1}}</span><span class="rank-path">${{esc(item.path)}}</span><strong>${{humanSize(item.size)}}</strong><button onclick='revealItem("${{esc(item.id)}}").catch(e=>alert(e.message))' ${{deleteEnabled ? "" : "disabled"}}>${{buttonLabel("locate", "显示")}}</button></div>`).join("") || `<div class="empty">没有匹配项目</div>`}}</div></div>
    </details>
    <details class="panel-card dashboard-card" open>
      <summary><span class="summary-title">${{icon("spark")}}<span>执行建议</span></span><span class="tier-count">按优先级处理</span></summary>
      <div class="panel-body"><ul class="advice-list">${{executionAdvice(items).map(text => `<li>${{esc(text)}}</li>`).join("")}}</ul></div>
    </details>`;
}}
function renderTierOverview(items) {{
  const selectedTier = document.getElementById("tierFilter").value;
  const cards = tierOrder.map(tier => {{
    const bucket = items.filter(item => item.tier === tier);
    const parentItems = buildPathGroups(bucket).map(group => group.parent);
    const meta = report.tiers[tier] || {{}};
    const total = parentItems.reduce((sum, item) => sum + item.size, 0);
    const processed = bucket.filter(item => itemState(item)).length;
    const active = selectedTier === tier ? " active" : "";
    const tierIcon = tier === "{TIER_AUTO}" ? "check" : tier === "{TIER_REVIEW}" ? "spark" : "shield";
    return `<button class="tier-card${{active}}" style="--tier-color:${{meta.color}}; --tier-soft:${{meta.soft}}" onclick='selectTier(${{JSON.stringify(tier)}})'>
      <h2><span class="summary-title">${{icon(tierIcon)}}<span>${{esc(tier)}}</span></span><span>${{parentItems.length}} 个总目录</span></h2>
      <div class="metrics">
        <div class="metric"><span class="label">总目录体积</span><strong>${{humanSize(total)}}</strong></div>
        <div class="metric"><span class="label">已处理</span><strong>${{processed}}</strong></div>
      </div>
      <div class="top-path">${{parentItems.length ? "按总目录去重统计" : "没有匹配项目"}}</div>
    </button>`;
  }}).join("");
  document.getElementById("tierOverview").innerHTML = `
    <details class="panel-card" open>
      <summary><span class="summary-title">${{icon("shield")}}<span>三档汇总</span></span><span class="tier-count">${{items.length}} 项</span></summary>
      <div class="panel-body"><div class="tier-overview">${{cards}}</div><div class="compare-caption">总目录体积按父级目录去重统计，展开后的子项只用于定位，不会重复累加。</div></div>
    </details>`;
}}
function selectTier(tier) {{
  const select = document.getElementById("tierFilter");
  select.value = select.value === tier ? "" : tier;
  render();
}}
async function copyText(text) {{
  await navigator.clipboard.writeText(text);
}}
function loadActions() {{
  try {{
    return JSON.parse(localStorage.getItem(actionKey) || "{{}}");
  }} catch {{
    return {{}};
  }}
}}
function saveActions() {{
  localStorage.setItem(actionKey, JSON.stringify(itemActions));
}}
function findItem(id) {{
  return report.items.find(item => item.id === id);
}}
function archiveItems() {{
  return report.download_archives || [];
}}
function findArchive(id) {{
  return archiveItems().find(item => item.id === id);
}}
function contentDuplicateGroups() {{
  return report.content_duplicate_files || [];
}}
function duplicateCandidates() {{
  return contentDuplicateGroups().flatMap(group => group.candidates || []);
}}
function findDuplicateCandidate(id) {{
  return duplicateCandidates().find(item => item.id === id);
}}
function revealItemById(id) {{
  return findItem(id) || findArchive(id) || findDuplicateCandidate(id) || null;
}}
function itemState(item) {{
  if (itemActions[item.id]) return {{...itemActions[item.id], sourceId: item.id, inherited: false}};
  for (const [sourceId, action] of Object.entries(itemActions)) {{
    if (action.path && item.path !== action.path && item.path.startsWith(action.path.endsWith("/") ? action.path : `${{action.path}}/`)) {{
      return {{...action, sourceId, inherited: true}};
    }}
  }}
  return null;
}}
function statusText(status) {{
  if (status === "trashed") return "已移到废纸篓";
  if (status === "deleted") return "已直接删除";
  if (status === "missing") return "路径已不存在";
  if (status === "kept") return "已保留";
  return "已处理";
}}
function showToast(message) {{
  const old = document.querySelector(".toast");
  if (old) old.remove();
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 4200);
}}
function recordItemAction(item, status, message, path) {{
  if (!item) return;
  itemActions[item.id] = {{
    status,
    message: message || statusText(status),
    path: path || item.path,
    at: new Date().toLocaleString()
  }};
  saveActions();
  render();
}}
function toggleKeep(id) {{
  const item = revealItemById(id);
  if (!item) return;
  const state = itemState(item);
  if (state && state.status === "kept") {{
    delete itemActions[state.sourceId || id];
    saveActions();
    render();
    showToast("已取消保留");
    return;
  }}
  if (state) return;
  itemActions[id] = {{
    status: "kept",
    message: "已保留",
    path: item.path,
    at: new Date().toLocaleString()
  }};
  saveActions();
  render();
  showToast("已标记为保留");
}}
function keepButtonHtml(item) {{
  const state = itemState(item);
  if (state && state.status !== "kept") return `<button disabled>${{buttonLabel(statusIcon(state.status), statusText(state.status))}}</button>`;
  const label = state && state.status === "kept" ? "取消保留" : "保留";
  const active = state && state.status === "kept" ? " active" : "";
  return `<button class="btn-keep${{active}}" onclick='toggleKeep("${{esc(item.id)}}")'>${{buttonLabel("bookmark", label)}}</button>`;
}}
async function revealItem(id) {{
  const item = revealItemById(id);
  if (!item) return;
  if (!deleteEnabled) {{
    showToast("需要通过本地服务打开报告后，才能在 Finder/资源管理器中显示。");
    return;
  }}
  const response = await fetch("/api/reveal", {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify({{id}})
  }});
  const result = await response.json();
  if (!response.ok) {{
    if (response.status === 404) {{
      recordItemAction(item, "missing", result.error || "Path no longer exists", result.path || item.path);
      showToast("这条路径已经不存在，已在报告里标记。");
      return;
    }}
    throw new Error(result.error || "reveal failed");
  }}
  showToast(result.message || "已在文件管理器中显示");
}}
async function deleteItem(id, mode) {{
  const item = findItem(id);
  let body;
  if (mode === "delete") {{
    const phrase = `DELETE:${{id}}`;
    const typed = prompt(`直接删除不可恢复。请输入 ${{phrase}} 确认：`);
    if (typed !== phrase) return;
    body = {{id, mode, confirm: typed}};
  }} else {{
    if (!confirm("将移到废纸篓/回收站，可以从废纸篓恢复。确定继续吗？")) return;
    body = {{id, mode, confirmed: true}};
  }}
  const response = await fetch("/api/delete", {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify(body)
  }});
  const result = await response.json();
  if (!response.ok) {{
    if (response.status === 404) {{
      recordItemAction(item, "missing", result.error || "Path no longer exists", result.path || item?.path);
      showToast("这条路径已经不存在，已在报告里标记。");
      return;
    }}
    throw new Error(result.error || "delete failed");
  }}
  recordItemAction(item, mode === "delete" ? "deleted" : "trashed", result.message, result.path || item?.path);
  refreshDiskUsage(true);
  showToast(result.message || "已处理");
}}
async function trashArchive(id) {{
  const item = findArchive(id);
  if (!item || itemState(item)) return;
  if (!confirm(`将这个下载压缩包移到废纸篓：\n${{item.path}}`)) return;
  const response = await fetch("/api/delete", {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify({{id, mode: "trash", confirmed: true}})
  }});
  const result = await response.json();
  if (!response.ok) {{
    if (response.status === 404) {{
      recordItemAction(item, "missing", result.error || "Path no longer exists", result.path || item.path);
      showToast("这个压缩包已经不存在，已标记。");
      return;
    }}
    throw new Error(result.error || "delete failed");
  }}
  recordItemAction(item, "trashed", result.message, result.path || item.path);
  refreshDiskUsage(true);
  showToast(result.message || "已移到废纸篓");
}}
async function trashAllArchives() {{
  const pending = archiveItems().filter(item => !itemState(item));
  const total = pending.reduce((sum, item) => sum + item.size, 0);
  if (!pending.length) return;
  if (!confirm(`将 ${{pending.length}} 个下载压缩包移到废纸篓，共 ${{humanSize(total)}}。确定继续吗？`)) return;
  const response = await fetch("/api/trash-download-archives", {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify({{ids: pending.map(item => item.id), confirmed: true}})
  }});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "bulk trash failed");
  for (const moved of result.moved || []) {{
    const item = findArchive(moved.id);
    recordItemAction(item, "trashed", moved.message, moved.path);
  }}
  for (const missing of result.missing || []) {{
    const item = findArchive(missing.id);
    recordItemAction(item, "missing", missing.message, missing.path);
  }}
  render();
  refreshDiskUsage(true);
  showToast(`已处理 ${{(result.moved || []).length}} 个，跳过 ${{(result.missing || []).length + (result.errors || []).length}} 个。`);
}}
async function trashDuplicateCandidate(id) {{
  const item = findDuplicateCandidate(id);
  if (!item || itemState(item)) return;
  if (!confirm(`将这个副本移到废纸篓，保留文件不会处理：\n${{item.path}}`)) return;
  const response = await fetch("/api/delete", {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify({{id, mode: "trash", confirmed: true}})
  }});
  const result = await response.json();
  if (!response.ok) {{
    if (response.status === 404) {{
      recordItemAction(item, "missing", result.error || "Path no longer exists", result.path || item.path);
      showToast("这个文件已经不存在，已标记。");
      return;
    }}
    throw new Error(result.error || "delete failed");
  }}
  recordItemAction(item, "trashed", result.message, result.path || item.path);
  refreshDiskUsage(true);
  showToast(result.message || "已移到废纸篓");
}}
async function trashDuplicateCandidates(ids) {{
  const pending = ids.map(findDuplicateCandidate).filter(item => item && !itemState(item));
  const total = pending.reduce((sum, item) => sum + item.size, 0);
  if (!pending.length) return;
  if (!confirm(`将 ${{pending.length}} 个副本移到废纸篓，共 ${{humanSize(total)}}。每组都会保留 1 个文件。确定继续吗？`)) return;
  const response = await fetch("/api/trash-content-duplicate-candidates", {{
    method: "POST",
    headers: {{"Content-Type":"application/json"}},
    body: JSON.stringify({{ids: pending.map(item => item.id), confirmed: true}})
  }});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || "bulk trash failed");
  for (const moved of result.moved || []) {{
    const item = findDuplicateCandidate(moved.id);
    recordItemAction(item, "trashed", moved.message, moved.path);
  }}
  for (const missing of result.missing || []) {{
    const item = findDuplicateCandidate(missing.id);
    recordItemAction(item, "missing", missing.message, missing.path);
  }}
  render();
  refreshDiskUsage(true);
  showToast(`已处理 ${{(result.moved || []).length}} 个，跳过 ${{(result.missing || []).length + (result.errors || []).length}} 个。`);
}}
function archiveItemHtml(item) {{
  const state = itemState(item);
  const status = statusBadgeHtml(state);
  return `<div class="archive-item${{state ? ` processed ${{esc(state.status)}}` : ""}}">
    <div>
      <div class="archive-path">${{esc(item.path)}}</div>
      <div class="archive-meta">${{status}}<span>${{humanSize(item.size)}}</span><span>${{esc(item.extension || "")}}</span></div>
    </div>
    <div class="actions">
      ${{keepButtonHtml(item)}}
      <button onclick='revealItem("${{esc(item.id)}}").catch(e=>alert(e.message))' ${{deleteEnabled ? "" : "disabled"}} title="在 Finder/资源管理器中显示">${{buttonLabel("locate", "显示")}}</button>
      <button onclick='trashArchive("${{esc(item.id)}}").catch(e=>alert(e.message))' ${{deleteEnabled && !state ? "" : "disabled"}}>${{buttonLabel("trash", "移废纸篓")}}</button>
    </div>
  </div>`;
}}
function renderDownloadArchives() {{
  const archives = archiveItems();
  const pending = archives.filter(item => !itemState(item));
  const total = archives.reduce((sum, item) => sum + item.size, 0);
  const pendingTotal = pending.reduce((sum, item) => sum + item.size, 0);
  document.getElementById("downloadArchives").innerHTML = `
    <details class="archive-panel" open>
      <summary><span class="summary-title">${{icon("archive")}}<span>下载压缩包</span></span><span class="tier-count">${{archives.length}} 个 / ${{humanSize(total)}}</span></summary>
      <div class="panel-body">
        <div class="archive-header">
          <div class="archive-summary"><span>待处理 ${{pending.length}} 个</span><span>可释放约 ${{humanSize(pendingTotal)}}</span></div>
          <button class="primary" onclick='trashAllArchives().catch(e=>alert(e.message))' ${{deleteEnabled && pending.length ? "" : "disabled"}}>${{buttonLabel("trash", "全部移废纸篓")}}</button>
        </div>
        ${{archives.length ? `<details open><summary><span class="summary-title">${{icon("folder")}}<span>查看下载目录里的压缩包和安装包</span></span></summary><div class="archive-list">${{archives.slice(0, 30).map(archiveItemHtml).join("")}}</div></details>` : `<div class="empty">下载目录没有发现压缩包或安装包。</div>`}}
      </div>
    </details>`;
}}
function duplicateFileHtml(item, canDelete = true) {{
  const state = itemState(item);
  const status = statusBadgeHtml(state);
  const deleteButton = canDelete
    ? `<button onclick='trashDuplicateCandidate("${{esc(item.id)}}").catch(e=>alert(e.message))' ${{deleteEnabled && !state ? "" : "disabled"}}>${{buttonLabel("trash", "移废纸篓")}}</button>`
    : `<button disabled>${{buttonLabel("bookmark", "保留文件")}}</button>`;
  return `<div class="archive-item${{state ? ` processed ${{esc(state.status)}}` : ""}}">
    <div>
      <div class="archive-path">${{esc(item.path)}}</div>
      <div class="archive-meta">${{status}}<span>${{humanSize(item.size)}}</span><span>${{esc(item.category || "")}}</span><span>${{esc(item.extension || "")}}</span></div>
    </div>
    <div class="actions">
      ${{canDelete ? keepButtonHtml(item) : ""}}
      <button onclick='revealItem("${{esc(item.id)}}").catch(e=>alert(e.message))' ${{deleteEnabled ? "" : "disabled"}} title="在 Finder/资源管理器中显示">${{buttonLabel("locate", "显示")}}</button>
      ${{deleteButton}}
    </div>
  </div>`;
}}
function duplicateGroupHtml(group) {{
  const candidates = group.candidates || [];
  const pending = candidates.filter(item => !itemState(item));
  return `<details class="duplicate-group" open>
    <summary>
      <span class="summary-title">${{icon("duplicate")}}<span class="group-title">${{esc(group.category)}} · 内容完全相同 · ${{group.count}} 个文件</span></span>
      <span class="group-subtitle">可移除 ${{pending.length}} 个 / ${{humanSize(pending.reduce((sum, item) => sum + item.size, 0))}}</span>
    </summary>
    <div class="duplicate-primary">
      <div class="label">保留文件</div>
      ${{duplicateFileHtml(group.primary, false)}}
    </div>
    <div class="duplicate-candidates">
      <div class="archive-header" style="margin:0">
        <div class="label">可移除副本</div>
        <button onclick='trashDuplicateCandidates(${{JSON.stringify(candidates.map(item => item.id))}}).catch(e=>alert(e.message))' ${{deleteEnabled && pending.length ? "" : "disabled"}}>${{buttonLabel("trash", "移除本组副本")}}</button>
      </div>
      ${{candidates.map(duplicateFileHtml).join("")}}
    </div>
  </details>`;
}}
function renderContentDuplicates() {{
  if (report.content_duplicate_scan_skipped) {{
    document.getElementById("similarNames").innerHTML = `
      <details class="archive-panel" open>
        <summary><span class="summary-title">${{icon("duplicate")}}<span>下载内容重复文件</span></span><span class="tier-count">快速扫描已跳过</span></summary>
        <div class="panel-body">
          <div class="notice" style="margin:0">这次为了更快定位空间大户，暂时跳过了下载目录的重复内容比对。需要时可以重新跑完整扫描。</div>
        </div>
      </details>`;
    return;
  }}
  const groups = contentDuplicateGroups();
  const candidates = duplicateCandidates();
  const pending = candidates.filter(item => !itemState(item));
  const pendingTotal = pending.reduce((sum, item) => sum + item.size, 0);
  document.getElementById("similarNames").innerHTML = `
    <details class="archive-panel" open>
      <summary><span class="summary-title">${{icon("duplicate")}}<span>下载内容重复文件</span></span><span class="tier-count">${{groups.length}} 组 / 可移除 ${{pending.length}} 个</span></summary>
      <div class="panel-body">
        <div class="archive-header">
          <div class="archive-summary"><span>每组保留 1 个</span><span>可移除副本 ${{pending.length}} 个 / ${{humanSize(pendingTotal)}}</span></div>
          <button class="primary" onclick='trashDuplicateCandidates(${{JSON.stringify(pending.map(item => item.id))}}).catch(e=>alert(e.message))' ${{deleteEnabled && pending.length ? "" : "disabled"}}>${{buttonLabel("trash", "移除所有副本")}}</button>
        </div>
        <div class="notice" style="margin:0 0 12px">仅扫描下载目录里的文档、图片、视频。这里展示的是内容完全相同的重复文件；每组固定保留 1 个，只把可移除副本放入废纸篓。</div>
        ${{groups.length ? groups.slice(0, 30).map(duplicateGroupHtml).join("") : `<div class="empty">下载目录没有发现文档、图片、视频的完全相同内容副本。</div>`}}
      </div>
    </details>`;
}}
function itemHtml(item) {{
  const color = report.tiers[item.tier]?.color || "#64748b";
  const disabled = deleteEnabled ? "" : "disabled";
  const disabledTitle = deleteEnabled ? "" : " title='需要通过本地服务打开报告后才可处理'";
  const state = itemState(item);
  const stateClass = state ? ` processed ${{esc(state.status)}}` : "";
  const status = state ? `${{statusBadgeHtml(state)}}<span>${{esc(state.at || "")}}</span>` : "";
  return `<article class="item${{stateClass}}" data-id="${{esc(item.id)}}">
    <div>
      <h3>${{esc(item.path)}}</h3>
      <div class="meta">
        <span class="badge" style="background:${{color}}">${{icon(item.tier === "{TIER_AUTO}" ? "check" : item.tier === "{TIER_REVIEW}" ? "spark" : "shield")}}<span>${{esc(item.tier)}}</span></span>
        ${{status}}
        <span>${{humanSize(item.size)}}</span>
        <span>${{esc(item.kind)}}</span>
        <span>${{esc(item.category)}}</span>
        <span>${{item.files}} files / ${{item.dirs}} dirs</span>
      </div>
      <div class="reason">${{esc(item.reason)}}</div>
    </div>
    <div class="actions">
      ${{keepButtonHtml(item)}}
      <button onclick='revealItem("${{esc(item.id)}}").catch(e=>alert(e.message))' ${{deleteEnabled ? "" : "disabled"}} title="在 Finder/资源管理器中显示">${{buttonLabel("locate", "显示")}}</button>
      <button onclick='deleteItem("${{esc(item.id)}}","trash").catch(e=>alert(e.message))' ${{deleteDisabled(item, disabled)}}${{deleteTitle(item, disabledTitle)}}>${{buttonLabel("trash", "移废纸篓")}}</button>
      <button class="danger" onclick='deleteItem("${{esc(item.id)}}","delete").catch(e=>alert(e.message))' ${{deleteDisabled(item, disabled)}}${{deleteTitle(item, disabledTitle)}}>${{buttonLabel("warning", "直接删除")}}</button>
    </div>
  </article>`;
}}
function pathKey(path) {{
  return path.replaceAll("\\\\", "/").replace(/\/+$/, "");
}}
function isChildPath(parent, child) {{
  const parentKey = pathKey(parent);
  const childKey = pathKey(child);
  return childKey !== parentKey && childKey.startsWith(`${{parentKey}}/`);
}}
function buildPathGroups(items) {{
  const sorted = items.slice().sort((a, b) => {{
    const aDepth = pathKey(a.path).split("/").length;
    const bDepth = pathKey(b.path).split("/").length;
    if (aDepth !== bDepth) return aDepth - bDepth;
    return b.size - a.size;
  }});
  const groups = [];
  for (const item of sorted) {{
    let parentGroup = null;
    for (const group of groups) {{
      if (isChildPath(group.parent.path, item.path)) {{
        if (!parentGroup || pathKey(group.parent.path).length > pathKey(parentGroup.parent.path).length) parentGroup = group;
      }}
    }}
    if (parentGroup) parentGroup.children.push(item);
    else groups.push({{parent: item, children: []}});
  }}
  return groups.sort((a, b) => b.parent.size - a.parent.size);
}}
function pathGroupHtml(group) {{
  const parent = group.parent;
  const children = group.children.sort((a, b) => b.size - a.size);
  if (!children.length) return `<div class="single-item-wrap">${{itemHtml(parent)}}</div>`;
  const processed = [parent, ...children].filter(item => itemState(item)).length;
  const disabled = deleteEnabled ? "" : "disabled";
  const disabledTitle = deleteEnabled ? "" : " title='需要通过本地服务打开报告后才可处理'";
  return `<details class="path-group" open>
    <summary>
      <span class="summary-title">${{icon("folder")}}<span class="group-title">总目录：${{esc(parent.path)}}</span></span>
      <span class="summary-meta">
        <span class="group-subtitle">总目录 ${{humanSize(parent.size)}} · ${{children.length}} 个子项 · 已处理 ${{processed}}</span>
        <button onclick='event.preventDefault(); event.stopPropagation(); deleteItem("${{esc(parent.id)}}","trash").catch(e=>alert(e.message))' ${{deleteDisabled(parent, disabled)}}${{deleteTitle(parent, disabledTitle)}}>${{buttonLabel("trash", "移废纸篓")}}</button>
      </span>
    </summary>
    ${{itemHtml(parent)}}
    <div class="group-children">
      ${{children.map(itemHtml).join("")}}
    </div>
  </details>`;
}}
function pathGroupsHtml(items) {{
  return buildPathGroups(items).map(pathGroupHtml).join("");
}}
function isProtectedContainer(item) {{
  const path = item.path.replaceAll("\\\\", "/");
  const parts = path.split("/");
  const home = parts.length >= 3 ? parts.slice(0, 3).join("/") : path;
  return [
    "/",
    home,
    `${{home}}/Desktop`,
    `${{home}}/Documents`,
    `${{home}}/Downloads`,
    `${{home}}/Library`,
    `${{home}}/Library/Caches`,
    `${{home}}/Library/Application Support`,
    `${{home}}/.Trash`
  ].includes(path);
}}
function deleteDisabled(item, serviceDisabled) {{
  return serviceDisabled || isProtectedContainer(item) || itemState(item) ? "disabled" : "";
}}
function deleteTitle(item, serviceTitle) {{
  if (serviceTitle) return serviceTitle;
  const state = itemState(item);
  if (state?.status === "kept") return " title='已标记为保留，取消保留后可处理'";
  if (state) return " title='这条记录已经处理过或路径已不存在'";
  if (isProtectedContainer(item)) return " title='这是总目录，不能整目录删除；请展开后删除具体子目录'";
  return "";
}}
function filteredItems() {{
  const text = document.getElementById("filter").value.toLowerCase();
  const tier = document.getElementById("tierFilter").value;
  const sorter = document.getElementById("sorter").value;
  const items = report.items.filter(item => {{
    const haystack = `${{item.path}} ${{item.category}} ${{item.reason}}`.toLowerCase();
    return (!tier || item.tier === tier) && (!text || haystack.includes(text));
  }});
  items.sort((a, b) => {{
    if (sorter === "size-asc") return a.size - b.size;
    if (sorter === "name") return a.name.localeCompare(b.name);
    if (sorter === "tier") return tierOrder.indexOf(a.tier) - tierOrder.indexOf(b.tier);
    return b.size - a.size;
  }});
  return items;
}}
function render() {{
  const items = filteredItems();
  renderDashboard(items);
  renderDownloadArchives();
  renderContentDuplicates();
  renderTierOverview(items);
  document.getElementById("serviceNotice").textContent = deleteEnabled
    ? "当前是本地服务模式：删除按钮已启用。默认移到废纸篓/回收站；直接删除需要额外确认。"
    : "当前是静态报告模式：删除按钮和实时空间对比已禁用。如需使用这些功能，请通过本地服务打开报告。";
  const groups = tierOrder.map(tier => {{
    const bucket = items.filter(item => item.tier === tier);
    const meta = report.tiers[tier] || {{}};
    const tierIcon = tier === "{TIER_AUTO}" ? "check" : tier === "{TIER_REVIEW}" ? "spark" : "shield";
    const parentItems = buildPathGroups(bucket).map(group => group.parent);
    const parentTotal = parentItems.reduce((sum, item) => sum + item.size, 0);
    return `<details class="tier" open>
      <summary style="border-left:6px solid ${{meta.color}}; background:${{meta.soft}}">
        <span class="summary-title">${{icon(tierIcon)}}<span>${{esc(tier)}}</span></span><span class="tier-count">${{parentItems.length}} 个总目录 / ${{bucket.length}} 项 / ${{humanSize(parentTotal)}}</span>
      </summary>
      ${{bucket.length ? pathGroupsHtml(bucket) : `<div class="empty">没有匹配项目</div>`}}
    </details>`;
  }}).join("");
  document.getElementById("groups").innerHTML = groups;
}}
document.getElementById("filter").addEventListener("input", render);
document.getElementById("tierFilter").addEventListener("change", render);
document.getElementById("sorter").addEventListener("change", render);
render();
refreshDiskUsage(true);
</script>
</body>
</html>"""


def write_scan_outputs(payload: dict[str, Any], output: str, json_output: str | None) -> tuple[Path, Path]:
    html_path = Path(output).expanduser().absolute()
    json_path = Path(json_output).expanduser().absolute() if json_output else html_path.with_suffix(".json")
    html_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.write_text(html_report(payload), encoding="utf-8")
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return html_path, json_path


def unique_destination(directory: Path, name: str) -> Path:
    candidate = directory / name
    if not candidate.exists():
        return candidate
    stem = Path(name).stem
    suffix = Path(name).suffix
    for index in range(1, 1000):
        candidate = directory / f"{stem} {index}{suffix}"
        if not candidate.exists():
            return candidate
    raise RuntimeError("Could not find a unique Trash destination")


def move_to_macos_trash(path: Path) -> str:
    trash = Path.home() / ".Trash"
    trash.mkdir(exist_ok=True)
    destination = unique_destination(trash, path.name)
    os.replace(str(path), str(destination))
    return str(destination)


def move_to_windows_recycle_bin(path: Path) -> str:
    if not hasattr(ctypes, "windll"):
        raise RuntimeError("Windows Recycle Bin API is not available")

    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", ctypes.c_void_p),
            ("wFunc", ctypes.c_uint),
            ("pFrom", ctypes.c_wchar_p),
            ("pTo", ctypes.c_wchar_p),
            ("fFlags", ctypes.c_uint),
            ("fAnyOperationsAborted", ctypes.c_bool),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", ctypes.c_wchar_p),
        ]

    operation = SHFILEOPSTRUCTW()
    operation.wFunc = 3
    operation.pFrom = str(path) + "\0\0"
    operation.pTo = None
    operation.fFlags = 0x40 | 0x10 | 0x400
    result = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(operation))
    if result != 0:
        raise RuntimeError(f"Recycle Bin operation failed with code {result}")
    return "Recycle Bin"


def move_to_trash(path: Path) -> str:
    if os.name == "nt":
        return move_to_windows_recycle_bin(path)
    if sys.platform == "darwin":
        return move_to_macos_trash(path)
    raise RuntimeError("Trash is supported only on macOS and Windows by this skill")


def direct_delete(path: Path) -> str:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()
    return "deleted"


def reveal_in_file_manager(path: Path) -> str:
    if sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(path)])
        return "Finder"
    if os.name == "nt":
        subprocess.Popen(["explorer", f"/select,{str(path)}"])
        return "File Explorer"
    target = path if path.is_dir() else path.parent
    subprocess.Popen(["xdg-open", str(target)])
    return "file manager"


def is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def is_protected_delete_path(path: Path) -> bool:
    """Reject broad user/system containers; delete their specific children instead."""
    home = Path.home().absolute()
    candidates = {
        Path("/").absolute(),
        home,
        home / "Desktop",
        home / "Documents",
        home / "Downloads",
        home / "Library",
        home / "Library" / "Caches",
        home / "Library" / "Application Support",
        home / ".Trash",
    }
    if os.name == "nt":
        candidates.update(
            {
                Path("C:\\"),
                home / "AppData",
                home / "AppData" / "Local",
                home / "AppData" / "Roaming",
            }
        )
    try:
        absolute = path.absolute()
    except OSError:
        absolute = path
    return absolute in candidates


class CleanupHandler(http.server.BaseHTTPRequestHandler):
    report_html = ""
    roots: list[str] = []
    allowed: dict[str, dict[str, Any]] = {}
    reveal_allowed: dict[str, dict[str, Any]] = {}
    download_archives: dict[str, dict[str, Any]] = {}
    content_duplicate_candidates: dict[str, dict[str, Any]] = {}

    def log_message(self, format: str, *args: Any) -> None:
        sys.stderr.write("[storage-cleanup] " + (format % args) + "\n")

    def send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        clean_path = posixpath.normpath(parsed.path)
        if clean_path == "/api/disk-usage":
            try:
                self.send_json(200, {"disk_usage": collect_disk_usage(self.roots)})
            except Exception as exc:
                self.send_json(500, {"error": str(exc)})
            return
        if clean_path in {"/", "/index.html"}:
            body = self.report_html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path not in {"/api/delete", "/api/reveal", "/api/trash-download-archives", "/api/trash-content-duplicate-candidates"}:
            self.send_error(404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(min(length, 10000))
            request = json.loads(raw.decode("utf-8"))
            if parsed.path == "/api/reveal":
                self.handle_reveal(request)
                return
            if parsed.path == "/api/trash-download-archives":
                self.handle_trash_download_archives(request)
                return
            if parsed.path == "/api/trash-content-duplicate-candidates":
                self.handle_trash_content_duplicate_candidates(request)
                return
            item_id = str(request.get("id", ""))
            mode = str(request.get("mode", "trash"))
            confirm = str(request.get("confirm", ""))
            confirmed = bool(request.get("confirmed", False))
            item = self.allowed.get(item_id)
            if not item:
                self.send_json(403, {"error": "Path is not in the scan allow-list"})
                return
            expected = ("DELETE:" if mode == "delete" else "TRASH:") + item_id
            if mode == "trash" and confirmed:
                pass
            elif confirm != expected:
                self.send_json(400, {"error": "Confirmation phrase did not match"})
                return
            path = Path(item["path"])
            if not path.exists() and not path.is_symlink():
                self.send_json(404, {"error": "Path no longer exists", "id": item_id, "path": item["path"], "status": "missing"})
                return
            if is_protected_delete_path(path):
                self.send_json(400, {"error": "This is a broad container folder. Delete specific child folders instead."})
                return
            if mode == "delete":
                direct_delete(path)
                self.send_json(200, {"message": f"Directly deleted: {item['path']}", "id": item_id, "path": item["path"], "mode": mode, "status": "deleted"})
                return
            if mode != "trash":
                self.send_json(400, {"error": "Unsupported delete mode"})
                return
            destination = move_to_trash(path)
            self.send_json(200, {"message": f"Moved to Trash/Recycle Bin: {destination}", "id": item_id, "path": item["path"], "mode": mode, "status": "trashed"})
        except Exception as exc:
            self.send_json(500, {"error": str(exc)})

    def handle_reveal(self, request: dict[str, Any]) -> None:
        item_id = str(request.get("id", ""))
        item = self.reveal_allowed.get(item_id)
        if not item:
            self.send_json(403, {"error": "Path is not in the scan allow-list"})
            return
        path = Path(item["path"])
        if not path.exists() and not path.is_symlink():
            self.send_json(404, {"error": "Path no longer exists", "id": item_id, "path": item["path"], "status": "missing"})
            return
        opener = reveal_in_file_manager(path)
        self.send_json(200, {"message": f"Opened in {opener}: {item['path']}", "id": item_id, "path": item["path"]})

    def handle_trash_download_archives(self, request: dict[str, Any]) -> None:
        if not bool(request.get("confirmed", False)):
            self.send_json(400, {"error": "Confirmation is required"})
            return
        raw_ids = request.get("ids", [])
        if not isinstance(raw_ids, list):
            self.send_json(400, {"error": "ids must be a list"})
            return
        moved: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for raw_id in raw_ids:
            item_id = str(raw_id)
            item = self.download_archives.get(item_id)
            if not item:
                errors.append({"id": item_id, "error": "Archive is not in the download archive allow-list"})
                continue
            path = Path(item["path"])
            if not path.exists() and not path.is_symlink():
                missing.append({"id": item_id, "path": item["path"], "message": "Path no longer exists"})
                continue
            try:
                destination = move_to_trash(path)
                moved.append({"id": item_id, "path": item["path"], "message": f"Moved to Trash/Recycle Bin: {destination}"})
            except Exception as exc:
                errors.append({"id": item_id, "path": item["path"], "error": str(exc)})
        self.send_json(200, {"moved": moved, "missing": missing, "errors": errors})

    def handle_trash_content_duplicate_candidates(self, request: dict[str, Any]) -> None:
        if not bool(request.get("confirmed", False)):
            self.send_json(400, {"error": "Confirmation is required"})
            return
        raw_ids = request.get("ids", [])
        if not isinstance(raw_ids, list):
            self.send_json(400, {"error": "ids must be a list"})
            return
        moved: list[dict[str, Any]] = []
        missing: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        for raw_id in raw_ids:
            item_id = str(raw_id)
            item = self.content_duplicate_candidates.get(item_id)
            if not item:
                errors.append({"id": item_id, "error": "File is not in the content-duplicate candidate allow-list"})
                continue
            path = Path(item["path"])
            if not path.exists() and not path.is_symlink():
                missing.append({"id": item_id, "path": item["path"], "message": "Path no longer exists"})
                continue
            try:
                destination = move_to_trash(path)
                moved.append({"id": item_id, "path": item["path"], "message": f"Moved to Trash/Recycle Bin: {destination}"})
            except Exception as exc:
                errors.append({"id": item_id, "path": item["path"], "error": str(exc)})
        self.send_json(200, {"moved": moved, "missing": missing, "errors": errors})


def run_scan(args: argparse.Namespace) -> int:
    roots = [normalize_path(root) for root in (args.roots or default_roots())]
    min_size = max(0, int(args.min_size_mb * 1024 * 1024))
    records, errors = scan_roots(roots, min_size=min_size, top=args.top, follow_symlinks=args.follow_symlinks)
    payload = report_payload(records, errors, roots, include_content_duplicates=not args.skip_content_duplicates)
    html_path, json_path = write_scan_outputs(payload, args.output, args.json_output)
    print(f"HTML report: {html_path}")
    print(f"Scan JSON:   {json_path}")
    print(f"Items: {len(records)}; total listed size: {human_size(payload['summary']['total_size'])}; scan errors: {len(errors)}")
    return 0


def run_serve(args: argparse.Namespace) -> int:
    if not is_loopback_host(args.host):
        print("Refusing to enable cleanup actions on a non-local host. Use 127.0.0.1 or localhost.", file=sys.stderr)
        return 2
    data_path = Path(args.data).expanduser().absolute()
    report_path = Path(args.report).expanduser().absolute() if args.report else data_path.with_suffix(".html")
    payload = json.loads(data_path.read_text(encoding="utf-8"))
    html_text = report_path.read_text(encoding="utf-8")
    CleanupHandler.report_html = html_text
    CleanupHandler.roots = [normalize_path(root) for root in (payload.get("roots") or default_roots())]
    archive_items = {str(item["id"]): item for item in payload.get("download_archives", [])}
    content_duplicate_candidates = {
        str(item["id"]): item
        for group in payload.get("content_duplicate_files", [])
        for item in group.get("candidates", [])
    }
    content_duplicate_items = {
        str(item["id"]): item
        for group in payload.get("content_duplicate_files", [])
        for item in ([group.get("primary")] + group.get("candidates", []))
        if item
    }
    CleanupHandler.download_archives = archive_items
    CleanupHandler.content_duplicate_candidates = content_duplicate_candidates
    CleanupHandler.allowed = {str(item["id"]): item for item in payload.get("items", [])}
    CleanupHandler.allowed.update(archive_items)
    CleanupHandler.allowed.update(content_duplicate_candidates)
    CleanupHandler.reveal_allowed = dict(CleanupHandler.allowed)
    CleanupHandler.reveal_allowed.update(content_duplicate_items)
    address = (args.host, args.port)
    server = http.server.ThreadingHTTPServer(address, CleanupHandler)
    url = f"http://{args.host}:{server.server_address[1]}/"
    print(f"Serving report with deletion enabled: {url}")
    print("Only paths from the scan JSON are allowed. Press Ctrl+C to stop.")
    if args.open:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only storage analysis and local cleanup report service.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Run a read-only disk usage scan and generate an HTML report.")
    scan.add_argument("--roots", nargs="+", help="Folders or drives to scan. Defaults to all drives on Windows or / on macOS.")
    scan.add_argument("--output", default=str(Path.cwd() / "storage-cleanup-report.html"), help="HTML report output path.")
    scan.add_argument("--json-output", help="JSON scan output path. Defaults to the HTML path with .json suffix.")
    scan.add_argument("--min-size-mb", type=float, default=100.0, help="Only include items at least this large.")
    scan.add_argument("--top", type=int, default=250, help="Maximum number of largest items to include.")
    scan.add_argument("--follow-symlinks", action="store_true", help="Follow symlinks during scan. Disabled by default.")
    scan.add_argument("--skip-content-duplicates", action="store_true", help="Skip Downloads content-duplicate hashing for a faster report.")
    scan.set_defaults(func=run_scan)

    serve = subparsers.add_parser("serve", help="Serve a report locally and enable one-click deletion for scanned paths.")
    serve.add_argument("--data", required=True, help="Scan JSON produced by the scan command.")
    serve.add_argument("--report", help="HTML report to serve. Defaults to the JSON path with .html suffix.")
    serve.add_argument("--host", default="127.0.0.1", help="Bind host. Only 127.0.0.1, localhost, and ::1 are allowed.")
    serve.add_argument("--port", type=int, default=8765, help="Bind port. Use 0 to auto-select a free port.")
    serve.add_argument("--open", action="store_true", help="Open the report URL in the default browser.")
    serve.set_defaults(func=run_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
