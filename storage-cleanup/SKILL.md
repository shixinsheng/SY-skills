---
name: storage-cleanup
description: Use this skill for read-only storage analysis and safe cleanup planning on macOS or Windows. Trigger when the user asks to clean disk/storage space or common Chinese phrasing such as "清理内存", "清理磁盘", "清理空间", "清理存储空间", "内存满了", "硬盘满了", "空间不够", "内存不足", "占空间", "哪些东西占地方", "帮我看看存储", "帮我进行存储分析", "存储空间", "电脑空间不够/不足/满了", "清缓存", or English requests such as "storage analysis", "disk cleanup", and "cleanup storage". In Chinese user requests, treat "内存" as likely meaning disk/storage space unless the user clearly means RAM.
---

# Storage Cleanup

## Purpose

Use this skill to inspect disk usage without modifying files, identify the largest storage consumers, classify cleanup candidates by risk, and produce an interactive HTML report. Scanning must be read-only. Deletion is allowed only after the user explicitly asks to enable the local report service and then clicks a delete action in the report.

## Safety Rules

- Never delete, move, rename, edit, or truncate files during `scan`.
- Default disk usage scanning must not read file contents. The Downloads content-duplicate panel may read file bytes only to compute local SHA-256 hashes; never display file contents.
- Do not print secrets, `.env` values, private keys, tokens, or credential contents.
- Do not add telemetry, analytics, remote network calls, or cloud upload.
- For deletion, prefer "move to Trash/Recycle Bin". Direct delete requires explicit confirmation in the local web UI.
- Treat system, app data, database, VM, mail, photo library, and development state directories as risky unless the user confirms their intent.

## Workflow

1. Confirm the user's intent is storage cleanup or disk analysis. If they say "清理内存" in ordinary Chinese, assume they mean storage space unless RAM is clearly mentioned.
2. Run a read-only scan with `scripts/storage_cleanup.py scan`.
3. Open or share the generated HTML report path. Explain the three tiers:
   - Green: `可自动清理`
   - Yellow: `需人工判断`
   - Red: `谨慎清理`
4. If the user asks for one-click deletion, run `scripts/storage_cleanup.py serve` against the generated report JSON. The service binds to `127.0.0.1` and only accepts paths from the scan result.
5. After any deletion, recommend rerunning `scan` to produce an updated report.

## Commands

macOS:

```bash
python3 /path/to/storage-cleanup/scripts/storage_cleanup.py scan --output ~/Desktop/storage-cleanup-report.html
python3 /path/to/storage-cleanup/scripts/storage_cleanup.py serve --data ~/Desktop/storage-cleanup-report.json --report ~/Desktop/storage-cleanup-report.html
```

Windows PowerShell:

```powershell
py -3 .\storage-cleanup\scripts\storage_cleanup.py scan --output "$env:USERPROFILE\Desktop\storage-cleanup-report.html"
py -3 .\storage-cleanup\scripts\storage_cleanup.py serve --data "$env:USERPROFILE\Desktop\storage-cleanup-report.json" --report "$env:USERPROFILE\Desktop\storage-cleanup-report.html"
```

Useful scan options:

- `--roots PATH [PATH ...]`: scan specific drives or folders instead of the default roots.
- `--min-size-mb N`: hide entries smaller than N MB from the report.
- `--top N`: limit the report to the N largest findings.
- `--json-output PATH`: write machine-readable scan data for the local delete service.
- `--follow-symlinks`: disabled by default; avoid unless the user understands the risk.
- `--skip-content-duplicates`: skip Downloads content-duplicate hashing for a faster first-pass report when the user needs urgent space relief.

## Classification Guide

Use these tiers consistently:

- `可自动清理`: user caches, temporary files, trash/recycle bin, logs, package manager caches, browser caches, build caches, and rebuildable generated artifacts.
- `需人工判断`: downloads, old installers, archives, large media, duplicate candidates, old backups, project dependency folders such as `node_modules`, and large user-created folders.
- `谨慎清理`: operating system folders, app support data, mail stores, Photos libraries, databases, virtual machine images, package manager state, source control metadata, and anything under sensitive system paths.

When unsure, classify as `需人工判断` or `谨慎清理`; do not downgrade risk to make cleanup look easier.

## Report Requirements

The report must be an interactive HTML file with:

- Green/yellow/red visual treatment for the three cleanup tiers.
- Collapsible interaction for every visible report section, including dashboard cards, archive panels, duplicate panels, tier summaries, tier sections, and directory groups.
- Sorting and text filtering.
- A dedicated Downloads archive panel that finds compressed packages/installers in the user's Downloads folder, summarizes count and size, and supports one-click move-to-Trash in local service mode.
- A Downloads content-duplicates panel for documents, images, and videos. It scans only the Downloads folder, compares file contents by SHA-256 after size prefiltering, keeps one file in each duplicate group, and cleanup actions move only removable duplicates to Trash.
- "Show in file manager" buttons for every report item, including tier items, TOP6 items, Downloads archives, and Downloads duplicate-content files.
- A before/after cleanup comparison inside Disk Overview. In local service mode, refresh current disk free space after cleanup actions; in static report mode, show scan-time disk data and explain that realtime comparison requires local service mode.
- Per-item "keep" markers for current-report-only ignore/keep decisions. Kept items must be visually marked, excluded from pending cleanup counts and recommendations, and disabled for cleanup until the user cancels the keep marker.
- Avoid showing terminal commands in the default UI; keep visible labels user-facing and action-oriented.
- Use the ClearSpace display brand in the report header while keeping the internal skill name `storage-cleanup`.
- Use a polished, user-facing macOS utility visual design: a refined custom logo, premium wordmark, strong contrast, graphical dashboard surfaces, clear icons, compact professional buttons, visible state changes, and no developer-oriented button text or code snippets in the main report.
- Delete buttons that are disabled in static file mode and enabled only when served by the local service.
- A visible notice that scanning is read-only and deletion is a separate user action.

## Deletion Service Requirements

Only start the local service when the user explicitly asks to delete from the web report. The service must:

- Bind to `127.0.0.1` by default.
- Load allowed paths from the scan JSON.
- Reject any path not present in the scan JSON.
- For reveal/show-in-file-manager actions, accept only IDs listed in the scan JSON and open the path locally without modifying it.
- For realtime disk comparison, expose a read-only local disk-usage endpoint that returns current capacity/used/free data and does not modify files.
- For Downloads archive bulk cleanup, accept only archive IDs listed in `download_archives` from the scan JSON.
- For Downloads content-duplicate cleanup, accept only candidate IDs listed under `content_duplicate_files[].candidates`; never bulk-delete the chosen primary/kept file. UI labels must say "keep one" and "remove duplicates" instead of implying all matching files will be deleted.
- Move to Trash/Recycle Bin by default.
- Require stronger confirmation for direct delete.
- Return clear errors for missing paths, permission failures, unsupported Trash behavior, or files in use.
