"""Verify a dataset against its SHA-256 manifest.

Re-scans the dataset directory, compares every file against the manifest and
reports:

    unchanged  file present, hash identical
    modified   file present, hash differs   (encrypted / tampered)
    missing    file in manifest, absent on disk
    new        file on disk, not in manifest (ransom notes, .encrypted copies)

"new" is not one of the three baseline categories but is reported separately
because ransomware typically *adds* files -- dropping ransom notes and writing
encrypted copies alongside or instead of the originals. Counting only the
first three would understate the blast radius.

Usage
-----
    python verify_dataset.py --root D:\\share\\dataset
    python verify_dataset.py --root D:\\share\\dataset --report after_attack.json
    python verify_dataset.py --root D:\\share\\dataset --entropy
    python verify_dataset.py --root D:\\share\\dataset --manifest .\\baseline.json

Exit codes: 0 = pristine, 1 = differences found, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone

MANIFEST_JSON = "_manifest.json"
MANIFEST_CSV = "_manifest.csv"
EXCLUDED_NAMES = {MANIFEST_JSON, MANIFEST_CSV}


def human(n):
    """Format a byte count as a readable size, e.g. 1536 -> '1.5 KB'."""
    n = float(n)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{n:,.0f} B"
        n /= 1024


def sha256_file(path, chunk=1 << 20):
    """SHA-256 fingerprint of a file, read in 1 MB blocks so large files
    don't have to fit in memory."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def shannon_entropy(path, limit=1 << 20):
    """Bits per byte over the first `limit` bytes. 8.0 = indistinguishable
    from random; encrypted output sits at ~7.99."""
    with open(path, "rb") as fh:
        data = fh.read(limit)
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def load_manifest(path):
    """Accepts either the JSON or the CSV manifest."""
    if path.lower().endswith(".csv"):
        entries = {}
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                entries[row["relpath"]] = {
                    "relpath": row["relpath"],
                    "size": int(row["size"]),
                    "sha256": row["sha256"],
                    "type": row.get("type", ""),
                }
        return {"files": entries, "meta": {}}

    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return {
        "files": {e["relpath"]: e for e in data.get("files", [])},
        "meta": {k: v for k, v in data.items() if k != "files"},
    }


def scan_disk(root):
    """Relative paths of every file under root, manifests excluded."""
    found = {}
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if rel in EXCLUDED_NAMES or name in EXCLUDED_NAMES:
                continue
            found[rel] = full
    return found


def _check(args):
    """Worker: hash one file and compare against its manifest entry."""
    root, rel, expected_size, expected_hash, want_entropy = args
    full = os.path.join(root, rel.replace("/", os.sep))
    try:
        size = os.path.getsize(full)
        digest = sha256_file(full)
    except OSError as exc:
        return {"relpath": rel, "status": "unreadable", "detail": str(exc)}
    res = {
        "relpath": rel,
        "status": "unchanged" if digest == expected_hash else "modified",
        "size": size,
        "expected_size": expected_size,
    }
    if res["status"] == "modified":
        res["expected_sha256"] = expected_hash
        res["actual_sha256"] = digest
        res["size_delta"] = size - expected_size
        if want_entropy:
            try:
                res["entropy"] = round(shannon_entropy(full), 3)
            except OSError:
                pass
    return res


def _entropy_only(args):
    root, rel = args
    full = os.path.join(root, rel.replace("/", os.sep))
    try:
        return rel, round(shannon_entropy(full), 3)
    except OSError:
        return rel, None


def main():
    """Load the manifest, re-hash every file on disk in parallel, then print
    the unchanged/modified/missing/new breakdown. Returns the exit code."""
    ap = argparse.ArgumentParser(description="Verify a dataset against its manifest.")
    ap.add_argument("--root", required=True, help="dataset directory to verify")
    ap.add_argument("--manifest", help=f"manifest path (default: <root>/{MANIFEST_JSON})")
    ap.add_argument("--report", help="write a full JSON report here")
    ap.add_argument("--entropy", action="store_true",
                    help="also report Shannon entropy per file type")
    ap.add_argument("--list", type=int, default=20,
                    help="how many affected files to print per category (0 = all)")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"error: no such directory: {root}", file=sys.stderr)
        return 2

    manifest_path = args.manifest or os.path.join(root, MANIFEST_JSON)
    if not os.path.isfile(manifest_path):
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        print("hint: keep a copy of the manifest OFF the share -- ransomware "
              "that encrypts the share will encrypt the manifest too.", file=sys.stderr)
        return 2

    manifest = load_manifest(manifest_path)
    expected = manifest["files"]
    on_disk = scan_disk(root)

    missing = sorted(set(expected) - set(on_disk))
    new = sorted(set(on_disk) - set(expected))
    present = sorted(set(expected) & set(on_disk))

    print(f"manifest : {manifest_path}")
    if manifest["meta"]:
        m = manifest["meta"]
        print(f"           generated {m.get('generated_utc', '?')}, "
              f"seed {m.get('seed', '?')}, {m.get('actual_files', '?')} files")
    print(f"root     : {root}")
    print(f"scanning {len(present):,} present + {len(missing):,} missing + "
          f"{len(new):,} new ...\n")

    payload = [(root, rel, expected[rel]["size"], expected[rel]["sha256"], args.entropy)
               for rel in present]
    results = []
    if payload:
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            for i, res in enumerate(pool.map(_check, payload, chunksize=32), 1):
                results.append(res)
                if i % 200 == 0 or i == len(payload):
                    print(f"\r  hashed {i:,}/{len(payload):,}", end="", flush=True)
        print()

    unchanged = [r for r in results if r["status"] == "unchanged"]
    modified = [r for r in results if r["status"] == "modified"]
    unreadable = [r for r in results if r["status"] == "unreadable"]

    total_expected = len(expected)
    bytes_expected = sum(e["size"] for e in expected.values())
    bytes_ok = sum(r["size"] for r in unchanged)

    def pct(n):
        return f"{(100.0 * n / total_expected):5.1f}%" if total_expected else "  n/a"

    print("\n" + "=" * 62)
    print("RESULT")
    print("=" * 62)
    print(f"  unchanged   {len(unchanged):>8,}  {pct(len(unchanged))}")
    print(f"  modified    {len(modified):>8,}  {pct(len(modified))}")
    print(f"  missing     {len(missing):>8,}  {pct(len(missing))}")
    if unreadable:
        print(f"  unreadable  {len(unreadable):>8,}  {pct(len(unreadable))}")
    print(f"  {'-' * 40}")
    print(f"  in manifest {total_expected:>8,}")
    print(f"  new on disk {len(new):>8,}  (not in manifest)")
    print()
    print(f"  intact data {human(bytes_ok)} of {human(bytes_expected)} "
          f"({100.0 * bytes_ok / bytes_expected:.2f}%)" if bytes_expected else "")

    damaged = len(modified) + len(missing) + len(unreadable)
    print(f"  damaged     {damaged:,} file(s)")

    def show(title, items, fmt):
        if not items:
            return
        cap = len(items) if args.list == 0 else min(args.list, len(items))
        print(f"\n{title} ({len(items):,}):")
        for it in items[:cap]:
            print("  " + fmt(it))
        if cap < len(items):
            print(f"  ... and {len(items) - cap:,} more "
                  f"(use --list 0 or --report for the full set)")

    show("MODIFIED", modified,
         lambda r: f"{r['relpath']}  ({human(r['expected_size'])} -> {human(r['size'])}"
                   + (f", entropy {r['entropy']}" if "entropy" in r else "") + ")")
    show("MISSING", missing, lambda p: f"{p}  ({human(expected[p]['size'])} expected)")
    show("NEW", new, lambda p: f"{p}  ({human(os.path.getsize(on_disk[p]))})")
    show("UNREADABLE", unreadable, lambda r: f"{r['relpath']}  ({r['detail']})")

    # Per-type breakdown: shows at a glance whether an attack targeted
    # specific extensions, which most real families do.
    if modified or missing:
        by_type = {}
        for rel in [r["relpath"] for r in modified] + missing:
            ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else "(none)"
            by_type[ext] = by_type.get(ext, 0) + 1
        print("\nDAMAGE BY FILE TYPE:")
        for ext, n in sorted(by_type.items(), key=lambda kv: -kv[1]):
            print(f"  .{ext:<6} {n:>7,}")

    entropy_summary = {}
    if args.entropy:
        print("\nENTROPY (bits/byte, first 1 MB, mean by type):")
        pool_args = [(root, rel) for rel in present]
        buckets = {}
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            for rel, ent in pool.map(_entropy_only, pool_args, chunksize=32):
                if ent is None:
                    continue
                ext = rel.rsplit(".", 1)[-1].lower() if "." in rel else "(none)"
                buckets.setdefault(ext, []).append(ent)
        for ext in sorted(buckets):
            vals = buckets[ext]
            mean = sum(vals) / len(vals)
            entropy_summary[ext] = {
                "count": len(vals), "mean": round(mean, 3),
                "min": round(min(vals), 3), "max": round(max(vals), 3),
            }
            print(f"  .{ext:<6} n={len(vals):>6,}  mean {mean:5.2f}  "
                  f"min {min(vals):5.2f}  max {max(vals):5.2f}")
        print("  note: compressed containers (docx/xlsx/png/jpg) sit near 8.0 by")
        print("        design -- only txt/csv/pdf give entropy-based detection headroom.")

    if args.report:
        report = {
            "verified_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "root": root,
            "manifest": manifest_path,
            "counts": {
                "unchanged": len(unchanged),
                "modified": len(modified),
                "missing": len(missing),
                "unreadable": len(unreadable),
                "new": len(new),
                "in_manifest": total_expected,
            },
            "bytes": {"expected": bytes_expected, "intact": bytes_ok},
            "modified": modified,
            "missing": [{"relpath": p, "expected_size": expected[p]["size"],
                         "expected_sha256": expected[p]["sha256"]} for p in missing],
            "new": [{"relpath": p, "size": os.path.getsize(on_disk[p])} for p in new],
            "unreadable": unreadable,
            "entropy_by_type": entropy_summary,
        }
        with open(args.report, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=1)
        print(f"\nreport written to {args.report}")

    clean = not (modified or missing or new or unreadable)
    print("\n" + ("PRISTINE - dataset matches the manifest exactly."
                  if clean else "DIFFERENCES FOUND."))
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main())
