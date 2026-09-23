"""Live folder monitor for ransomware-resilience timing measurements.

Run this BEFORE starting a test, pointed at the dataset folder. It records a
baseline snapshot, then polls the folder at a fixed interval and logs a
timestamped event for every file that is modified, created or deleted while the
test runs. When it stops it derives the attack timeline and (optionally) runs an
authoritative SHA-256 comparison against the manifest.

It answers three questions for the thesis:

  1. WHAT changed   -- modified / missing / new vs. the clean baseline
                       (hash-authoritative, via verify_dataset.py's logic)
  2. WHEN it changed -- a per-file event log with timestamps: when the first
                       change happened, when the last happened, total duration
  3. HOW FAST        -- encryption duration and a files-affected-over-time
                       timeline (how many files were hit in each time bucket)

Why polling (not filesystem events): under a real encryption storm the OS event
buffer can overflow and silently drop notifications, which would undercount --
fatal for a measurement tool. Periodic snapshots never drop changes; the only
cost is that timing resolution equals the poll interval (default 0.5 s), which
is far finer than the seconds-to-minutes an encryption pass takes.

Typical use
-----------
  # terminal 1 -- start monitoring, auto-stop 10 s after activity ceases
  python monitor_attack.py --root C:\\...\\dataset --idle-stop 10

  # terminal 2 -- run the attack (or real sample in the VM) against the folder
  # ... monitor stops itself, then prints the timeline and writes the logs

Outputs (written OUTSIDE the monitored folder so they are never touched):
  <out>/events_<ts>.csv      one row per change event, with timestamps
  <out>/timeline_<ts>.csv    files-affected per time bucket (plot this)
  <out>/summary_<ts>.json    all derived figures in one place

Exit codes: 0 = no changes seen, 1 = changes detected, 2 = usage/IO error.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from datetime import datetime, timezone

# Reuse the proven helpers from the verifier so the final hash comparison is
# identical to the standalone tool the rest of the workflow already uses.
import verify_dataset as vd

# Files that live beside the data but are never part of the measured set.
IGNORE_NAMES = {"_manifest.json", "_manifest.csv", "_checkpoint.jsonl"}


def snapshot(root, ignore_abs):
    """Map every data file under root to a cheap change-signal (size, mtime).

    (size, mtime) is enough to notice that a file was rewritten between two
    polls without paying to hash gigabytes every half second. The authoritative
    hash check runs once at the end.
    """
    snap = {}
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            if n in IGNORE_NAMES:
                continue
            full = os.path.join(dirpath, n)
            if full in ignore_abs:
                continue
            try:
                st = os.stat(full)
            except OSError:
                continue  # file vanished mid-walk; caught on the next poll
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            snap[rel] = (st.st_size, st.st_mtime_ns)
    return snap


def diff(prev, cur):
    """Yield (relpath, event) for changes between two snapshots."""
    for rel in cur.keys() - prev.keys():
        yield rel, "created"
    for rel in prev.keys() - cur.keys():
        yield rel, "deleted"
    for rel in prev.keys() & cur.keys():
        if prev[rel] != cur[rel]:
            yield rel, "modified"


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="milliseconds")


def final_hash_compare(root, manifest_path, ignore_abs, workers):
    """Authoritative modified/missing/new/unchanged via SHA-256 vs. manifest."""
    manifest = vd.load_manifest(manifest_path)
    expected = manifest["files"]
    on_disk = {rel: full for rel, full in _walk_files(root, ignore_abs)}

    missing = sorted(set(expected) - set(on_disk))
    new = sorted(set(on_disk) - set(expected))
    present = sorted(set(expected) & set(on_disk))

    payload = [(root, rel, expected[rel]["size"], expected[rel]["sha256"], False)
               for rel in present]
    results = []
    if payload:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(vd._check, payload, chunksize=32))
    modified = [r["relpath"] for r in results if r["status"] == "modified"]
    unchanged = [r for r in results if r["status"] == "unchanged"]

    bytes_expected = sum(e["size"] for e in expected.values())
    bytes_ok = sum(r["size"] for r in unchanged)
    return {
        "modified": sorted(modified),
        "missing": missing,
        "new": new,
        "counts": {
            "unchanged": len(unchanged),
            "modified": len(modified),
            "missing": len(missing),
            "new": len(new),
            "in_manifest": len(expected),
        },
        "bytes": {"expected": bytes_expected, "intact": bytes_ok},
        "intact_pct": round(100.0 * bytes_ok / bytes_expected, 2) if bytes_expected else None,
    }


def _walk_files(root, ignore_abs):
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            if n in IGNORE_NAMES:
                continue
            full = os.path.join(dirpath, n)
            if full in ignore_abs:
                continue
            yield os.path.relpath(full, root).replace(os.sep, "/"), full


def main():
    ap = argparse.ArgumentParser(description="Time a file-encryption test against a manifest baseline.")
    ap.add_argument("--root", required=True, help="dataset folder to watch")
    ap.add_argument("--manifest", help="manifest path (default: <root>/_manifest.json)")
    ap.add_argument("--interval", type=float, default=0.5, help="poll interval seconds (timing resolution)")
    ap.add_argument("--duration", type=float, default=0, help="stop after N seconds (0 = until idle-stop or Ctrl+C)")
    ap.add_argument("--idle-stop", type=float, default=0,
                    help="stop once no change has been seen for N seconds (0 = disabled)")
    ap.add_argument("--bucket", type=float, default=1.0, help="timeline bucket width in seconds")
    ap.add_argument("--out-dir", default=".", help="where to write the logs (kept out of --root)")
    ap.add_argument("--no-verify", action="store_true", help="skip the final SHA-256 comparison")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"error: no such directory: {root}", file=sys.stderr)
        return 2
    manifest_path = args.manifest or os.path.join(root, "_manifest.json")
    if not args.no_verify and not os.path.isfile(manifest_path):
        print(f"error: manifest not found: {manifest_path}", file=sys.stderr)
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    events_path = os.path.abspath(os.path.join(args.out_dir, f"events_{stamp}.csv"))
    timeline_path = os.path.abspath(os.path.join(args.out_dir, f"timeline_{stamp}.csv"))
    summary_path = os.path.abspath(os.path.join(args.out_dir, f"summary_{stamp}.json"))
    # Never let our own output files register as "new" during the walk.
    ignore_abs = {events_path, timeline_path, summary_path}

    print(f"root      : {root}")
    print(f"baseline  : taking snapshot ...")
    base = snapshot(root, ignore_abs)
    print(f"            {len(base):,} files under watch")
    print(f"interval  : {args.interval}s   stop: "
          + (f"{args.duration}s" if args.duration else
             (f"idle {args.idle_stop}s" if args.idle_stop else "Ctrl+C"))
          + f"\nlogging   : {events_path}\n")
    print("watching -- start the test now. Ctrl+C to stop.\n")

    ev_fh = open(events_path, "w", newline="", encoding="utf-8")
    ev_writer = csv.writer(ev_fh)
    ev_writer.writerow(["wall_utc", "epoch", "elapsed_s", "since_first_change_s", "event", "relpath", "size"])

    t_start = time.time()
    prev = base
    events = []            # (epoch, event, relpath, size)
    first_change = None
    last_change = None
    unique_changed = set()

    try:
        while True:
            loop_t = time.time()
            cur = snapshot(root, ignore_abs)
            now = time.time()
            for rel, kind in diff(prev, cur):
                size = cur.get(rel, (0, 0))[0]
                # Re-stat created/modified files: the poll can catch a file
                # mid-rewrite (truncated to 0 bytes), so read a settled size.
                if kind != "deleted":
                    try:
                        size = os.path.getsize(os.path.join(root, rel.replace("/", os.sep)))
                    except OSError:
                        pass
                if first_change is None:
                    first_change = now
                last_change = now
                unique_changed.add(rel)
                events.append((now, kind, rel, size))
                ev_writer.writerow([
                    iso(now), f"{now:.3f}", f"{now - t_start:.3f}",
                    f"{now - first_change:.3f}", kind, rel, size,
                ])
            ev_fh.flush()
            prev = cur

            n = len(events)
            live = (f"\r  elapsed {now - t_start:6.1f}s | events {n:5,} | "
                    f"files {len(unique_changed):5,}")
            if first_change:
                live += f" | active {last_change - first_change:6.1f}s"
            print(live, end="", flush=True)

            if args.duration and (now - t_start) >= args.duration:
                break
            if args.idle_stop and last_change and (now - last_change) >= args.idle_stop:
                print(f"\n\nno activity for {args.idle_stop}s -- stopping.")
                break

            time.sleep(max(0, args.interval - (time.time() - loop_t)))
    except KeyboardInterrupt:
        print("\n\ninterrupted -- finalising.")
    finally:
        ev_fh.close()

    # ---- derive the timeline ------------------------------------------------
    print("\n" + "=" * 62)
    print("TIMELINE")
    print("=" * 62)
    if not events:
        print("  no file changes were observed.")
    else:
        window = last_change - first_change
        print(f"  first change : {iso(first_change)}")
        print(f"  last change  : {iso(last_change)}")
        print(f"  duration     : {window:.1f}s  (encryption window)")
        print(f"  total events : {len(events):,}")
        by_kind = {}
        for _, kind, _, _ in events:
            by_kind[kind] = by_kind.get(kind, 0) + 1
        for kind in ("modified", "created", "deleted"):
            if kind in by_kind:
                print(f"     {kind:<9}: {by_kind[kind]:,}")
        print(f"  files hit    : {len(unique_changed):,} unique")
        rate = len(unique_changed) / window if window > 0 else len(unique_changed)
        print(f"  mean rate    : {rate:,.1f} files/s over the window")

        # bucket the events so the thesis can plot files-over-time
        buckets = {}
        for epoch, _, rel, _ in events:
            b = int((epoch - first_change) // args.bucket)
            buckets.setdefault(b, []).append(rel)
        peak = max(len(v) for v in buckets.values())
        peak_at = max(buckets, key=lambda b: len(buckets[b])) * args.bucket
        print(f"  peak rate    : {peak:,} events in one {args.bucket:g}s bucket "
              f"(at ~{peak_at:.0f}s)")

        with open(timeline_path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["bucket_start_s", "events_in_bucket", "cumulative_events", "cumulative_unique_files"])
            seen, cum = set(), 0
            for b in range(0, max(buckets) + 1):
                rels = buckets.get(b, [])
                cum += len(rels)
                seen.update(rels)
                w.writerow([f"{b * args.bucket:.1f}", len(rels), cum, len(seen)])
        print(f"\n  timeline csv : {timeline_path}")

    # ---- authoritative hash comparison -------------------------------------
    final = None
    if not args.no_verify:
        print("\n" + "=" * 62)
        print("DAMAGE (SHA-256 vs. manifest)")
        print("=" * 62)
        print("  hashing current files ...")
        final = final_hash_compare(root, manifest_path, ignore_abs, args.workers)
        c = final["counts"]
        print(f"  unchanged {c['unchanged']:>7,}   modified {c['modified']:>7,}   "
              f"missing {c['missing']:>7,}   new {c['new']:>7,}")
        if final["intact_pct"] is not None:
            print(f"  intact data: {final['intact_pct']}% of baseline bytes")

    # ---- one summary file ---------------------------------------------------
    summary = {
        "root": root,
        "manifest": manifest_path,
        "monitor_start_utc": iso(t_start),
        "monitor_end_utc": iso(time.time()),
        "poll_interval_s": args.interval,
        "baseline_files": len(base),
        "observed": {
            "total_events": len(events),
            "unique_files_changed": len(unique_changed),
            "first_change_utc": iso(first_change) if first_change else None,
            "last_change_utc": iso(last_change) if last_change else None,
            "encryption_window_s": round(last_change - first_change, 3) if events else 0,
        },
        "final_hash_comparison": final,
        "outputs": {"events_csv": events_path, "timeline_csv": timeline_path if events else None},
    }
    with open(summary_path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, indent=1)
    print(f"\nsummary      : {summary_path}")

    return 1 if events else 0


if __name__ == "__main__":
    sys.exit(main())
