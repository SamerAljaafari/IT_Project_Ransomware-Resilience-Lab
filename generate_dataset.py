"""Generate a reproducible, structurally-valid test dataset for
ransomware-resilience measurements on an SMB file share.

Every file is a real, openable document (DOCX/XLSX/PDF/JPG/PNG) or genuine
plain text (TXT/CSV) built from a fixed business-language corpus -- never
random bytes. A SHA-256 manifest is written at the end; use verify_dataset.py
to diff the share against it after an attack or a restore.

Usage
-----
    python generate_dataset.py --out D:\\share\\dataset --size-gb 0.1 --files 300
    python generate_dataset.py --out D:\\share\\dataset --size-gb 8 --files 8000
    python generate_dataset.py --out ... --size-gb 8 --files 8000 --dry-run

Reproducibility
---------------
Each file's content is derived from SHA-256(seed, relative_path), so the
dataset is identical regardless of worker count or generation order. Byte-
identical regeneration additionally requires the same versions of
python-docx / openpyxl / reportlab / Pillow, since those libraries control
container layout.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import random
import re
import time
import zipfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import date, datetime, timedelta, timezone

import corpus

# --------------------------------------------------------------------------
# Tunables
# --------------------------------------------------------------------------

KB = 1024
MB = 1024 * 1024
GB = 1024 * 1024 * 1024

SMALL_RANGE = (10 * KB, 500 * KB)
MEDIUM_RANGE = (1 * MB, 10 * MB)
LARGE_RANGE = (100 * MB, 500 * MB)

# Share of the *file count* in each tier. Large-file count is derived from the
# byte budget instead, since a handful of them dominates total size.
SMALL_FRACTION = 0.92

# Which formats appear in which tier. Large files are text-based only:
# a 300 MB DOCX or PNG is neither realistic nor practical to build.
SMALL_TYPES = ["docx", "xlsx", "pdf", "jpg", "png", "txt", "csv"]
SMALL_WEIGHTS = [22, 18, 16, 14, 8, 12, 10]
MEDIUM_TYPES = ["docx", "xlsx", "pdf", "jpg", "png", "csv", "txt"]
# Weighted away from DOCX/XLSX: multi-MB office containers are both rarer on a
# real share and far more expensive to build than exports and photos.
MEDIUM_WEIGHTS = [10, 10, 14, 22, 10, 20, 14]
LARGE_TYPES = ["csv", "txt"]
LARGE_WEIGHTS = [60, 40]

# Formats written at an exact byte count; used to trim the dataset to --size-gb.
EXACT_TYPES = {"txt", "csv"}

# A fixed embedded timestamp for every office document. Without this, python-docx
# and openpyxl stamp the current wall-clock into core.xml, and reportlab stamps
# it into the PDF trailer -- making otherwise-identical files differ byte-for-byte
# between runs and breaking reproducibility. Value is arbitrary but must be fixed.
FIXED_DT = datetime(2024, 1, 1, 0, 0, 0)

FOLDERS = [
    ("Finance/Invoices/2024", 10),
    ("Finance/Invoices/2025", 10),
    ("Finance/Budgets", 6),
    ("Finance/Reports", 6),
    ("HR/Personnel", 7),
    ("HR/Payroll", 5),
    ("HR/Recruiting", 4),
    ("HR/Training", 3),
    ("Projects/2024/Alpha", 6),
    ("Projects/2024/Beta", 5),
    ("Projects/2025/Gamma", 7),
    ("Projects/2025/Delta", 6),
    ("Projects/2025/Shared", 5),
    ("Archive/2019", 4),
    ("Archive/2020", 4),
    ("Archive/2021", 4),
    ("Operations/Logs", 5),
    ("Operations/Exports", 5),
    ("Legal/Contracts", 4),
    ("Marketing/Assets", 4),
]

MANIFEST_JSON = "_manifest.json"
MANIFEST_CSV = "_manifest.csv"
# Append-only log of completed files, enabling --resume after an interruption.
# Deleted automatically once a run finishes cleanly.
CHECKPOINT = "_checkpoint.jsonl"
# These live beside the data but must never be part of the hashed set.
EXCLUDED_NAMES = {MANIFEST_JSON, MANIFEST_CSV, CHECKPOINT}


# --------------------------------------------------------------------------
# Planning
# --------------------------------------------------------------------------

@dataclass
class FileSpec:
    relpath: str
    ftype: str
    tier: str
    target: int          # planned size in bytes (exact for txt/csv, approx otherwise)


def derive_rng(seed: int, relpath: str) -> random.Random:
    """Per-file RNG that does not depend on generation order."""
    h = hashlib.sha256(f"{seed}:{relpath}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(h[:8], "big"))


def plan_counts(n_files: int, total_bytes: int):
    """Split the file count across tiers so both targets are met."""
    small_mean = sum(SMALL_RANGE) / 2
    medium_mean = sum(MEDIUM_RANGE) / 2
    large_mean = sum(LARGE_RANGE) / 2

    n_large = 0
    for _ in range(12):  # converges in 2-3 rounds
        n_small = int(round(n_files * SMALL_FRACTION))
        n_medium = max(0, n_files - n_small - n_large)
        used = n_small * small_mean + n_medium * medium_mean
        residual = total_bytes - used
        new_large = max(0, int(round(residual / large_mean)))
        if new_large == n_large:
            break
        n_large = new_large

    n_small = int(round(n_files * SMALL_FRACTION))
    n_medium = max(0, n_files - n_small - n_large)
    if n_large > n_files:  # tiny --files with a huge --size-gb
        n_large, n_small, n_medium = n_files, 0, 0
    return n_small, n_medium, n_large


def make_filename(rng, ftype, tier, folder):
    top = folder.split("/")[0]
    year = rng.choice([2019, 2020, 2021, 2024, 2025])
    d = date(year, rng.randint(1, 12), rng.randint(1, 28))
    tag = f"{rng.randint(1000, 9999)}"

    if tier == "large":
        base = rng.choice([
            f"export_{top.lower()}_{d.isoformat()}_full",
            f"audit_trail_{year}_complete",
            f"ledger_dump_{year}_Q{rng.randint(1, 4)}",
            f"transaction_log_{d.isoformat()}",
        ])
        return f"{base}.{ftype}"

    stems = {
        "Finance": ["Invoice", "Budget", "Forecast", "CostReport", "Reconciliation"],
        "HR": ["Personnel", "Payroll", "Contract", "Training", "Appraisal"],
        "Projects": ["Spec", "Status", "Minutes", "Plan", "Handover"],
        "Archive": ["Archived", "Backup", "Legacy", "Record"],
        "Operations": ["Runbook", "Export", "Inventory", "Checklist"],
        "Legal": ["Agreement", "NDA", "Addendum", "Policy"],
        "Marketing": ["Campaign", "Brochure", "Banner", "Factsheet"],
    }.get(top, ["Document"])

    stem = rng.choice(stems)
    pattern = rng.randint(0, 3)
    if pattern == 0:
        name = f"{stem}_{d.isoformat()}_{tag}"
    elif pattern == 1:
        name = f"{stem}_Q{rng.randint(1, 4)}_{year}_v{rng.randint(1, 4)}"
    elif pattern == 2:
        name = f"{stem}_{corpus.COST_CENTRES[rng.randrange(len(corpus.COST_CENTRES))]}"
    else:
        name = f"{stem}_{rng.choice(corpus.CITIES)}_{tag}"
    return f"{name}.{ftype}"


def build_plan(seed: int, n_files: int, total_bytes: int):
    """Deterministic list of FileSpecs, sized to hit total_bytes."""
    rng = random.Random(seed)
    n_small, n_medium, n_large = plan_counts(n_files, total_bytes)

    folder_names = [f for f, _ in FOLDERS]
    folder_weights = [w for _, w in FOLDERS]

    specs = []
    used_paths = set()

    def add(tier, types, weights, size_range, count):
        for _ in range(count):
            ftype = rng.choices(types, weights=weights)[0]
            if tier == "large":
                folder = rng.choice([
                    "Operations/Logs", "Operations/Exports",
                    "Archive/2019", "Archive/2020", "Archive/2021",
                    "Finance/Reports",
                ])
            else:
                folder = rng.choices(folder_names, weights=folder_weights)[0]
            size = rng.randint(*size_range)
            for attempt in range(200):
                fname = make_filename(rng, ftype, tier, folder)
                if attempt:
                    stem, ext = fname.rsplit(".", 1)
                    fname = f"{stem}_{attempt:02d}.{ext}"
                relpath = f"{folder}/{fname}"
                if relpath not in used_paths:
                    break
            used_paths.add(relpath)
            specs.append(FileSpec(relpath, ftype, tier, size))

    add("small", SMALL_TYPES, SMALL_WEIGHTS, SMALL_RANGE, n_small)
    add("medium", MEDIUM_TYPES, MEDIUM_WEIGHTS, MEDIUM_RANGE, n_medium)
    add("large", LARGE_TYPES, LARGE_WEIGHTS, LARGE_RANGE, n_large)

    rebalance(specs, total_bytes)
    specs.sort(key=lambda s: s.relpath)
    return specs


TIER_RANGES = {"small": SMALL_RANGE, "medium": MEDIUM_RANGE, "large": LARGE_RANGE}


def rebalance(specs, total_bytes):
    """Scale planned sizes onto total_bytes, largest tier first.

    Each tier is scaled only within its own realistic size range, so a tier
    that saturates hands the remaining correction to the next one down.
    """
    if not specs:
        return
    tolerance = max(1 * MB, int(total_bytes * 0.002))
    for _ in range(8):
        delta = total_bytes - sum(s.target for s in specs)
        if abs(delta) <= tolerance:
            break
        for tier in ("large", "medium", "small"):
            group = [s for s in specs if s.tier == tier]
            if not group:
                continue
            lo_b, hi_b = TIER_RANGES[tier]
            current = sum(s.target for s in group)
            want = min(len(group) * hi_b, max(len(group) * lo_b, current + delta))
            if current <= 0:
                continue
            factor = want / current
            for s in group:
                s.target = max(lo_b, min(hi_b, int(s.target * factor)))
            delta = total_bytes - sum(s.target for s in specs)
            if abs(delta) <= tolerance:
                break


# --------------------------------------------------------------------------
# Low-level writers -- exact size, genuine low-entropy text
# --------------------------------------------------------------------------

def _pad_line(remaining: int) -> bytes:
    """A filler line of exactly `remaining` bytes (including the newline)."""
    if remaining <= 1:
        return b"\n" * remaining
    body = ("filler " * (remaining // 7 + 2))[: remaining - 1]
    return body.encode("ascii") + b"\n"


def write_txt(path, rng, target):
    """Report/log style text, exactly `target` bytes."""
    mode = rng.choice(["memo", "log"])
    written = 0
    seq = 0
    ts = datetime(2024, 1, 1, 8, 0, 0) + timedelta(minutes=rng.randint(0, 100000))
    with open(path, "wb", buffering=1 << 20) as fh:
        if mode == "memo":
            header = (
                f"{rng.choice(corpus.DEPARTMENTS)} -- internal memorandum\r\n"
                f"Author: {corpus.person(rng)}\r\n"
                f"Reference: {rng.choice(corpus.COST_CENTRES)}\r\n"
                f"{'=' * 60}\r\n\r\n"
            ).encode("ascii", "replace")
            fh.write(header)
            written += len(header)

        # Bulk phase: emit in chunks so we are not doing millions of tiny writes.
        while target - written > 64 * KB:
            buf = []
            size = 0
            while size < 64 * KB:
                if mode == "memo":
                    line = corpus.paragraph(rng) + "\r\n\r\n"
                else:
                    seq += 1
                    ts += timedelta(seconds=rng.randint(1, 30))
                    line = corpus.log_line(rng, seq, ts.isoformat(sep=" ")) + "\r\n"
                buf.append(line)
                size += len(line)
            chunk = "".join(buf).encode("ascii", "replace")
            if written + len(chunk) > target:
                break
            fh.write(chunk)
            written += len(chunk)

        # Tail phase: line at a time until a padding line can land exactly.
        while target - written > 512:
            if mode == "memo":
                line = corpus.paragraph(rng) + "\r\n\r\n"
            else:
                seq += 1
                ts += timedelta(seconds=rng.randint(1, 30))
                line = corpus.log_line(rng, seq, ts.isoformat(sep=" ")) + "\r\n"
            enc = line.encode("ascii", "replace")
            if written + len(enc) > target - 8:
                break
            fh.write(enc)
            written += len(enc)

        fh.write(_pad_line(target - written))


def write_csv(path, rng, target):
    """Tabular export, exactly `target` bytes, valid rows throughout."""
    header = "record_id,booking_date,cost_centre,vendor,description,net_amount,vat_rate,status,owner\r\n"
    written = 0
    rid = rng.randint(100000, 900000)
    day = date(rng.choice([2019, 2020, 2021, 2024, 2025]), 1, 1)

    def make_row():
        nonlocal rid
        rid += 1
        d = day + timedelta(days=rng.randint(0, 364))
        desc = rng.choice(corpus.SUBJECTS).replace(",", "")
        row = (
            f"R{rid},{d.isoformat()},{rng.choice(corpus.COST_CENTRES)},"
            f"\"{rng.choice(corpus.COMPANIES)}\",{desc},"
            f"{rng.randint(50, 250000) / 100:.2f},{rng.choice([0, 7, 19])},"
            f"{rng.choice(corpus.STATUSES)},{corpus.person(rng)}\r\n"
        )
        return row[:190] if len(row) > 190 else row

    with open(path, "wb", buffering=1 << 20) as fh:
        enc = header.encode("ascii", "replace")
        fh.write(enc)
        written += len(enc)

        while target - written > 64 * KB:
            buf = []
            size = 0
            while size < 64 * KB:
                r = make_row()
                buf.append(r)
                size += len(r)
            chunk = "".join(buf).encode("ascii", "replace")
            if written + len(chunk) > target:
                break
            fh.write(chunk)
            written += len(chunk)

        while target - written > 512:
            enc = make_row().encode("ascii", "replace")
            if written + len(enc) > target - 8:
                break
            fh.write(enc)
            written += len(enc)

        # Final row padded in its last field so the CSV stays well-formed.
        remaining = target - written
        if remaining > 0:
            prefix = f"R{rid + 1},{day.isoformat()},{rng.choice(corpus.COST_CENTRES)},\"pad\",note,0.00,0,open,"
            pad = remaining - len(prefix) - 2
            if pad >= 0:
                fh.write((prefix + "x" * pad + "\r\n").encode("ascii"))
            else:
                fh.write(_pad_line(remaining))


# --------------------------------------------------------------------------
# Image helpers -- smooth synthetic graphics, never noise
# --------------------------------------------------------------------------

def _render_image(rng, w, h):
    """Low-frequency gradient plus shapes: compresses like a real photo/diagram.

    All pixel work happens inside Pillow's C code. A tiny seed image is drawn
    and then upscaled bicubically, which yields smooth, genuinely compressible
    content -- per-pixel Python loops here would dominate the whole run.
    """
    from PIL import Image, ImageDraw, ImageFilter

    W, H = max(8, w), max(8, h)

    # 1. Small seed canvas: a few dozen C-speed draw calls, not W*H iterations.
    sw, sh = 64, 64
    seed_img = Image.new("RGB", (sw, sh), (
        rng.randint(30, 200), rng.randint(30, 200), rng.randint(30, 200)))
    sd = ImageDraw.Draw(seed_img)
    c1 = (rng.randint(20, 120), rng.randint(20, 120), rng.randint(60, 180))
    c2 = (rng.randint(120, 240), rng.randint(120, 240), rng.randint(140, 255))
    for y in range(sh):  # only 64 iterations
        t = y / (sh - 1)
        sd.line(
            [(0, y), (sw, y)],
            fill=(int(c1[0] + (c2[0] - c1[0]) * t),
                  int(c1[1] + (c2[1] - c1[1]) * t),
                  int(c1[2] + (c2[2] - c1[2]) * t)),
        )
    for _ in range(rng.randint(6, 14)):
        x0, y0 = rng.randint(0, sw), rng.randint(0, sh)
        x1, y1 = x0 + rng.randint(4, 28), y0 + rng.randint(4, 28)
        fill = (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
        if rng.random() < 0.5:
            sd.ellipse([x0, y0, x1, y1], fill=fill)
        else:
            sd.rectangle([x0, y0, x1, y1], fill=fill)

    # 2. Upscale in C -> smooth low-frequency base.
    base = seed_img.resize((W, H), Image.BICUBIC)

    # 3. Crisp structure on top. Detail density scales with area so that
    #    bytes-per-pixel stays roughly constant -- without this, big images
    #    compress away to nothing and can never reach a multi-MB target.
    d = ImageDraw.Draw(base)
    area = W * H
    n_shapes = max(8, min(3000, area // 12000))
    span = max(12, int((area / max(1, n_shapes)) ** 0.5))
    for _ in range(n_shapes):
        x0, y0 = rng.randint(0, W), rng.randint(0, H)
        x1, y1 = x0 + rng.randint(8, span * 2), y0 + rng.randint(8, span * 2)
        fill = (rng.randint(0, 255), rng.randint(0, 255), rng.randint(0, 255))
        k = rng.random()
        if k < 0.4:
            d.ellipse([x0, y0, x1, y1], fill=fill)
        elif k < 0.8:
            d.rectangle([x0, y0, x1, y1], fill=fill)
        else:
            d.line([x0, y0, x1, y1], fill=fill, width=rng.randint(1, 4))
    # Only lightly smooth small images; smoothing large ones destroys the
    # detail we just added to hit the size target.
    return base.filter(ImageFilter.SMOOTH) if area < 400_000 else base


def _save_image_near(rng, target, fmt):
    """Search image dimensions until the encoded size is close to `target`."""
    from PIL import Image

    aspect = rng.choice([4 / 3, 16 / 9, 3 / 2, 1.0])
    # Bigger targets get higher quality / lower compression, matching how real
    # multi-MB photos and screenshots are actually stored.
    if fmt == "JPEG":
        quality = 92 if target > 2 * MB else rng.choice([78, 84, 88])
        bpp = 0.55 if target > 2 * MB else 0.30
    else:
        # Large PNGs use light compression: fewer pixels are then needed for
        # the same byte target, which is dramatically faster than deflating a
        # huge canvas at level 6.
        quality = 1 if target > 2 * MB else 6
        bpp = 3.0 if target > 2 * MB else 0.9

    px_needed = max(4096, target / bpp)
    w = int((px_needed * aspect) ** 0.5)
    best = None
    for _ in range(5):
        w = max(48, min(w, 14000))
        h = max(48, int(w / aspect))
        img = _render_image(rng, w, h)
        buf = io.BytesIO()
        if fmt == "JPEG":
            img.save(buf, "JPEG", quality=quality, optimize=False)
        else:
            img.save(buf, "PNG", compress_level=quality)
        data = buf.getvalue()
        if best is None or abs(len(data) - target) < abs(len(best) - target):
            best = data
        if 0.85 * target <= len(data) <= 1.15 * target:
            break
        w = int(w * (target / max(1, len(data))) ** 0.5)
    return best


def write_jpg(path, rng, target):
    with open(path, "wb") as fh:
        fh.write(_save_image_near(rng, target, "JPEG"))


def write_png(path, rng, target):
    with open(path, "wb") as fh:
        fh.write(_save_image_near(rng, target, "PNG"))


# --------------------------------------------------------------------------
# Office / PDF writers
# --------------------------------------------------------------------------

# Fixed DOS-format timestamp for every ZIP member. python-docx and openpyxl
# both write each archive entry with the current time in its local header, so
# even byte-identical document content produces differing files run to run.
FIXED_ZIP_DT = (2024, 1, 1, 0, 0, 0)
# W3CDTF datetime, e.g. 2026-07-23T06:08:01Z, as stamped into docProps/core.xml.
_CORE_DT_RE = re.compile(rb"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
_CORE_DT_FIXED = b"2024-01-01T00:00:00Z"


def _normalize_zip(path):
    """Rewrite a docx/xlsx so it is byte-identical for identical content.

    Three sources of run-to-run variance are removed: per-entry ZIP timestamps,
    hash-seed-dependent entry order, and the wall-clock created/modified stamps
    inside docProps/core.xml (openpyxl overwrites `modified` at save time no
    matter what properties are set). The result is still a valid, openable
    Office document -- just reproducible.
    """
    tmp = path + ".det.tmp"
    with zipfile.ZipFile(path, "r") as zin:
        # openpyxl emits parts in a hash-seed-dependent order, so byte-identical
        # content still yields different archives. Write in a canonical order
        # ([Content_Types].xml first, then alphabetical) to remove that variance.
        infos = sorted(zin.infolist(),
                       key=lambda zi: (zi.filename != "[Content_Types].xml", zi.filename))
        with zipfile.ZipFile(tmp, "w") as zout:
            for zi in infos:
                data = zin.read(zi.filename)
                if zi.filename == "docProps/core.xml":
                    data = _CORE_DT_RE.sub(_CORE_DT_FIXED, data)
                nzi = zipfile.ZipInfo(zi.filename, date_time=FIXED_ZIP_DT)
                nzi.compress_type = zi.compress_type
                nzi.external_attr = zi.external_attr
                nzi.internal_attr = zi.internal_attr
                nzi.create_system = 0  # fixed (MS-DOS) rather than host OS
                zout.writestr(nzi, data)
    os.replace(tmp, path)


def write_docx(path, rng, target):
    from docx import Document
    from docx.shared import Inches

    doc = Document()
    # Pin the timestamps python-docx would otherwise set to "now" on save.
    cp = doc.core_properties
    cp.created = FIXED_DT
    cp.modified = FIXED_DT
    cp.last_printed = FIXED_DT
    cp.revision = 1
    doc.add_heading(f"{rng.choice(corpus.DEPARTMENTS)}: {rng.choice(corpus.SUBJECTS).title()}", level=1)
    doc.add_paragraph(f"Prepared by {corpus.person(rng)}")
    doc.add_paragraph(f"Cost centre {rng.choice(corpus.COST_CENTRES)}")

    # Text first. A DOCX is a ZIP and this prose compresses ~4.3:1. Text alone
    # covers files up to ~300 KB; past that, paragraph-object overhead in
    # python-docx dominates, so the remainder comes from embedded images.
    text_target = min(target, 120 * KB)
    chars_needed = int(text_target * 8.0)
    written = 0
    while written < chars_needed:
        # Long multi-paragraph blocks: far fewer XML elements for the same
        # byte count than one short paragraph at a time.
        p = " ".join(corpus.paragraph(rng) for _ in range(4))
        doc.add_paragraph(p)
        written += len(p)
        if rng.random() < 0.05:
            rows = rng.randint(3, 8)
            t = doc.add_table(rows=rows, cols=4)
            for r in range(rows):
                for c in range(4):
                    t.cell(r, c).text = rng.choice(corpus.STATUSES) if c else f"R{rng.randint(1000, 9999)}"
                    written += 8

    # Single pass: compute how many images are needed rather than re-zipping
    # the whole document after every insertion.
    remaining = target - text_target
    if remaining > 40 * KB:
        per_image = min(2 * MB, max(50 * KB, remaining // 4))
        n_images = max(1, min(40, int(remaining / per_image)))
        for _ in range(n_images):
            img = _save_image_near(rng, per_image, "JPEG")
            doc.add_picture(io.BytesIO(img), width=Inches(5.5))
            doc.add_paragraph(corpus.paragraph(rng))
    doc.save(path)
    _normalize_zip(path)


HEADER_XLSX = ["Record", "Date", "Cost centre", "Vendor", "Description",
               "Net", "VAT", "Status", "Owner", "Comment"]

# Compressed bytes per row for the shape below. Measured, not guessed; the
# free-text Comment column is what keeps this high enough that a multi-MB
# sheet needs tens of thousands of rows rather than millions.
XLSX_BYTES_PER_ROW = 67


def _fill_xlsx(ws, rng, rows):
    rid = rng.randint(100000, 900000)
    day = date(2024, 1, 1)
    for i in range(rows):
        rid += 1
        ws.append([
            f"R{rid}",
            (day + timedelta(days=i % 365)).isoformat(),
            rng.choice(corpus.COST_CENTRES),
            rng.choice(corpus.COMPANIES),
            rng.choice(corpus.SUBJECTS),
            rng.randint(50, 250000) / 100,
            rng.choice([0, 7, 19]),
            rng.choice(corpus.STATUSES),
            corpus.person(rng),
            corpus.sentence(rng),
        ])


def _save_xlsx(path, rng, rows):
    """Build, save and normalize one workbook of `rows` ledger rows."""
    from openpyxl import Workbook

    wb = Workbook(write_only=True)
    # Pin the created/modified timestamps openpyxl would set to "now".
    wb.properties.created = FIXED_DT
    wb.properties.modified = FIXED_DT
    ws = wb.create_sheet("Ledger")
    ws.append(HEADER_XLSX)
    _fill_xlsx(ws, rng, rows)
    wb.save(path)
    _normalize_zip(path)


def write_xlsx(path, rng, target):
    rows = max(20, int(target / XLSX_BYTES_PER_ROW))
    _save_xlsx(path, rng, rows)

    # One proportional correction pass if the estimate was well off. The retry
    # decision keys on the now-deterministic file size and rng simply continues,
    # so the same input always takes the same path -- reproducibility holds.
    actual = os.path.getsize(path)
    if actual and not (0.7 * target <= actual <= 1.4 * target):
        rows = max(20, int(rows * target / actual))
        _save_xlsx(path, rng, rows)


def write_pdf(path, rng, target):
    # invariant mode replaces reportlab's wall-clock /CreationDate and random
    # document ID with fixed values, so identical input yields identical bytes.
    import reportlab.rl_config
    reportlab.rl_config.invariant = 1
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    W, H = A4
    c = canvas.Canvas(path, pagesize=A4)
    title = f"{rng.choice(corpus.DEPARTMENTS)} -- {rng.choice(corpus.SUBJECTS).title()}"

    def text_page(n):
        c.setFont("Helvetica-Bold", 14)
        c.drawString(56, H - 56, title)
        c.setFont("Helvetica", 9)
        y = H - 84
        while y > 56:
            line = corpus.sentence(rng)[:110]
            c.drawString(56, y, line)
            y -= 12
        c.setFont("Helvetica", 8)
        c.drawString(56, 36, f"Page {n} - {rng.choice(corpus.COST_CENTRES)}")
        c.showPage()

    # PDF text streams are low entropy and run ~2.2 KB per page. Text alone
    # carries files up to ~500 KB; beyond that we add scanned-style image
    # pages, which is how large PDFs get large in practice.
    text_target = min(target, 500 * KB)
    pages = max(1, min(240, int(text_target / 2400)))
    for i in range(1, pages + 1):
        text_page(i)

    remaining = target - pages * 2400
    if remaining > 100 * KB:
        # Fixed per-image budget => page count is arithmetic, not trial-and-error.
        per_image = min(1500 * KB, max(120 * KB, remaining // 6))
        n_images = max(1, min(64, int(remaining / per_image)))
        # 0.82 corrects for reportlab's own image-stream overhead, which
        # otherwise pushes finished PDFs ~25% past target.
        for _ in range(n_images):
            img_bytes = _save_image_near(rng, int(per_image * 0.82), "JPEG")
            c.drawImage(ImageReader(io.BytesIO(img_bytes)), 56, 120,
                        width=W - 112, height=H - 240, preserveAspectRatio=True)
            c.showPage()
    c.save()


WRITERS = {
    "txt": write_txt,
    "csv": write_csv,
    "jpg": write_jpg,
    "png": write_png,
    "docx": write_docx,
    "xlsx": write_xlsx,
    "pdf": write_pdf,
}


# --------------------------------------------------------------------------
# Worker
# --------------------------------------------------------------------------

def sha256_file(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def generate_one(args):
    """Runs in a worker process. Returns a manifest entry."""
    root, seed, spec_dict = args
    spec = FileSpec(**spec_dict)
    path = os.path.join(root, spec.relpath.replace("/", os.sep))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rng = derive_rng(seed, spec.relpath)
    try:
        WRITERS[spec.ftype](path, rng, spec.target)
    except Exception as exc:  # keep one bad file from killing an 8 GB run
        return {"relpath": spec.relpath, "error": f"{type(exc).__name__}: {exc}"}
    size = os.path.getsize(path)
    return {
        "relpath": spec.relpath,
        "type": spec.ftype,
        "tier": spec.tier,
        "size": size,
        "sha256": sha256_file(path),
    }


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def human(n):
    """Format a byte count as a readable size, e.g. 1536 -> '1.5 KB'."""
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(n) < 1024 or unit == "TB":
            return f"{n:,.1f} {unit}" if unit != "B" else f"{n:,.0f} B"
        n /= 1024


def main():
    """Parse arguments, plan the dataset, generate every file in parallel,
    then write the SHA-256 manifest. See the module docstring for the flow."""
    ap = argparse.ArgumentParser(description="Generate a ransomware-test dataset.")
    ap.add_argument("--out", required=True, help="output directory (created if absent)")
    ap.add_argument("--size-gb", type=float, default=8.0, help="target total size in GB")
    ap.add_argument("--files", type=int, default=8000, help="target file count")
    ap.add_argument("--seed", type=int, default=20260720, help="RNG seed")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 4) - 1))
    ap.add_argument("--dry-run", action="store_true", help="print the plan, write nothing")
    ap.add_argument("--resume", action="store_true",
                    help="continue an interrupted run, skipping already-completed files")
    args = ap.parse_args()

    total_bytes = int(args.size_gb * GB)
    specs = build_plan(args.seed, args.files, total_bytes)

    tiers = {}
    for s in specs:
        t = tiers.setdefault(s.tier, [0, 0])
        t[0] += 1
        t[1] += s.target

    print(f"Plan: {len(specs):,} files, planned total {human(sum(s.target for s in specs))} "
          f"(target {human(total_bytes)}), seed {args.seed}")
    for tier in ("small", "medium", "large"):
        if tier in tiers:
            n, b = tiers[tier]
            print(f"  {tier:<7} {n:>6,} files  {human(b):>12}")
    types = {}
    for s in specs:
        types[s.ftype] = types.get(s.ftype, 0) + 1
    print("  types: " + ", ".join(f"{k}={v}" for k, v in sorted(types.items())))

    if args.dry_run:
        print("\n(dry run -- nothing written)")
        for s in specs[:15]:
            print(f"    {s.relpath}  [{s.tier}, {human(s.target)}]")
        return

    root = os.path.abspath(args.out)
    os.makedirs(root, exist_ok=True)
    checkpoint_path = os.path.join(root, CHECKPOINT)

    # Resume: replay the checkpoint so completed files are skipped. An entry is
    # only trusted if its file is still on disk (last write wins if duplicated).
    entries = []
    done_relpaths = set()
    if args.resume and os.path.isfile(checkpoint_path):
        by_rel = {}
        with open(checkpoint_path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue  # a half-written final line after a hard kill
                full = os.path.join(root, e["relpath"].replace("/", os.sep))
                if os.path.exists(full):
                    by_rel[e["relpath"]] = e
        entries = list(by_rel.values())
        done_relpaths = set(by_rel)
        print(f"Resuming: {len(done_relpaths):,} files already done "
              f"({human(sum(e['size'] for e in entries))}), "
              f"{len(specs) - len(done_relpaths):,} to go.")
    elif not args.resume and os.path.isfile(checkpoint_path):
        os.remove(checkpoint_path)  # stale checkpoint from an old run

    # Phase 1 = container formats, whose final size is only approximate.
    # Phase 2 = txt/csv, which are byte-exact and therefore absorb the drift
    # so the finished dataset lands on --size-gb.
    approx = [s for s in specs if s.ftype not in EXACT_TYPES and s.relpath not in done_relpaths]
    exact = [s for s in specs if s.ftype in EXACT_TYPES and s.relpath not in done_relpaths]

    errors = []
    t0 = time.time()
    # Single-writer append log; flushed per file so an abrupt kill loses at most
    # the one file in flight, which is simply regenerated on the next --resume.
    ckpt = open(checkpoint_path, "a", encoding="utf-8", buffering=1)

    def run_batch(batch, label):
        done = 0
        payload = [(root, args.seed, asdict(s)) for s in batch]
        with ProcessPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(generate_one, p) for p in payload]
            for fut in as_completed(futures):
                res = fut.result()
                if "error" in res:
                    errors.append(res)
                else:
                    entries.append(res)
                    ckpt.write(json.dumps(res) + "\n")
                    ckpt.flush()
                done += 1
                if done % 50 == 0 or done == len(batch):
                    got = sum(e["size"] for e in entries)
                    print(f"\r  {label}: {done:,}/{len(batch):,} files, "
                          f"{human(got)} total, {time.time() - t0:,.0f}s", end="", flush=True)
        print()

    print(f"\nWriting to {root}")
    if approx:
        run_batch(approx, "docx/xlsx/pdf/img")

    if exact:
        # Re-target txt/csv from measured phase-1 sizes so the finished total
        # lands on --size-gb despite the container formats being approximate.
        so_far = sum(e["size"] for e in entries)
        want = max(0, total_bytes - so_far)
        planned = sum(s.target for s in exact)
        if planned > 0 and want > 0:
            factor = want / planned
            for s in exact:
                lo, hi = TIER_RANGES[s.tier]
                s.target = max(4 * KB, min(hi, int(s.target * factor)))
            drift = want - sum(s.target for s in exact)
            biggest = max(exact, key=lambda s: s.target)
            biggest.target = max(4 * KB, biggest.target + drift)
        run_batch(exact, "txt/csv")

    ckpt.close()
    # De-dup in case a --resume regenerated a file that was already logged.
    entries = list({e["relpath"]: e for e in entries}.values())
    entries.sort(key=lambda e: e["relpath"])
    total = sum(e["size"] for e in entries)

    manifest = {
        "generator": "generate_dataset.py",
        "generated_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "seed": args.seed,
        "requested_size_bytes": total_bytes,
        "requested_files": args.files,
        "actual_size_bytes": total,
        "actual_files": len(entries),
        "root_name": os.path.basename(root),
        "files": entries,
    }
    with open(os.path.join(root, MANIFEST_JSON), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1)
    with open(os.path.join(root, MANIFEST_CSV), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["relpath", "size", "sha256", "type", "tier"])
        for e in entries:
            w.writerow([e["relpath"], e["size"], e["sha256"], e["type"], e["tier"]])

    # Manifests are complete, so the checkpoint has served its purpose.
    try:
        os.remove(checkpoint_path)
    except OSError:
        pass

    print(f"\nDone in {time.time() - t0:,.0f}s")
    print(f"  files : {len(entries):,}")
    print(f"  size  : {human(total)}  (target {human(total_bytes)}, "
          f"delta {human(total - total_bytes)})")
    print(f"  manifest: {os.path.join(root, MANIFEST_JSON)}")
    print(f"            {os.path.join(root, MANIFEST_CSV)}")
    if errors:
        print(f"\n  {len(errors)} file(s) failed:")
        for e in errors[:10]:
            print(f"    {e['relpath']}: {e['error']}")


if __name__ == "__main__":
    main()
