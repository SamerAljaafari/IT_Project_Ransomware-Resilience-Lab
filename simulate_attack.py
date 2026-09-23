"""Simulated-ransomware damage generator for testing verify_dataset.py.

Applies a KNOWN amount of damage to a copy of a dataset so the verifier's
modified / missing / new counts can be checked against ground truth. This does
NOT touch the manifest -- that is the whole point: the manifest is the pre-attack
baseline, the disk is the post-attack state.

    encrypt : overwrite file contents in place (AES-CTR-style high entropy),
              keeping the same path -> verifier should report "modified"
    delete  : remove the file entirely            -> "missing"
    note    : drop a ransom note                  -> "new"

Usage:
    python simulate_attack.py --root <copy> --encrypt 40 --delete 10 --notes 1
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys

MANIFEST_NAMES = {"_manifest.json", "_manifest.csv"}
RANSOM_NOTE = (
    "!!! YOUR FILES HAVE BEEN ENCRYPTED !!!\r\n\r\n"
    "This is a SIMULATED ransom note created by simulate_attack.py for a\r\n"
    "university ransomware-resilience experiment. No real malware was used.\r\n"
    "To restore, run verify_dataset.py against the baseline manifest, then\r\n"
    "restore the affected files from backup.\r\n"
)


def list_targets(root):
    files = []
    for dirpath, _dirs, names in os.walk(root):
        for n in names:
            if n in MANIFEST_NAMES:
                continue
            files.append(os.path.join(dirpath, n))
    return files


def encrypt_in_place(path, rng):
    """Overwrite with high-entropy bytes -- stand-in for real encryption.

    Kept the same length here only for tidiness; the verifier keys on the
    SHA-256, so content change alone is what flags it as modified.
    """
    size = os.path.getsize(path)
    with open(path, "wb") as fh:
        fh.write(rng.randbytes(size))


def main():
    ap = argparse.ArgumentParser(description="Apply known damage to a dataset copy.")
    ap.add_argument("--root", required=True, help="dataset copy to damage (NOT the original)")
    ap.add_argument("--encrypt", type=int, default=40, help="files to overwrite -> modified")
    ap.add_argument("--delete", type=int, default=10, help="files to remove -> missing")
    ap.add_argument("--notes", type=int, default=1, help="ransom notes to drop -> new")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--ledger", help="write the ground-truth damage list here (JSON)")
    args = ap.parse_args()

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"error: no such directory: {root}", file=sys.stderr)
        return 2
    if not os.path.isfile(os.path.join(root, "_manifest.json")):
        print("error: no _manifest.json in root -- refusing to damage a "
              "directory that has no baseline.", file=sys.stderr)
        return 2

    rng = random.Random(args.seed)
    targets = list_targets(root)
    rng.shuffle(targets)

    need = args.encrypt + args.delete
    if need > len(targets):
        print(f"error: asked to touch {need} files but only {len(targets)} exist.",
              file=sys.stderr)
        return 2

    to_encrypt = targets[:args.encrypt]
    to_delete = targets[args.encrypt:args.encrypt + args.delete]

    def rel(p):
        return os.path.relpath(p, root).replace(os.sep, "/")

    ledger = {"encrypted": [], "deleted": [], "notes": []}

    for p in to_encrypt:
        encrypt_in_place(p, rng)
        ledger["encrypted"].append(rel(p))

    for p in to_delete:
        os.remove(p)
        ledger["deleted"].append(rel(p))

    # Ransom notes land in random existing folders, as real families do.
    dirs = list({os.path.dirname(p) for p in targets})
    for i in range(args.notes):
        d = rng.choice(dirs)
        note_path = os.path.join(d, f"_RESTORE_YOUR_FILES_{i:02d}.txt")
        with open(note_path, "w", encoding="utf-8") as fh:
            fh.write(RANSOM_NOTE)
        ledger["notes"].append(rel(note_path))

    print(f"damage applied to {root}")
    print(f"  encrypted (->modified): {len(ledger['encrypted'])}")
    print(f"  deleted   (->missing) : {len(ledger['deleted'])}")
    print(f"  notes     (->new)     : {len(ledger['notes'])}")

    if args.ledger:
        with open(args.ledger, "w", encoding="utf-8") as fh:
            json.dump(ledger, fh, indent=1)
        print(f"  ground-truth ledger: {args.ledger}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
