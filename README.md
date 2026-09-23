# Ransomware-Resilience Lab, IT Project

Tools and lab setup for the IT project *"Comparative Analysis of Ransomware Resilience in File-Server Protection Solutions"* (Hochschule Stralsund).

The idea in one line: build a realistic file share, take a **manifest** (a SHA-256 fingerprint of every file) before the attack, let a simulated ransomware attack run, then compare against the manifest to measure exactly which files were damaged and how well the backup restored them.

---

## Repository layout

| Path | What it is |
| --- | --- |
| `generate_dataset.py` | Builds the test dataset and writes the manifest. |
| `verify_dataset.py` | Compares a folder to the manifest (unchanged / modified / missing / new). The measurement tool. |
| `monitor_attack.py` | Watches the folder during an attack and records the timeline. |
| `simulate_attack.py` | Applies a *known* amount of damage to a copy, to check the verifier reports correct numbers. |
| `corpus.py` | Word/text templates used to fill the files with realistic content. Not run directly. |
| `scripts/Vagrantfile` | Builds the three-VM lab (Windows file server, Kali attacker, Ubuntu Veeam repo). |
| `scripts/encrypt.ps1`, `slow_encrypt.ps1` | Windows attack: fast / slow GPG encryption (T1486). |
| `scripts/encrypt.sh`, `encrypt_slow.sh` | Same attack over the SMB share (Linux). |
| `scripts/kali_monitor.sh` | Lightweight monitor run on the Kali VM for the NAS tests. |

---

## Requirements

- Python 3.10+
- `pip install python-docx openpyxl reportlab Pillow`
- VirtualBox + Vagrant (for the lab)

---

## Step-by-step

### 1. Build the lab
```
cd scripts
vagrant up
```
Brings up the three VMs. Fixed IPs: file server `.10`, attacker `.20`, Veeam repo `.30` on the isolated `192.168.56.0/24` network. Installing the tested solutions and loading the dataset are done as separate steps.

### 2. Generate the dataset
Small test set first (100 MB):
```
python generate_dataset.py --out <path>\testset --size-gb 0.1 --files 300
```
Full set (8 GB):
```
python generate_dataset.py --out <path>\dataset --size-gb 8 --files 8000
```
Copy the resulting `_manifest.json` somewhere **off the share**, so the attack can't encrypt your ground truth.

### 3. Run and measure an attack
Start the monitor first, then run the attack in a second terminal:
```
python monitor_attack.py --root <path>\dataset --idle-stop 10
```
Attack scripts are in `scripts/` (or use `simulate_attack.py` for a safe dry run).

### 4. Check the result
```
python verify_dataset.py --root <path>\dataset --manifest <safe copy>\_manifest.json
```
Reports how many files are unchanged, modified, missing or new, plus an intact-%. `verify` answers *what* changed; `monitor` answers *when* and *how fast*.

---

## Key points

- **Manifest** = the before snapshot (every file + SHA-256). All measurement compares against it.
- **Fixed seed** (`--seed`, default `20260720`): the same seed rebuilds the exact same dataset, so the experiment is reproducible.
- **No random bytes**: files use real text/images, so they start at low entropy. If they were random they'd already look encrypted and break entropy checks.
- Keep the manifest and logs **outside** the folder under attack.

---

## Flag reference

### `generate_dataset.py`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--out` | *(required)* | Output folder (created if absent). |
| `--size-gb` | `8.0` | Target total size in GB. Accepts decimals (`0.1` = 100 MB). |
| `--files` | `8000` | Target number of files. |
| `--seed` | `20260720` | Random seed. Same seed = identical dataset. |
| `--workers` | CPU count − 1 | Parallel worker processes. |
| `--dry-run` | off | Print the plan and write nothing. |
| `--resume` | off | Continue an interrupted run instead of restarting. |

### `verify_dataset.py`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--root` | *(required)* | Folder to verify. |
| `--manifest` | `<root>/_manifest.json` | Manifest to compare against. Point at a copy kept off the share. |
| `--report` | — | Write a full JSON report of every affected file. |
| `--entropy` | off | Also print the entropy-by-type table. |
| `--list N` | `20` | How many affected files to print per category (`0` = all). |
| `--workers` | CPU count − 1 | Parallel worker processes. |

Exit codes: `0` = pristine, `1` = differences found, `2` = error.

### `simulate_attack.py`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--root` | *(required)* | The **copy** to damage. Refuses to run without a manifest inside. |
| `--encrypt N` | `40` | Overwrite N files with high-entropy bytes (become "modified"). |
| `--delete N` | `10` | Remove N files (become "missing"). |
| `--notes N` | `1` | Drop N ransom notes (become "new"). |
| `--seed` | `1337` | Which files get hit (reproducible). |
| `--ledger` | — | Write the exact list of what was damaged (JSON ground truth). |

Never touches the manifest, that stays as the clean baseline.

### `monitor_attack.py`

| Flag | Default | Meaning |
| --- | --- | --- |
| `--root` | *(required)* | Folder to watch. |
| `--manifest` | `<root>/_manifest.json` | Baseline for the final SHA-256 comparison. |
| `--interval N` | `0.5` | Poll every N seconds (timing resolution). |
| `--idle-stop N` | off | Stop once no change seen for N seconds. |
| `--duration N` | off | Hard time limit in seconds. |
| `--bucket N` | `1.0` | Timeline bucket width in seconds. |
| `--out-dir` | `.` | Where to write the log files (keep out of `--root`). |
| `--no-verify` | off | Skip the final SHA-256 comparison (timing only). |

Writes `events_<ts>.csv`, `timeline_<ts>.csv`, `summary_<ts>.json`. Exit codes: `0` = no changes, `1` = changes detected, `2` = error.
