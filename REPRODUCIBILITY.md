# Reproducibility Guide

## Quick start

**Python 3.11–3.14 required** for exact reproduction with `requirements-lock.txt`.
For older Python, use `requirements.txt` (exact numerical reproduction not guaranteed).

```bash
bash scripts/download_data.sh        # Strict mode (default): fails on hash mismatch
python src/experiment.py              # Writes outputs/results.json
python src/gen_figures.py             # Regenerates figures/
pdflatex main.tex && pdflatex main.tex
```

## Download modes

The download script defaults to **strict mode** (`STRICT=1`), which enforces SHA256 hash validation against the manuscript snapshot (2026-05-17). Any mismatch causes the script to abort.

```bash
# Strict (default) — exact reproduction
bash scripts/download_data.sh

# Live mode — downloads latest versions, warns on drift
STRICT=0 bash scripts/download_data.sh
```

## Pinned data sources

| Source | Pinning method |
|--------|---------------|
| NVD 2023/2024 | fkie-cad release tag `v2026.05.17-000006` (assets no longer downloadable; see below) |
| CISA KEV | SHA256 hash-enforced (live feed, v2026.05.15) |
| EPSS | Dated snapshot `epss_scores-2026-05-17.csv.gz` |
| ExploitDB | GitLab commit `11e5b5e5015c` + SHA256 hash |
| CWE | SHA256 hash-enforced (current CSV zip) |
| MITRE ATT&CK | Pinned release tag `v19.0` |

## Pinned NVD release no longer downloadable

As of 2026-09-26, the pinned NVD release assets return HTTP 404:

```
$ curl -s -o /dev/null -w '%{http_code}' -L https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/v2026.05.17-000006/CVE-2024.json.xz
404
$ curl -s -o /dev/null -w '%{http_code}' -L https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/v2026.05.17-000006/CVE-2023.json.xz
404
```

`scripts/download_data.sh` therefore stops at step 1 with an error message. The exact NVD inputs (`CVE-2023.json`, `CVE-2024.json`; SHA256 in `data_manifest.json`) are not in this repository or in the Zenodo deposit (10.5281/zenodo.20270362), so strict reproduction of the NVD-derived results is not currently possible from the pinned sources. Manuscript statistics can still be checked against `outputs/results.json`.

## Stochasticity note

IRT uses stochastic SGD. Regenerated values may differ by ±0.01–0.02 across runs (within bootstrap CIs reported in the paper). Key values to check:

```
matrix.vendors:                    333
matrix.cwes:                       169
temporal.rho_b:                    ~0.889 (±0.02)
cross_validation.b_kev_rho:        ~-0.224 (±0.03)
cross_validation.b_exploitdb_rho:  ~-0.362 (±0.03)
ransomware.mann_whitney_p:         <1e-9
```

## File manifest

See `data_manifest.json` for SHA256 checksums of all data files.
See `outputs/results.json` for all statistical values from the manuscript run.

## Archival deposit

> **DOI:** [10.5281/zenodo.20270362](https://doi.org/10.5281/zenodo.20270362)

The Zenodo deposit contains the manuscript PDF, source code, figures, and `outputs/results.json` (a snapshot of this repository, including `data/snapshots/`). It does not contain the NVD, EPSS, ExploitDB, or ATT&CK data files. The exact KEV and CWE snapshots are bundled in `data/snapshots/`. Other data files (except NVD; see above) can be retrieved using the pinned URLs and SHA256 hashes in `data_manifest.json`.

## If strict download fails

If an upstream live source has changed since the manuscript snapshot, the strict-mode script will abort with a hash mismatch. Options:

1. **Use `STRICT=0`** to download current versions (results may differ slightly).
2. **Use the archived KEV and CWE snapshots** in `data/snapshots/` (also in the Zenodo deposit); the script falls back to them automatically when the live KEV/CWE files change. The Zenodo deposit has no archived copies of the other sources.
3. **Pin ExploitDB to the commit** listed in `data_manifest.json` (`11e5b5e5015c`). No commit SHA is recorded for the KEV GitHub mirror; use the bundled `data/snapshots/kev_2026-05-15.json` instead.

All SHA256 checksums for the manuscript snapshot are recorded in `data_manifest.json`.
