# IRT+LLTM+PCR for Cybersecurity Vulnerability Analysis

**Paper:** *Item Response Theory Reveals Latent Structure in the Cybersecurity Vulnerability Landscape: A Cross-Validated Analysis of 55,020 CVEs*

**Author:** Jung Min Kang (ORCID: 0009-0007-9599-2792)

## Overview

A vendor × CWE application of psychometric methods (IRT, LLTM-inspired decomposition, PCR) to cybersecurity vulnerability data using 7 real data sources and cross-validated against 3 independent exploitation-signal datasets.

## Key Findings

1. **CWE difficulty is temporally stable** (ρ = 0.889, 95% CI [0.836, 0.927])
2. **Common CWEs are more exploited** (b ↔ KEV: ρ = −0.224; b ↔ ExploitDB: ρ = −0.362)
3. **Ransomware targets low-difficulty CWEs** (Mann-Whitney p < 10⁻⁹)
4. **CVSS-only features explain 12% of CWE difficulty variance (in-sample R²); CVSS + CWE hierarchy explain 21%** — structural incompleteness identified
5. **PCR achieves up to 2.3× lift** among the top-5-θ vendors (below random, 0.78×, for the highest-θ vendor)

## Reproduction

> **Note:** This repository does not bundle large NVD, EPSS, ExploitDB, or ATT&CK files.
> Run `bash scripts/download_data.sh` before `python src/experiment.py`.

> **Known issue — NVD inputs not downloadable:** the pinned NVD release assets
> (`fkie-cad/nvd-json-data-feeds`, tag `v2026.05.17-000006`) return HTTP 404 (checked 2026-09-26),
> so `scripts/download_data.sh` stops at step 1 with an error. The NVD files are not in the
> Zenodo archive either. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md#pinned-nvd-release-no-longer-downloadable).

### Archived snapshot (Zenodo)
DOI: [10.5281/zenodo.20270362](https://doi.org/10.5281/zenodo.20270362). The deposit contains the manuscript PDF, source code, figures, and `outputs/results.json` (plus the KEV and CWE snapshots bundled in `data/snapshots/`). It does **not** include the large NVD, EPSS, ExploitDB, or ATT&CK data files; retrieve those via the pinned URLs and SHA256 hashes in `data_manifest.json`.

### Scripted reproduction
```bash
# 1. Download data (SHA256-verified)
bash scripts/download_data.sh

# 2. Run experiment
python src/experiment.py

# 3. Generate figures
python src/gen_figures.py

# 4. Compile paper
pdflatex main.tex && pdflatex main.tex
```

### Lightweight verification
Use `outputs/results.json` to verify manuscript statistics without rerunning the full pipeline.
Note: the committed `outputs/results.json` does not use the exact schema that `src/experiment.py` writes (e.g. `snapshot_date` vs. `run_date`/`data_snapshot_date`, `pcr.note`, and the `ransomware.mann_whitney_p` format), and some manuscript statistics are not included in it (e.g. the vendor-level θ ↔ KEV p-value and the KEV/EPSS/ExploitDB inter-correlations).

## Requirements

- Python 3.11+ (3.11–3.14 recommended for exact reproduction with requirements-lock.txt) with numpy, scipy, matplotlib
- LaTeX (texlive-latex-extra, texlive-science)
- curl, xz-utils, unzip (for data download)

## Data Sources

| Source | Records | URL |
|--------|---------|-----|
| NVD CVE 2023 | 26,733 | github.com/fkie-cad/nvd-json-data-feeds |
| NVD CVE 2024 | 28,287 | github.com/fkie-cad/nvd-json-data-feeds |
| CISA KEV | 1,592 | github.com/cisagov/kev-data |
| FIRST EPSS | 333,778 | first.org/epss/api |
| ExploitDB | 25,001 | gitlab.com/exploit-database/exploitdb |
| CWE Hierarchy | 944 | cwe.mitre.org/data/csv (bundled snapshot: v4.16) |
| MITRE ATT&CK | 697 (222 techniques + 475 sub-techniques) | github.com/mitre-attack/attack-stix-data |

## Citation

```bibtex
@article{kang2026irt_cybersecurity,
  title={Item Response Theory Reveals Latent Structure in the Cybersecurity Vulnerability Landscape: A Cross-Validated Analysis of 55,020 CVEs},
  author={Kang, Jung Min},
  year={2026},
  note={Preprint}
}
```

## License

MIT License
