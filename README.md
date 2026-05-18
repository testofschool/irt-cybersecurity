# IRT+LLTM+PCR for Cybersecurity Vulnerability Analysis

**Paper:** *Item Response Theory Reveals Latent Structure in the Cybersecurity Vulnerability Landscape: A Cross-Validated Analysis of 55,020 CVEs*

**Author:** Jung Min Kang (ORCID: 0009-0007-9599-2792)

## Overview

A vendor × CWE application of psychometric methods (IRT, LLTM-inspired decomposition, PCR) to cybersecurity vulnerability data using 7 real data sources and cross-validated against 3 independent exploitation-signal datasets.

## Key Findings

1. **CWE difficulty is temporally stable** (ρ = 0.889, 95% CI [0.836, 0.927])
2. **Common CWEs are more exploited** (b ↔ KEV: ρ = −0.224; b ↔ ExploitDB: ρ = −0.362)
3. **Ransomware targets low-difficulty CWEs** (Mann-Whitney p < 10⁻⁹)
4. **CVSS explains only 12–21% of CWE difficulty** — structural incompleteness identified
5. **PCR achieves up to 2.3× lift** for mid-range vendors

## Reproduction

> **Note:** This repository does not bundle large NVD, EPSS, ExploitDB, or ATT&CK files.
> Run `bash scripts/download_data.sh` before `python src/experiment.py`.
> For exact offline reproduction, use the Zenodo snapshot once available.

### Exact reproduction (Zenodo)
Use the Zenodo archive (DOI pending). Includes all large data snapshots.

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
