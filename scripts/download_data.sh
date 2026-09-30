#!/bin/bash
# IRT Cybersecurity — Data Download (strict reproducibility mode)
# Snapshot: 2026-05-17 | SHA256 enforced | Fails on mismatch
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$SCRIPT_DIR"
mkdir -p data
cd data
SNAPSHOTS="$SCRIPT_DIR/data/snapshots"

declare -A EXPECTED
EXPECTED[CVE-2023.json]="5d3ca098c4409f266162abc704db8e7b944a94a9bf1ead7ada1dcd8d5e5eb3e1"
EXPECTED[CVE-2024.json]="9d353b6037f6b2b38a1c7624d33b84fbe3556ed2b20e60297e97e41421caf0c9"
EXPECTED[kev.json]="eee489c38ef15f84f1c7620aa6c671f8e4539053fee150f3cfab9931bdd92e2b"
EXPECTED[epss_current.csv]="04575fd5453ee31b1cf6d5479eee16fab319ed45332f06323ce4546192760b44"
EXPECTED[exploitdb.csv]="0384ee2f62f0e8e6a2f09427ee2cb7c23e9f25ff1d0cc7b736cd81fadaeb2a37"
EXPECTED[attack-enterprise.json]="df520ea0775a57db7bff760145b02fed89290802913e056b7ed5970b02f3626a"
EXPECTED[cwe_data.zip]="6a3d52a7d164d98eb24ca3228039dcd98461379d225dfd395474c0d007537791"

declare -A BUNDLED
BUNDLED[kev.json]="kev_2026-05-15.json"
BUNDLED[cwe_data.zip]="cwe_v4.16.zip"

STRICT=${STRICT:-1}
WARN=0

verify() {
    local f=$1
    [ ! -f "$f" ] && echo "  MISSING: $f" && exit 1
    local actual=$(sha256sum "$f" | cut -d' ' -f1)
    if [ "$actual" = "${EXPECTED[$f]}" ]; then
        echo "  OK: $f"
        return 0
    fi
    local bundled="${BUNDLED[$f]}"
    if [ -n "$bundled" ] && [ -f "$SNAPSHOTS/$bundled" ]; then
        echo "  CHANGED: $f (live source updated since 2026-05-17)"
        echo "  Using bundled snapshot: $bundled"
        cp "$SNAPSHOTS/$bundled" "$f"
        local retry=$(sha256sum "$f" | cut -d' ' -f1)
        if [ "$retry" = "${EXPECTED[$f]}" ]; then
            echo "  OK: $f (restored from bundled snapshot)"
            return 0
        fi
    fi
    echo "  HASH MISMATCH: $f"
    echo "    expected: ${EXPECTED[$f]}"
    echo "    actual:   $actual"
    if [ "$STRICT" = "1" ]; then
        echo "  STRICT mode: aborting."
        exit 1
    else
        echo "  WARNING: results may differ from manuscript."
        WARN=1
    fi
}

# Pinned NVD release. Its assets return HTTP 404 (checked 2026-09-26); see
# REPRODUCIBILITY.md, "Pinned NVD release no longer downloadable".
NVD_TAG="v2026.05.17-000006"
ZENODO_DOI="10.5281/zenodo.20270362"

fetch_nvd() {
    local year=$1
    local url="https://github.com/fkie-cad/nvd-json-data-feeds/releases/download/${NVD_TAG}/CVE-${year}.json.xz"
    if ! curl -sfL "$url" -o "CVE-${year}.json.xz"; then
        rm -f "CVE-${year}.json.xz"
        echo ""
        echo "  ERROR: could not download CVE-${year}.json.xz from the pinned NVD release ${NVD_TAG}."
        echo "  The pinned fkie-cad/nvd-json-data-feeds release assets are no longer downloadable"
        echo "  (HTTP 404 when checked on 2026-09-26), so the NVD inputs cannot be fetched by this script."
        echo "  Archived copy of this study: Zenodo https://doi.org/${ZENODO_DOI}"
        echo "    It contains the manuscript PDF, source code, figures, outputs/results.json and the"
        echo "    bundled KEV/CWE snapshots. It does NOT contain the NVD CVE-2023/CVE-2024 files."
        echo "  To check manuscript statistics without NVD data, use outputs/results.json."
        echo "  See REPRODUCIBILITY.md, section 'Pinned NVD release no longer downloadable'."
        exit 1
    fi
    xz -d -k -f "CVE-${year}.json.xz"
}

echo "=== IRT Cybersecurity — Data Download ==="
echo "Snapshot: 2026-05-17 | Mode: $([ "$STRICT" = "1" ] && echo STRICT || echo LIVE)"
echo ""

echo "[1/7] NVD 2024 (pinned ${NVD_TAG})..."
fetch_nvd 2024

echo "[2/7] NVD 2023 (pinned ${NVD_TAG})..."
fetch_nvd 2023

echo "[3/7] CISA KEV (live; auto-fallback to bundled snapshot)..."
curl -sfL "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -o kev.json

echo "[4/7] EPSS (dated snapshot 2026-05-17)..."
curl -sfL "https://epss.empiricalsecurity.com/epss_scores-2026-05-17.csv.gz" -o epss_current.csv.gz
gunzip -f epss_current.csv.gz

echo "[5/7] ExploitDB (pinned commit 11e5b5e5015c)..."
curl -sfL "https://gitlab.com/exploit-database/exploitdb/-/raw/11e5b5e5015c/files_exploits.csv" -o exploitdb.csv

echo "[6/7] CWE (live; auto-fallback to bundled snapshot)..."
curl -sfL "https://cwe.mitre.org/data/csv/1000.csv.zip" -o cwe_data.zip

echo "[7/7] MITRE ATT&CK v19.0 (pinned release tag)..."
curl -sfL "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/refs/tags/v19.0/enterprise-attack/enterprise-attack-19.0.json" -o attack-enterprise.json

echo ""
echo "=== SHA256 Verification ==="
for f in CVE-2023.json CVE-2024.json kev.json epss_current.csv exploitdb.csv attack-enterprise.json cwe_data.zip; do
    verify "$f"
done

# Extract the CWE archive only after it has passed (or, with STRICT=0, been
# warned by) SHA256 verification.
echo ""
echo "=== Extracting CWE archive ==="
unzip -oq cwe_data.zip -d cwe_extracted
echo "  OK: cwe_data.zip -> cwe_extracted/"

echo ""
if [ $WARN -ne 0 ]; then
    echo "WARNING: Some files differ from manuscript snapshot."
else
    echo "All files match manuscript snapshot."
fi
echo ""
echo "Run: python src/experiment.py"
