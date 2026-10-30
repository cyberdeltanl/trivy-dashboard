#!/usr/bin/env bash
# Packs the plugin archive that plugin.yaml points at. Run after editing any of the files below.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
tar czf htmlreport.tar.gz --owner=0 --group=0 --numeric-owner plugin.yaml htmlreport.sh trivy-report-cli.mjs trivy-report.html LICENSE
echo "wrote htmlreport.tar.gz"
