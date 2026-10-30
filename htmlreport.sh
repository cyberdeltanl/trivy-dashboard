#!/usr/bin/env bash
# Trivy plugin "htmlreport": interactive, self-contained HTML reports from Trivy results.
#
#   Scan and report in one go (Trivy flags first, report flags after --report-flags):
#     trivy htmlreport k8s --report summary --report-flags -o cluster.html --title "Cluster" --enrich
#     trivy htmlreport image nginx:1.29 --report-flags -o nginx.html
#
#   Report from existing JSON / SBOM files:
#     trivy htmlreport generate -o report.html --enrich scan1.json sbom.cdx.json
#
#   As an output plugin (Trivy pipes its JSON in):
#     trivy image -f json --output plugin=htmlreport --output-plugin-arg "-o nginx.html" nginx:1.29
set -euo pipefail

dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
cli="$dir/trivy-report-cli.mjs"
command -v node >/dev/null 2>&1 || { echo "htmlreport: Node.js 18 or newer is required" >&2; exit 1; }

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ] || { [ $# -eq 0 ] && [ -t 0 ]; }; then
  sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  echo
  node "$cli" --help
  exit 0
fi

if [ "$1" = "generate" ]; then
  shift
  exec node "$cli" "$@"
fi

# output plugin: trivy pipes the JSON in
if { [ $# -eq 0 ] || [[ "$1" == -* ]]; } && [ ! -t 0 ]; then
  exec node "$cli" "$@" -
fi

trivy_args=() report_args=() seen=0
for a in "$@"; do
  if [ "$a" = "--report-flags" ]; then seen=1; continue; fi
  if [ $seen -eq 1 ]; then report_args+=("$a"); else trivy_args+=("$a"); fi
done

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trivy "${trivy_args[@]}" --format json --output "$tmp/scan.json"
node "$cli" ${report_args[@]+"${report_args[@]}"} "$tmp/scan.json"
