# trivy-htmlreport

Interactive, self-contained HTML reports from [Trivy](https://trivy.dev) results.

One HTML file, no server, no build step. Open it in a browser and drop in Trivy output, or let the CLI / Trivy plugin write a finished report you can mail or attach to a ticket.

## What it shows

- Summary per severity, with how many findings already have a fix
- Highlights: worst images, known-exploited CVEs (CISA KEV), highest EPSS, most widespread criticals, most fixable images, privileged workloads
- Images table, worst first, expandable to the findings and the workloads that use the image
- Vulnerabilities as **each finding** or as **unique CVEs** with links to every image they appear in; filter by severity, namespace, source, fix available, known exploited; sort by severity, CVSS, EPSS or number of images
- CVE details: description, CVSS vector, CWE, references, EPSS and KEV data
- Misconfigurations grouped by check, secrets (rule, file and line only - the matched value is never stored), licenses, package inventory
- Workloads whose images Trivy could not scan, so gaps are visible
- Light and dark theme, works on a phone

## Input

- `trivy k8s`, `trivy image`, `trivy fs`, `trivy repo` JSON (`-f json`)
- CycloneDX and SPDX JSON SBOMs
- Package inventories (`--list-all-pkgs`)

Several files can be merged into one report. Large files are streamed, so a 300 MB cluster scan is fine.

```sh
trivy k8s --report summary -f json -o cluster.json
trivy image --scanners vuln,secret,misconfig,license -f json -o image.json nginx:1.29
trivy image --format cyclonedx -o sbom.cdx.json nginx:1.29
```

## Usage

### In the browser

Open `trivy-report.html`, drop the JSON files on it, then **Save report** to get a single shareable file.

### CLI (Node.js 18+)

```sh
node trivy-report-cli.mjs -o report.html --title "Production cluster" cluster.json
node trivy-report-cli.mjs -o report.html --enrich image.json sbom.cdx.json
trivy image -f json nginx:1.29 | node trivy-report-cli.mjs -o nginx.html -
```

Options: `-o/--output`, `-t/--title`, `--epss`, `--kev`, `--enrich` (both), `--from a.json,b.json`, `--viewer <template>`, `-q`, `-h`.

### Trivy plugin

```sh
./build.sh
trivy plugin install .
```

```sh
# scan and report in one go: Trivy flags first, report flags after --report-flags
trivy htmlreport k8s --report summary --report-flags -o cluster.html --title "Cluster" --enrich

# report from existing files
trivy htmlreport generate -o report.html scan1.json sbom.cdx.json

# as an output plugin
trivy image -f json --output plugin=htmlreport --output-plugin-arg "-o nginx.html" nginx:1.29
```

Trivy installs a copy of the plugin, so after editing the source run `./build.sh`, then `trivy plugin uninstall htmlreport && trivy plugin install .`.

## Network access

Your scan data never leaves your machine. The only outbound requests are:

| When | Request | What is sent |
|---|---|---|
| Opening the page | Google Fonts (IBM Plex) | nothing but the request itself; falls back to system fonts offline |
| **Fetch EPSS + exploit data** button, or `--epss` | `api.first.org` | the CVE IDs, in batches of 100 |
| Same, or `--kev` | CISA KEV list (GitHub mirror in the browser, cisa.gov in the CLI) | nothing, plain download |

Without these two options the report is built entirely offline.

## Security notes

- All scan content is escaped before it is rendered, and links only allow `http(s)`.
- Reports contain an inventory of your weaknesses (images, workloads, unpatched and known-exploited CVEs). Treat them like any other sensitive document and keep them out of public repositories.
- `--viewer` loads code from the template you give it; only use a template you trust.

## Limitations

- CycloneDX severities come from the SBOM's ratings, so a few CVEs can rank one level differently from Trivy's own JSON.
- Images Trivy could not pull do not appear; affected workloads are listed in the summary.
- Opening and saving compressed reports needs a current browser (Chrome/Edge 80+, Firefox 113+, Safari 16.4+).

## License

[MIT](LICENSE)
