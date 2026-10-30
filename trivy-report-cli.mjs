#!/usr/bin/env node
// Headless version of the viewer's "Save report".
// The parser is pulled out of trivy-report.html so there's only one copy of it.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const KEV_CISA = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const USAGE = `Usage: trivy-report-cli.mjs [options] <file.json> [more.json ...]

Reads Trivy JSON (k8s, image, fs, repo), CycloneDX or SPDX JSON and writes one
self-contained HTML report. Use - to read a single file from stdin.

Options:
  -o, --output <file>   Report to write (default: trivy-report.html)
  -t, --title <text>    Report title (default: derived from the scanned target)
      --epss            Add EPSS scores (sends CVE IDs to api.first.org)
      --kev             Mark CVEs in the CISA Known Exploited Vulnerabilities catalog
      --enrich          Same as --epss --kev
      --from a,b,c      Comma-separated input files
      --viewer <file>   Viewer template (default: trivy-report.html next to this script)
  -q, --quiet           No progress output
  -h, --help            Show this help`;

function fail(msg) { console.error('trivy-report: ' + msg); process.exit(2); }
function parseArgs(argv) {
  const o = { output: 'trivy-report.html', title: '', epss: false, kev: false, viewer: path.join(HERE, 'trivy-report.html'), quiet: false, inputs: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i], val = () => { if (i + 1 >= argv.length) fail(`${a} needs a value`); return argv[++i]; };
    if (a === '-o' || a === '--output') o.output = val();
    else if (a.startsWith('--output=')) o.output = a.slice(9);
    else if (a === '-t' || a === '--title' || a === '--report-title') o.title = val();
    else if (a.startsWith('--title=')) o.title = a.slice(8);
    else if (a === '--epss' || a === '--with-epss') o.epss = true;
    else if (a === '--kev' || a === '--with-exploits') o.kev = true;
    else if (a === '--enrich') o.epss = o.kev = true;
    else if (a === '--viewer') o.viewer = val();
    else if (a === '-q' || a === '--quiet') o.quiet = true;
    else if (a === '-h' || a === '--help') { console.log(USAGE); process.exit(0); }
    else if (a === '--from') o.inputs.push(...val().split(',').filter(Boolean));
    else if (a.startsWith('-') && a !== '-') fail(`unknown option ${a}\n\n${USAGE}`);
    else o.inputs.push(a);
  }
  if (!o.inputs.length) fail(`no input files\n\n${USAGE}`);
  return o;
}

// minimal File stand-in (slice + arrayBuffer), reads from disk on demand
function diskFile(p, name) {
  const st = fs.statSync(p), fd = fs.openSync(p, 'r');
  return {
    name: name || path.basename(p), size: st.size, lastModified: st.mtimeMs,
    slice: (a, b) => ({
      arrayBuffer: async () => {
        const len = Math.max(0, Math.min(b, st.size) - a), buf = Buffer.allocUnsafe(len);
        let got = 0;
        while (got < len) got += fs.readSync(fd, buf, got, len - got, a + got);
        return buf.buffer.slice(buf.byteOffset, buf.byteOffset + len);
      }
    })
  };
}
async function stdinToFile() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'trivy-report-'));
  const p = path.join(dir, 'stdin.json');
  await new Promise((res, rej) => { const w = fs.createWriteStream(p); process.stdin.pipe(w); w.on('finish', res); w.on('error', rej); process.stdin.on('error', rej); });
  process.on('exit', () => fs.rmSync(dir, { recursive: true, force: true }));
  return p;
}
const mb = n => (n / 1e6).toFixed(1) + ' MB';
const escHtml = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

async function main() {
  const o = parseArgs(process.argv.slice(2));
  const log = o.quiet ? () => {} : m => process.stderr.write(m + '\n');
  if (!fs.existsSync(o.viewer)) fail(`viewer template not found: ${o.viewer}`);
  const html = fs.readFileSync(o.viewer, 'utf8');
  const core = html.match(/\/\*CORE-START\*\/([\s\S]*?)\/\*CORE-END\*\//);
  if (!core) fail(`${o.viewer} has no parser block (CORE-START/CORE-END markers)`);
  const lib = new Function(core[1] + '\nreturn trivyCore;')()();

  const files = [];
  for (const p of o.inputs) {
    if (p === '-') files.push(diskFile(await stdinToFile(), 'stdin.json'));
    else if (!fs.existsSync(p)) fail(`input not found: ${p}`);
    else files.push(diskFile(p));
  }
  const t0 = Date.now();
  let lastPct = -10;
  const data = await lib.processFiles(files, (p, name) => {
    const pct = Math.floor(p * 100);
    if (pct >= lastPct + 10) { lastPct = pct; log(`reading ${name}: ${pct}%`); }
  });
  data.ms = Date.now() - t0;

  if (o.epss || o.kev) {
    log(`fetching ${[o.epss && 'EPSS', o.kev && 'CISA KEV'].filter(Boolean).join(' + ')} data`);
    const r = await lib.enrich(data, { epss: o.epss, kev: o.kev, kevUrl: KEV_CISA }, m => {
      const x = /^EPSS (\d+)\/(\d+)$/.exec(m);   // too chatty otherwise
      if (!x || +x[1] % 10 === 0 || x[1] === x[2]) log('  ' + m);
    });
    Object.assign(data, { epss: r.epss, kev: r.kev, enrich: r.info });
  }
  data.title = o.title;

  // write via .part + rename so a failed run doesn't leave half a report
  const tag = '<script id="embedded" type="application/json"></script>';
  const at = html.indexOf(tag);
  if (at < 0) fail(`${o.viewer} has no empty embedded-data tag`);
  let head = html.slice(0, at);
  if (o.title) head = head.replace(/<title>[^<]*<\/title>/, () => '<title>' + escHtml(o.title) + '</title>');
  const tmpOut = o.output + '.part';
  const fd = fs.openSync(tmpOut, 'w');
  try {
    fs.writeSync(fd, head + tag.replace('></script>', ' data-pack="gzip">'));
    for await (const s of lib.packReport(data)) fs.writeSync(fd, s);
    fs.writeSync(fd, '</script>' + html.slice(at + tag.length));
  } catch (e) { fs.closeSync(fd); fs.rmSync(tmpOut, { force: true }); throw e; }
  fs.closeSync(fd);
  fs.renameSync(tmpOut, o.output);

  const t = data.totals.v;
  log(`wrote ${o.output} (${mb(fs.statSync(o.output).size)}) in ${((Date.now() - t0) / 1000).toFixed(1)} s: ` +
    `${t.CRITICAL} critical, ${t.HIGH} high, ${t.MEDIUM} medium, ${t.LOW} low vulnerabilities; ` +
    `${data.mis.length} failed checks; ${data.secrets.length} secrets; ${data.licenses.length} licenses; ${data.packages.length} packages` +
    (data.enrich && data.enrich.kev ? `; ${Object.keys(data.kev).length} known-exploited CVEs` : '') +
    (data.unscanned.length ? `; ${data.unscanned.length} workloads without image results` : ''));
}
main().catch(e => { console.error('trivy-report: ' + (e && e.message || e)); process.exit(1); });
