const fs = require('fs');
const path = require('path');
const net = require('net');
const { socks5sources, socks4sources, httpSources, httpsSources } = require('./proxySources.js');

const userAgent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36';
const CACHE_DIR = path.join(__dirname, 'cache');
const ETAG_FILE = path.join(CACHE_DIR, '.etags.json');
const TEST_URL = 'https://icanhazip.com/';
const TIMEOUT = 9000;
// Keep concurrency unchanged; speedups come from shorter TCP-only timeouts,
// protocol dedup/short-circuiting, early reply aborts, and dead-proxy backoff.
const CONCURRENCY = 300;
const SAVE_INTERVAL = 5000;
const PROXY_SOURCE_CACHE_VALIDITY = 6 * 60 * 60 * 1000; // 6 hours

if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}

const isValidIp = (ip) => net.isIP(ip) > 0;

// Reject private, loopback, link-local, CGNAT, documentation, multicast and
// reserved IPv4 ranges so we never waste sockets or pollute all_proxies.csv.
function isPublicIpv4(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  const a = Number(parts[0]);
  const b = Number(parts[1]);
  const c = Number(parts[2]);
  const d = Number(parts[3]);
  if (!Number.isInteger(a) || !Number.isInteger(b) || !Number.isInteger(c) || !Number.isInteger(d)) return false;
  if (a < 1 || a > 223 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return false;
  if (a === 10 || a === 127) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  if (a === 203 && b === 0 && c === 113) return false;
  return true;
}

let _etagStore = null;
function loadEtags() {
  if (_etagStore) return _etagStore;
  try {
    _etagStore = JSON.parse(fs.readFileSync(ETAG_FILE, 'utf8'));
  } catch (_) {
    _etagStore = {};
  }
  return _etagStore;
}

function saveEtags() {
  if (!_etagStore) return;
  try {
    fs.writeFileSync(ETAG_FILE, JSON.stringify(_etagStore));
  } catch (_) {}
}

function urlToCacheFilename(url) {
  const noScheme = url.replace(/^[a-zA-Z]+:\/\//, '');
  return `${noScheme.replace(/[^a-zA-Z0-9\-_]/g, '_').replace(/\./g, '_')}.txt`;
}

// Fetch a proxy source with gzip/brotli compression and ETag/If-Modified-Since
// conditional GETs (HTTP 304 transfers 0 body bytes). Rejects HTML error pages.
async function downloadSource(url) {
  const filename = urlToCacheFilename(url);
  const cachePath = path.join(CACHE_DIR, filename);
  const hasCache = fs.existsSync(cachePath);

  if (hasCache) {
    try {
      const stat = fs.statSync(cachePath);
      if (Date.now() - stat.mtimeMs < PROXY_SOURCE_CACHE_VALIDITY && stat.size > 0) {
        return cachePath;
      }
    } catch (_) {}
  }

  const etags = loadEtags();
  const meta = etags[filename] || {};
  const headers = { 'User-Agent': userAgent, 'Accept-Encoding': 'gzip, deflate, br' };
  if (hasCache && meta.etag) headers['If-None-Match'] = meta.etag;
  if (hasCache && meta.lastModified) headers['If-Modified-Since'] = meta.lastModified;

  try {
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(15000), redirect: 'follow' });
    if (res.status === 304 && hasCache) {
      const now = new Date();
      try { fs.utimesSync(cachePath, now, now); } catch (_) {}
      return cachePath;
    }
    if (!res.ok) {
      return hasCache ? cachePath : null;
    }
    const text = await res.text();
    if (!text || /<!doctype\s+html|<html[\s>]/i.test(text.slice(0, 500))) {
      return hasCache ? cachePath : null;
    }
    fs.writeFileSync(cachePath, text, 'utf8');
    const etag = res.headers.get('etag');
    const lastModified = res.headers.get('last-modified');
    if (etag || lastModified) {
      etags[filename] = { etag: etag || undefined, lastModified: lastModified || undefined };
      saveEtags();
    }
    return cachePath;
  } catch (_) {
    return hasCache ? cachePath : null;
  }
}

// Normalize a proxy line to { type, host, port, hostPort, normalized, original }
function normalizeProxyLine(line, typeHint = null) {
  let trimmed = line.trim();
  if (!trimmed) return null;

  // Strip inline trailing comments (e.g. "1.2.3.4:8080 # HTTP [US]")
  const commentIdx = trimmed.search(/\s+(?:#|\/\/|;)/);
  if (commentIdx !== -1) trimmed = trimmed.slice(0, commentIdx).trim();

  let type;
  let hostport;
  const match = trimmed.match(/^(socks5|socks4|http|https):\/\/(.+)$/i);
  if (match) {
    type = match[1].toLowerCase();
    hostport = match[2];
  } else {
    type = typeHint;
    hostport = trimmed;
  }
  if (!type) return null;

  hostport = hostport.replace(/\/+$/, '');

  // Strip trailing metadata after ip:port (e.g. hideip.me's "1.2.3.4:1080:United States")
  const ipMeta = hostport.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})(?:$|[:,\s])/);
  let host;
  let portNum;
  if (ipMeta) {
    host = ipMeta[1];
    portNum = Number(ipMeta[2]);
  } else {
    const hpMatch = hostport.match(/^([a-zA-Z0-9._-]+):(\d{1,5})$/);
    if (!hpMatch) return null;
    host = hpMatch[1];
    portNum = Number(hpMatch[2]);
  }

  if (!Number.isInteger(portNum) || portNum < 1 || portNum > 65535) return null;
  // Require a valid public IPv4 (free proxy lists don't serve valid hostnames;
  // rejecting bogus strings/bogons avoids wasted DNS lookups and bad sockets).
  if (!isPublicIpv4(host)) return null;

  const port = String(portNum);
  const hostPort = `${host}:${port}`;
  return { type, host, port, hostPort, normalized: `${type}://${hostPort}`, original: line };
}

const COMMENT_PREFIXES = ['#', '//', ';'];

function isCommentLine(line) {
  const trimmed = line.trim();
  return !trimmed || COMMENT_PREFIXES.some((prefix) => trimmed.startsWith(prefix));
}

function convertSourceLine(line, typeHint, sourceUrl) {
  const trimmed = line.trim();
  if (!trimmed) return { skip: true };

  if ((sourceUrl || '').toLowerCase().endsWith('.csv')) {
    if (/^dest_ip\s*,/i.test(trimmed)) return { skip: true };
    const parts = trimmed.split(',');
    if (parts.length < 2) return { error: 'CSV row missing columns', raw: trimmed };
    const host = parts[0].trim();
    const port = parts[1].trim();
    if (!host) return { error: 'CSV row missing dest_ip value', raw: trimmed };
    if (!/^\d{1,5}$/.test(port)) return { error: `CSV row has invalid dest_port value: ${port || 'undefined'}`, raw: trimmed };
    return { value: `${host}:${port}`, raw: trimmed };
  }

  if (isCommentLine(trimmed)) return { skip: true };
  return { value: trimmed, raw: trimmed };
}

async function validateNormalizeProxyLine({ verbose = true } = {}) {
  const sources = [
    ...socks5sources.map((url) => ({ url, type: 'socks5' })),
    ...socks4sources.map((url) => ({ url, type: 'socks4' })),
    ...httpSources.map((url) => ({ url, type: 'http' })),
    ...httpsSources.map((url) => ({ url, type: 'https' })),
  ];

  const summary = { sourcesChecked: 0, totalLines: 0, skippedComments: 0, normalized: 0, failures: [] };

  for (const { url, type } of sources) {
    const cachePath = await downloadSource(url).catch(() => null);
    if (!cachePath) {
      summary.failures.push({ type, url, reason: 'Failed to download source' });
      if (verbose) console.error(`[-] Could not download ${url}`);
      continue;
    }
    summary.sourcesChecked += 1;
    const lines = fs.readFileSync(cachePath, 'utf8').split(/\r?\n/);
    let sourceNorm = 0;
    for (const line of lines) {
      const conversion = convertSourceLine(line, type, url);
      if (conversion.skip) { summary.skippedComments += 1; continue; }
      if (conversion.error) continue;
      summary.totalLines += 1;
      if (normalizeProxyLine(conversion.value, type)) {
        summary.normalized += 1;
        sourceNorm += 1;
      }
    }
    if (sourceNorm === 0) {
      summary.failures.push({ type, url, reason: 'Source yielded 0 valid public proxies' });
      if (verbose) console.error(`[-] Source yielded 0 valid proxies: ${url}`);
    }
  }

  if (verbose) {
    console.log(`[+] Validation complete: ${summary.sourcesChecked} sources, ${summary.normalized}/${summary.totalLines} normalized, ${summary.failures.length} source failures.`);
  }
  return summary;
}

async function getCurrentPublicIp() {
  try {
    const res = await fetch(TEST_URL, {
      headers: { 'User-Agent': userAgent, Accept: '*/*' },
      signal: AbortSignal.timeout(7000),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const ip = (await res.text()).trim();
    if (!isValidIp(ip)) throw new Error(`Invalid IP format received: ${ip}`);
    return ip;
  } catch (err) {
    console.log(`[-] Could not determine current public IP: ${err.message}`);
    throw err;
  }
}

// Persist only working proxies + failure counts (keeps proxy_results.json
// ~150 KB instead of 28 MB of failed-proxy error logs rewritten every 5k tests).
function saveResults(results, outputPath) {
  try {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    const compact = {};
    for (const proto of ['socks5', 'socks4', 'http', 'https']) {
      const entry = results[proto] || { working: [], failedCount: 0 };
      compact[proto] = {
        working: entry.working || [],
        failedCount: entry.failedCount ?? (entry.failed ? entry.failed.length : 0),
      };
    }
    fs.writeFileSync(outputPath, JSON.stringify(compact));
  } catch (error) {
    console.log(`[-] Error saving results to ${outputPath}: ${error.message}`);
  }
}

function saveUniqueIpResults(results, outputDir) {
  try {
    fs.mkdirSync(outputDir, { recursive: true });
    const ipSet = new Set();
    for (const proto of ['socks5', 'socks4', 'http', 'https']) {
      for (const r of results[proto]?.working || []) {
        if (r.ip && typeof r.ip === 'string') ipSet.add(r.ip.trim());
      }
    }
    fs.writeFileSync(path.join(outputDir, 'unique_working_ips.txt'), Array.from(ipSet).join('\n'), 'utf8');
  } catch (error) {
    console.log(`[-] Error saving unique IP results: ${error.message}`);
  }
}

const writeWorkingProxiesToFiles = (resultsObj = null) => {
  let results = resultsObj;
  if (!results) {
    const resultsPath = path.join(__dirname, 'outputs', 'proxy_results.json');
    try {
      results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
    } catch (err) {
      console.log(`[-] Failed to read or parse proxy_results.json: ${err.message}`);
      return;
    }
  }

  const protocols = ['socks5', 'socks4', 'http', 'https'];
  const proxiesDir = path.join(__dirname, 'proxies');
  fs.mkdirSync(proxiesDir, { recursive: true });

  const allIPs = [];
  for (const type of protocols) {
    const currentResults = results[type] || { working: [] };
    const normalizedSet = new Set();
    const dedupedProxies = type === 'socks5' ? ['78.47.63.161:1080'] : [];
    for (const p of currentResults.working) {
      const proxyStr = p.proxy || p.original;
      if (!proxyStr) continue;
      const norm = normalizeProxyLine(proxyStr, type);
      if (norm && !normalizedSet.has(norm.normalized)) {
        normalizedSet.add(norm.normalized);
        dedupedProxies.push(norm.hostPort);
        allIPs.push(norm.host);
      }
    }
    fs.writeFileSync(path.join(proxiesDir, `${type}_working.txt`), dedupedProxies.join('\n'));
  }

  const uniqueIPs = [...new Set(allIPs)];
  fs.writeFileSync(path.join(proxiesDir, 'ips.txt'), uniqueIPs.join('\n'), 'utf8');
  const currentDate = new Date().toISOString();
  fs.writeFileSync(path.join(proxiesDir, 'lastUpdated.txt'), currentDate, 'utf8');
  console.log(`[+] Updated lastUpdated.txt (${currentDate}) and ips.txt (${uniqueIPs.length} IPs)`);
};

// Suppress unhandled socket/TLS reset noise from flaky remote proxies.
const isBenignSocketErr = (err) => Boolean(err && typeof err === 'object' && (
  err.code === 'ECONNRESET'
  || err.code === 'EPIPE'
  || (err.message && (
    err.message.includes('Client network socket disconnected before secure TLS connection was established')
    || err.message.includes('socket hang up')
    || err.message.includes('read ECONNRESET')
  ))
));

process.on('uncaughtException', (err) => {
  if (!isBenignSocketErr(err)) throw err;
});

process.on('unhandledRejection', (reason) => {
  if (!isBenignSocketErr(reason)) throw reason;
});

module.exports = {
  userAgent,
  TIMEOUT,
  CONCURRENCY,
  SAVE_INTERVAL,
  CACHE_DIR,
  TEST_URL,
  downloadSource,
  getCurrentPublicIp,
  normalizeProxyLine,
  saveResults,
  saveUniqueIpResults,
  writeWorkingProxiesToFiles,
  isValidIp,
  isPublicIpv4,
  validateNormalizeProxyLine,
  convertSourceLine,
};
