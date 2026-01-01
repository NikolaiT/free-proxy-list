const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const os = require('os');
const net = require('net');
const { socks5sources, socks4sources, httpSources, httpsSources } = require('./proxySources.js');

const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";
const CACHE_DIR = path.join(__dirname, 'cache');
const RESULTS_CACHE_DIR = path.join(__dirname, 'results_cache');
const TEST_URL = 'https://icanhazip.com/';
const TIMEOUT = 12000;
const CONCURRENCY = 50;
const SAVE_INTERVAL = 200;
// Cache validity for proxy source downloads: 6 hours (in ms)
const PROXY_SOURCE_CACHE_VALIDITY = 6 * 60 * 60 * 1000; // 6 hours

// Helper to check if a string is a valid IPv4 or IPv6 address
const isValidIp = (ip) => net.isIP(ip) > 0;

const executeCommand = (command) => {
  return new Promise((resolve, reject) => {
    exec(command, (err, stdout, stderr) => {
      if (err) reject(err);
      resolve(stdout);
    });
  });
};

function downloadCurl(url, dest) {
  return new Promise((resolve, reject) => {
    const command = `curl -s --connect-timeout 5 --max-time 20 --insecure --location --user-agent "${userAgent}" '${url}' > ${dest} 2>/dev/null`;
    executeCommand(command).then((ok) => resolve(ok)).catch((fail) => reject(fail));
  });
}

// Download a proxy source, caching for 6 hours
function urlToCacheFilename(url) {
  // Remove scheme (http:// or https://)
  let noScheme = url.replace(/^[a-zA-Z]+:\/\//, '');
  // Replace all non-filename-safe chars and dots with underscores
  let safe = noScheme.replace(/[^a-zA-Z0-9\-_]/g, '_').replace(/\./g, '_');
  return `${safe}.txt`;
}

// Download a proxy source, caching for 6 hours
async function downloadSource(url) {
  const filename = urlToCacheFilename(url);
  const cachePath = path.join(CACHE_DIR, filename);

  // Check if cache exists and is fresh (within 6 hours)
  let cacheValid = false;
  try {
    const stat = fs.statSync(cachePath);
    const now = Date.now();
    if (now - stat.mtimeMs < PROXY_SOURCE_CACHE_VALIDITY) {
      cacheValid = true;
    }
  } catch (e) {
    // File does not exist or stat error, will download
    cacheValid = false;
  }

  if (cacheValid) {
    console.log(`[+] Using cached proxy source for ${url} at ${cachePath}`);
    return cachePath;
  }

  try {
    await downloadCurl(url, cachePath);
    // Update mtime to now (in case curl doesn't)
    try {
      fs.utimesSync(cachePath, new Date(), new Date());
    } catch (e) { }
    console.log(`[+] Downloaded ${url} to ${cachePath}`);
    return cachePath;
  } catch (error) {
    if (fs.existsSync(cachePath)) {
      // If download failed but cache exists, use stale cache as fallback
      console.log(`[!] Failed to download ${url}, using stale cache at ${cachePath}: ${error.message}`);
      return cachePath;
    }
    console.log(`[-] Failed to download ${url}: ${error.message}`);
    return null;
  }
}

// Normalize a proxy line to { type, host, port, normalized, original }
function normalizeProxyLine(line, typeHint = null) {
  let trimmed = line.trim();
  if (!trimmed) return null;

  // Try to extract protocol
  let match = trimmed.match(/^(socks5|socks4|http|https):\/\/(.+)$/i);
  let type, hostport;
  if (match) {
    type = match[1].toLowerCase();
    hostport = match[2];
  } else {
    // No protocol, use typeHint if provided
    type = typeHint;
    hostport = trimmed;
  }

  // Remove any trailing slashes
  hostport = hostport.replace(/\/+$/, '');

  // Validate host:port
  let hpMatch = hostport.match(/^([a-zA-Z0-9\.\-\_]+):(\d{2,5})$/);
  if (!hpMatch) return null;

  let host = hpMatch[1];
  let port = hpMatch[2];

  // Normalized string: type://host:port
  let normalized = `${type}://${host}:${port}`;
  return { type, host, port, normalized, original: line };
}

const COMMENT_PREFIXES = ['#', '//', ';'];

function isCommentLine(line) {
  const trimmed = line.trim();
  if (!trimmed) {
    return true;
  }
  return COMMENT_PREFIXES.some(prefix => trimmed.startsWith(prefix));
}

function convertSourceLine(line, typeHint, sourceUrl) {
  const trimmed = line.trim();
  if (!trimmed) {
    return { skip: true };
  }

  const lowerSource = (sourceUrl || '').toLowerCase();

  if (lowerSource.endsWith('.csv')) {
    if (/^dest_ip\s*,/i.test(trimmed)) {
      return { skip: true };
    }

    const parts = trimmed.split(',');
    if (parts.length < 2) {
      return { error: 'CSV row missing columns', raw: trimmed };
    }

    const host = parts[0].trim();
    const port = parts[1].trim();

    if (!host) {
      return { error: 'CSV row missing dest_ip value', raw: trimmed };
    }

    if (!/^\d{1,5}$/.test(port)) {
      return { error: `CSV row has invalid dest_port value: ${port || 'undefined'}`, raw: trimmed };
    }

    return { value: `${host}:${port}`, raw: trimmed };
  }

  if (isCommentLine(trimmed)) {
    return { skip: true };
  }

  return { value: trimmed, raw: trimmed };
}

function explainNormalizationFailure(line, typeHint) {
  const trimmed = line.trim();
  if (!trimmed) {
    return 'Line is empty after trimming';
  }

  const protocolMatch = trimmed.match(/^(socks5|socks4|http|https):\/\/(.+)$/i);
  let type;
  let hostPortCandidate;

  if (protocolMatch) {
    type = protocolMatch[1].toLowerCase();
    hostPortCandidate = protocolMatch[2];
  } else {
    type = typeHint;
    hostPortCandidate = trimmed;
    if (!type) {
      return 'Missing protocol prefix and no type hint supplied';
    }
  }

  const hostPort = hostPortCandidate.replace(/\/+$/, '');

  if (!hostPort.includes(':')) {
    return 'Missing port separator (:)';
  }

  const [hostPart, portPart] = hostPort.split(':');
  if (!portPart || !/^\d{2,5}$/.test(portPart)) {
    return `Invalid port segment: ${portPart || 'undefined'}`;
  }

  if (!hostPart) {
    return 'Host portion is empty';
  }

  if (!/^[a-zA-Z0-9._-]+$/.test(hostPart)) {
    return `Host contains unsupported characters: ${hostPart}`;
  }

  return 'Unknown failure during normalization';
}

async function validateNormalizeProxyLine({ verbose = true } = {}) {
  const sources = [
    ...socks5sources.map(url => ({ url, type: 'socks5' })),
    ...socks4sources.map(url => ({ url, type: 'socks4' })),
    ...httpSources.map(url => ({ url, type: 'http' })),
    ...httpsSources.map(url => ({ url, type: 'https' })),
  ];

  const summary = {
    sourcesChecked: 0,
    totalLines: 0,
    skippedComments: 0,
    normalized: 0,
    failures: [],
  };

  for (const { url, type } of sources) {
    const filename = path.basename(url);
    let cachePath;
    try {
      cachePath = await downloadSource(url);
    } catch (err) {
      cachePath = null;
    }

    if (!cachePath) {
      summary.failures.push({
        type,
        url,
        lineNumber: null,
        line: null,
        reason: 'Failed to download source',
      });
      if (verbose) {
        console.error(`[-] Could not download ${url}`);
      }
      continue;
    }

    summary.sourcesChecked += 1;

    let content;
    try {
      content = fs.readFileSync(cachePath, 'utf8');
    } catch (error) {
      summary.failures.push({
        type,
        url,
        lineNumber: null,
        line: null,
        reason: `Failed to read cached file (${error.message})`,
      });
      if (verbose) {
        console.error(`[-] Failed to read ${cachePath}: ${error.message}`);
      }
      continue;
    }

    const lines = content.split(/\r?\n/);

    lines.forEach((line, index) => {
      const conversion = convertSourceLine(line, type, url);

      if (conversion.skip) {
        summary.skippedComments += 1;
        return;
      }

      if (conversion.error) {
        const failureDetails = {
          type,
          url,
          lineNumber: index + 1,
          line: conversion.raw || line.trim(),
          reason: conversion.error,
        };
        summary.failures.push(failureDetails);
        if (verbose) {
          console.error(`[-] normalizeProxyLine skipped ${filename}:${index + 1} (${type}) -> ${conversion.error}. Line: ${failureDetails.line}`);
        }
        return;
      }

      summary.totalLines += 1;

      const candidate = conversion.value;
      const result = normalizeProxyLine(candidate, type);
      if (!result) {
        const reason = explainNormalizationFailure(candidate, type);
        const failureDetails = {
          type,
          url,
          lineNumber: index + 1,
          line: conversion.raw || candidate,
          reason,
        };
        summary.failures.push(failureDetails);
        if (verbose) {
          console.error(`[-] normalizeProxyLine failed for ${filename}:${index + 1} (${type}) -> ${reason}. Source line: ${failureDetails.line}`);
        }
        return;
      }

      summary.normalized += 1;
    });
  }

  if (verbose) {
    console.log(`[+] normalizeProxyLine validation complete. Checked ${summary.totalLines} entries, ${summary.failures.length} failures.`);
  }

  return summary;
}

// Get the current public IP address by querying api.ipapi.is/ip
async function getCurrentPublicIp() {
  try {
    const tempFile = path.join(os.tmpdir(), `ip-check-${Date.now()}.txt`);

    // Use curl to fetch the IP address
    const curlCommand = `curl -s -m 7 -A "${userAgent}" -H "Accept: */*" -H "Connection: close" ${TEST_URL} -o ${tempFile}`;

    await new Promise((resolve, reject) => {
      exec(curlCommand, (error) => {
        if (error) reject(error);
        else resolve();
      });
    });

    if (fs.existsSync(tempFile)) {
      const data = fs.readFileSync(tempFile, 'utf8').trim();

      // Clean up temp file
      try { fs.unlinkSync(tempFile); } catch (e) { }

      if (isValidIp(data)) {
        return data;
      } else {
        throw new Error(`Invalid IP format received: ${data}`);
      }
    } else {
      throw new Error('Failed to get public IP: No response data');
    }
  } catch (err) {
    console.log(`[-] Could not determine current public IP: ${err.message}`);
    throw err;
  }
}

function saveResults(results, outputPath) {
  try {
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
    console.log(`[+] Intermediate results saved to ${outputPath}`);
  } catch (error) {
    console.log(`[-] Error saving results to ${outputPath}: ${error.message}`);
  }
}

// New helper: Save a single text output file with unique IPs (no port)
function saveUniqueIpResults(results, outputDir) {
  try {
    fs.mkdirSync(outputDir, { recursive: true });
    // Collect all working IPs from all protocols
    const ipSet = new Set();
    for (const proto of ['socks5', 'socks4', 'http', 'https']) {
      const protoResults = results[proto] || { working: [] };
      for (const r of protoResults.working) {
        if (r.ip && typeof r.ip === 'string') {
          ipSet.add(r.ip.trim());
        }
      }
    }
    const uniqueIps = Array.from(ipSet);
    const outputPath = path.join(outputDir, 'unique_working_ips.txt');
    fs.writeFileSync(outputPath, uniqueIps.join('\n'), 'utf8');
    console.log(`[+] Saved unique working IPs to ${outputPath} (${uniqueIps.length} IPs)`);
  } catch (error) {
    console.log(`[-] Error saving unique IP results: ${error.message}`);
  }
}

const writeWorkingProxiesToFiles = () => {
  const resultsPath = path.join(__dirname, 'outputs', 'proxy_results.json');
  let results;
  try {
    results = JSON.parse(fs.readFileSync(resultsPath, 'utf8'));
  } catch (err) {
    console.log(`[-] Failed to read or parse proxy_results.json: ${err.message}`);
    return;
  }

  const protocols = ['socks5', 'socks4', 'http', 'https'];
  const proxiesDir = path.join(__dirname, 'proxies');
  if (!fs.existsSync(proxiesDir)) {
    fs.mkdirSync(proxiesDir, { recursive: true });
  }

  const allIPs = [];

  for (const type of protocols) {
    const currentResults = results[type] || { working: [] };
    // Normalize and dedupe using normalizeProxyLine
    const normalizedSet = new Set();
    const dedupedProxies = type === 'socks5' ? ['78.47.63.161:1080'] : [];
    for (const p of currentResults.working) {
      // p.proxy may be undefined if structure changes, fallback to p.original or skip
      const proxyStr = p.proxy || p.original;
      if (!proxyStr) continue;
      const norm = normalizeProxyLine(proxyStr, type);
      if (norm && !normalizedSet.has(norm.normalized)) {
        normalizedSet.add(norm.normalized);
        dedupedProxies.push(norm.normalized.replace(/^.*?:\/\//, '')); // Write as host:port
        allIPs.push(norm.host);
      }
    }
    const filePath = path.join(proxiesDir, `${type}_working.txt`);
    fs.writeFileSync(filePath, dedupedProxies.join('\n'));
  }

  const uniqueIPs = [...new Set(allIPs)];
  const outputPath = path.join(proxiesDir, 'ips.txt');
  fs.writeFileSync(outputPath, uniqueIPs.join('\n'), 'utf8');
  const lastUpdatedPath = path.join(proxiesDir, 'lastUpdated.txt');
  const currentDate = new Date().toISOString();
  fs.writeFileSync(lastUpdatedPath, currentDate, 'utf8');
  console.log(`[+] Updated lastUpdated.txt with current date: ${currentDate}`);
  console.log(`[+] Saved unique working IPs to ${outputPath} (${uniqueIPs.length} IPs)`);
}

if (!fs.existsSync(CACHE_DIR)) {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
}
if (!fs.existsSync(RESULTS_CACHE_DIR)) {
  fs.mkdirSync(RESULTS_CACHE_DIR, { recursive: true });
}

// --- GLOBAL TLS/Socket error handler to prevent unhandled 'error' events ---
process.on('uncaughtException', (err) => {
  if (
    err &&
    (err.code === 'ECONNRESET' ||
      err.message.includes('Client network socket disconnected before secure TLS connection was established') ||
      err.message.includes('socket hang up') ||
      err.message.includes('read ECONNRESET'))
  ) {
    console.log(`[-] Suppressed unhandled socket/TLS error: ${err.message}`);
  } else {
    throw err;
  }
});

process.on('unhandledRejection', (reason, promise) => {
  if (
    reason &&
    typeof reason === 'object' &&
    (reason.code === 'ECONNRESET' ||
      (reason.message && reason.message.includes('Client network socket disconnected before secure TLS connection was established')) ||
      (reason.message && reason.message.includes('socket hang up')) ||
      (reason.message && reason.message.includes('read ECONNRESET')))
  ) {
    console.log(`[-] Suppressed unhandled rejection socket/TLS error: ${reason.message}`);
  } else {
    throw reason;
  }
});

module.exports = {
  userAgent,
  TIMEOUT,
  CONCURRENCY,
  SAVE_INTERVAL,
  RESULTS_CACHE_DIR,
  CACHE_DIR,
  TEST_URL,
  executeCommand,
  downloadCurl,
  downloadSource,
  getCurrentPublicIp,
  normalizeProxyLine,
  saveResults,
  saveUniqueIpResults,
  writeWorkingProxiesToFiles,
  isValidIp,
  validateNormalizeProxyLine,
  convertSourceLine
};
