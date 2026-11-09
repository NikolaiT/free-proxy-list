const fs = require('fs');
const path = require('path');
const net = require('net');
const tls = require('tls');
const dns = require('dns');
const { once } = require('events');
const { execSync } = require('child_process');
const { socks5sources, socks4sources, httpSources, httpsSources } = require('./proxySources.js');
const {
  downloadSource,
  getCurrentPublicIp,
  normalizeProxyLine,
  TIMEOUT,
  TEST_URL,
  CONCURRENCY,
  SAVE_INTERVAL,
  saveResults,
  saveUniqueIpResults,
  writeWorkingProxiesToFiles,
  isValidIp,
  convertSourceLine
} = require('./helpers.js');

const { readFile } = fs.promises;

// Tests run in-process. Spawning a curl per proxy (300 at a time, ~60 a second)
// got the whole Terminal session killed by macOS XProtect as malware.
const TEST_HOST = new URL(TEST_URL).hostname;
const CONNECT_TIMEOUT = 5000;
const PORT_443 = Buffer.from([0x01, 0xbb]);
let testHostIp;

// Resolves with what the proxy sent once `complete(bytes)` holds.
function readReply(socket, complete) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const onReadable = () => {
      for (let chunk; (chunk = socket.read()) !== null;) bytes = Buffer.concat([bytes, chunk]);
      if (complete(bytes)) settle();
    };
    const onClose = () => settle(new Error('Proxy closed the connection'));
    const settle = (err) => {
      socket.off('readable', onReadable).off('end', onClose).off('close', onClose);
      if (err) reject(err);
      else resolve(bytes);
    };
    socket.on('readable', onReadable).on('end', onClose).on('close', onClose);
  });
}

// VER REP RSV ATYP BND.ADDR BND.PORT, where ATYP gives the length of BND.ADDR.
function socks5ReplyComplete(b) {
  if (b.length >= 2 && b[1] !== 0) return true;
  if (b.length < 5) return false;
  return b.length >= 6 + (b[3] === 1 ? 4 : b[3] === 4 ? 16 : 1 + b[4]);
}

// As curl did: SOCKS proxies get TEST_HOST resolved locally (--socks5, not
// --socks5-hostname), HTTP proxies a CONNECT.
async function openTunnel(socket, type) {
  if (type === 'http' || type === 'https') {
    socket.write(`CONNECT ${TEST_HOST}:443 HTTP/1.1\r\nHost: ${TEST_HOST}:443\r\n\r\n`);
    const reply = await readReply(socket, (b) => b.includes('\r\n\r\n') || b.length > 16384);
    const status = reply.toString('latin1').split('\r\n', 1)[0];
    if (!/^HTTP\/1\.[01] 2\d\d/.test(status)) throw new Error(`Proxy CONNECT failed: ${status.substring(0, 80)}`);
    return;
  }
  testHostIp ??= (await dns.promises.lookup(TEST_HOST, { family: 4 })).address;
  const address = Buffer.from(testHostIp.split('.').map(Number));
  if (type === 'socks4') {
    socket.write(Buffer.concat([Buffer.from([4, 1]), PORT_443, address, Buffer.from([0])]));
    const reply = await readReply(socket, (b) => b.length >= 8);
    if (reply[1] !== 90) throw new Error(`SOCKS4 connect failed (reply ${reply[1]})`);
    return;
  }
  socket.write(Buffer.from([5, 1, 0]));
  const [version, method] = await readReply(socket, (b) => b.length >= 2);
  if (version !== 5 || method !== 0) throw new Error(`SOCKS5 proxy refused unauthenticated access (method ${method})`);
  socket.write(Buffer.concat([Buffer.from([5, 1, 0, 1]), address, PORT_443]));
  const reply = await readReply(socket, socks5ReplyComplete);
  if (reply[1] !== 0) throw new Error(`SOCKS5 connect failed (reply ${reply[1]})`);
}

// The limits of curl --connect-timeout 5 --max-time 12: tunnel and TLS within
// CONNECT_TIMEOUT, everything within TIMEOUT. Certificates are checked through
// SOCKS only; HTTP proxies were always tested with curl -k.
async function fetchThroughProxy({ type, host, port }) {
  const socket = net.connect({ host, port: Number(port), family: 4 });
  let secure;
  let fail;
  const failed = new Promise((_, reject) => { fail = reject; });
  const connectTimer = setTimeout(() => fail(new Error('Connect timeout')), CONNECT_TIMEOUT);
  const totalTimer = setTimeout(() => fail(new Error('Timeout')), TIMEOUT);
  socket.on('error', (err) => fail(err));
  try {
    return await Promise.race([failed, (async () => {
      await once(socket, 'connect');
      await openTunnel(socket, type);
      secure = tls.connect({ socket, servername: TEST_HOST, rejectUnauthorized: type.startsWith('socks') });
      secure.on('error', (err) => fail(err));
      await once(secure, 'secureConnect');
      clearTimeout(connectTimer);
      secure.write(`GET / HTTP/1.0\r\nHost: ${TEST_HOST}\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
      let response = '';
      for await (const chunk of secure) {
        response += chunk;
        if (response.length > 65536) break;
      }
      const headerEnd = response.indexOf('\r\n\r\n');
      if (headerEnd < 0) throw new Error('No HTTP response');
      return response.slice(headerEnd + 4).trim();
    })()]);
  } finally {
    clearTimeout(connectTimer);
    clearTimeout(totalTimer);
    socket.destroy();
    if (secure) secure.destroy();
  }
}

/**
 * Test a single proxy for functionality and anonymity.
 *
 * @param {Object} proxyObj - Proxy object with type, host, port, normalized.
 * @param {string} currentPublicIp - The current public IP of the client.
 * @returns {Promise<Object>} - Result object with success, proxy, ip/error.
 */
async function testProxy(proxyObj, currentPublicIp) {
  const started = Date.now();
  const failure = (error) => ({ success: false, proxy: proxyObj.normalized, error: error.substring(0, 200) });
  try {
    const ip = await fetchThroughProxy(proxyObj);
    if (ip === currentPublicIp) return failure('Proxy resolves to client IP, not a working proxy');
    if (!isValidIp(ip)) return failure(`Invalid IP format received: ${ip}`);
    return { success: true, ip, proxy: proxyObj.normalized, latencyMs: Date.now() - started };
  } catch (err) {
    return failure(err.message || err.code || 'Unknown error');
  }
}

/**
 * Get initial results object for all proxy types.
 */
function getInitialResults() {
  return {
    socks5: { working: [], failed: [] },
    socks4: { working: [], failed: [] },
    http: { working: [], failed: [] },
    https: { working: [], failed: [] }
  };
}

/**
 * Group proxies by their type.
 * @param {Array} dedupedProxies
 * @returns {Object} - { socks5: [], socks4: [], http: [], https: [] }
 */
function groupProxiesByType(dedupedProxies) {
  const proxiesByType = {
    socks5: [],
    socks4: [],
    http: [],
    https: []
  };
  for (const obj of dedupedProxies) {
    if (proxiesByType[obj.type]) {
      proxiesByType[obj.type].push(obj);
    }
  }
  return proxiesByType;
}

async function loadProxiesFromSource({ url, type }) {
  const proxies = [];

  const filePath = await downloadSource(url);
  if (!filePath) {
    return { type, proxies, error: 'download failed' };
  }

  let content;
  try {
    content = await readFile(filePath, 'utf8');
  } catch (readError) {
    return { type, proxies, error: readError.message };
  }

  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const conversion = convertSourceLine(lines[i], type, url);
    if (conversion.skip || conversion.error) {
      continue;
    }
    const norm = normalizeProxyLine(conversion.value, type);
    if (norm) {
      proxies.push({ ...norm, source: url });
    }
  }

  return { type, proxies };
}

async function loadAndNormalizeSources(sources) {
  const perSourceResults = await Promise.all(sources.map(loadProxiesFromSource));

  const dedupedMap = new Map();
  let combinedCount = 0;

  for (const { proxies } of perSourceResults) {
    combinedCount += proxies.length;
    for (let i = 0; i < proxies.length; i++) {
      const proxy = proxies[i];
      if (!dedupedMap.has(proxy.normalized)) {
        dedupedMap.set(proxy.normalized, proxy);
      }
    }
  }

  const dedupedProxies = Array.from(dedupedMap.values());
  return {
    combinedCount,
    dedupedProxies,
    proxiesByType: groupProxiesByType(dedupedProxies)
  };
}

function csvEscape(value) {
  if (value === undefined || value === null) {
    return '';
  }
  const stringValue = String(value);
  if (/[",\n]/.test(stringValue)) {
    return '"' + stringValue.replace(/"/g, '""') + '"';
  }
  return stringValue;
}

async function exportAllProxiesCsv() {
  const allSources = [
    ...socks5sources.map(url => ({ url, type: 'socks5' })),
    ...socks4sources.map(url => ({ url, type: 'socks4' })),
    ...httpSources.map(url => ({ url, type: 'http' })),
    ...httpsSources.map(url => ({ url, type: 'https' })),
  ];

  const { dedupedProxies } = await loadAndNormalizeSources(allSources);
  const counts = {
    socks5: 0,
    socks4: 0,
    http: 0,
    https: 0
  };

  const header = 'host,port,protocol,source';
  const rows = [header];
  for (const proxy of dedupedProxies) {
    const { host, port, type, source } = proxy;
    if (counts[type] !== undefined) {
      counts[type] += 1;
    }
    rows.push([
      csvEscape(host),
      csvEscape(port),
      csvEscape(type),
      csvEscape(source || '')
    ].join(','));
  }

  const outputPath = path.join(__dirname, 'all_proxies.csv');
  fs.writeFileSync(outputPath, rows.join('\n'), 'utf8');

  return { outputPath, total: dedupedProxies.length, counts };
}

/**
 * Process proxies with a concurrency queue, persisting progress regularly.
 */
async function processProxiesWithQueue(proxyObjs, type, currentResults, workingSet, failedSet, currentPublicIp, results, outputPath, outputDir) {
  let testedCountSinceSave = 0;
  let totalWorkingCount = currentResults.working.length;
  let totalFailedCount = currentResults.failed.length;

  const proxiesToTest = [];
  let alreadyKnown = 0;
  for (let i = 0; i < proxyObjs.length; i++) {
    const candidate = proxyObjs[i];
    if (workingSet.has(candidate.normalized) || failedSet.has(candidate.normalized)) {
      alreadyKnown++;
      continue;
    }
    proxiesToTest.push(candidate);
  }

  // Silently skip already-tested proxies

  const total = proxiesToTest.length;
  const startTime = Date.now();

  if (total === 0) {
    // No new proxies to test, skip silently
    return;
  }

  let index = 0;
  let finished = 0;

  function recordResult(result) {
    if (!result) return;

    if (result.success) {
      if (!workingSet.has(result.proxy)) {
        currentResults.working.push(result);
        workingSet.add(result.proxy);
        totalWorkingCount++;
      }
    } else {
      if (!failedSet.has(result.proxy)) {
        currentResults.failed.push(result);
        failedSet.add(result.proxy);
        totalFailedCount++;
      }
    }

    testedCountSinceSave++;
  }

  function recordInternalError(err, proxyObj) {
    const errorResult = {
      success: false,
      proxy: proxyObj.normalized,
      error: `Internal test error: ${err.message}`.substring(0, 200)
    };
    recordResult(errorResult);
  }

  function persistIfNeeded(force = false) {
    if (!force && testedCountSinceSave < SAVE_INTERVAL) {
      return;
    }
    results[type] = currentResults;
    try {
      saveResults(results, outputPath);
      saveUniqueIpResults(results, outputDir);
      exportRankedProxiesForScrapeApi(results, false);
    } catch (saveError) {
      // ignore persistence errors
    }
    testedCountSinceSave = 0;
  }

  const latencies = [];

  const workerCount = Math.min(CONCURRENCY, total);

  // Carriage-return progress is only useful on an interactive terminal; when
  // stdout is redirected to a log file it produces huge unreadable blobs, so
  // fall back to a plain progress line once a minute.
  const isTTY = process.stdout.isTTY;
  if (!isTTY) {
    console.log(`[${type}] Testing ${total} proxies with ${workerCount} workers...`);
  }
  let lastPlainLog = Date.now();
  const progressInterval = setInterval(() => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
    const rate = (finished / Math.max(elapsed, 1)).toFixed(1);
    if (isTTY) {
      process.stdout.write(`\r[${type}] ${finished}/${total} tested | ${totalWorkingCount} working | ${totalFailedCount} failed | ${rate}/s | ${elapsed}s`);
    } else if (Date.now() - lastPlainLog >= 60000) {
      lastPlainLog = Date.now();
      console.log(`[${type}] ${finished}/${total} tested | ${totalWorkingCount} working | ${totalFailedCount} failed | ${rate}/s | ${elapsed}s`);
    }
  }, 2000);
  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      const currentIndex = index++;
      if (currentIndex >= total) {
        break;
      }

      const proxyObj = proxiesToTest[currentIndex];
      try {
        const result = await testProxy(proxyObj, currentPublicIp);
        recordResult(result);
        if (result.success && result.latencyMs) {
          latencies.push(result.latencyMs);
        }
      } catch (err) {
        recordInternalError(err, proxyObj);
      } finally {
        finished++;
        persistIfNeeded();
      }
    }
  });

  await Promise.all(workers);
  clearInterval(progressInterval);

  persistIfNeeded(true);

  const avgLatency = latencies.length > 0 ? (latencies.reduce((a, b) => a + b, 0) / latencies.length).toFixed(0) : '-';
  const sorted = latencies.slice().sort((a, b) => a - b);
  const medianLatency = sorted.length > 0 ? sorted[Math.floor(sorted.length / 2)] : '-';
  const minLatency = sorted.length > 0 ? sorted[0] : '-';
  const maxLatency = sorted.length > 0 ? sorted[sorted.length - 1] : '-';
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);

  process.stdout.write(`${isTTY ? '\r' : ''}[${type}] ${finished}/${total} tested | ${totalWorkingCount} working | ${totalFailedCount} failed | ${elapsed}s | avg ${avgLatency}ms med ${medianLatency}ms min ${minLatency}ms max ${maxLatency}ms\n`);
}


/**
 * Main function to detect proxies from all sources.
 */
async function detectProxies() {
  const outputDir = path.join(__dirname, 'outputs');
  const outputPath = path.join(outputDir, 'proxy_results.json');
  let results = {};

  let currentPublicIp;
  try {
    currentPublicIp = await getCurrentPublicIp();
    if (!isValidIp(currentPublicIp)) {
      console.log(`[-] Could not determine current public IP. Abort.`);
      return;
    }
  } catch (err) {
    console.log('[-] Unable to continue without current public IP. Abort.');
    return;
  }

  results = getInitialResults();

  // Gather all proxy sources
  const allSources = [
    ...socks5sources.map(url => ({ url, type: 'socks5' })),
    ...socks4sources.map(url => ({ url, type: 'socks4' })),
    ...httpSources.map(url => ({ url, type: 'http' })),
    ...httpsSources.map(url => ({ url, type: 'https' })),
  ];

  const { combinedCount, dedupedProxies, proxiesByType } = await loadAndNormalizeSources(allSources);
  const typeCounts = Object.entries(proxiesByType).map(([t, arr]) => `${t}: ${arr.length}`).join(' | ');
  console.log(`[proxy-list] Loaded ${dedupedProxies.length} unique proxies from ${allSources.length} sources (${combinedCount} raw, ${typeCounts})`);

  // Process proxies by type
  for (const type of ['socks5', 'socks4', 'http', 'https']) {
    const proxyObjs = proxiesByType[type];
    if (!proxyObjs || proxyObjs.length === 0) continue;

    const currentResults = results[type] || { working: [], failed: [] };
    const workingSet = new Set(currentResults.working.map(p => p.proxy));
    const failedSet = new Set(currentResults.failed.map(p => p.proxy));

    await processProxiesWithQueue(proxyObjs, type, currentResults, workingSet, failedSet, currentPublicIp, results, outputPath, outputDir);
    results[type] = currentResults;
  }

  saveResults(results, outputPath);
  saveUniqueIpResults(results, outputDir);

  const allLatencies = [];
  const counts = {};
  for (const type of ['socks5', 'socks4', 'http', 'https']) {
    const w = results[type].working;
    counts[type] = w.length;
    for (const entry of w) {
      if (entry.latencyMs) allLatencies.push(entry.latencyMs);
    }
  }
  const totalWorking = counts.socks5 + counts.socks4 + counts.http + counts.https;
  const totalFailed = results.socks5.failed.length + results.socks4.failed.length + results.http.failed.length + results.https.failed.length;
  const totalTested = totalWorking + totalFailed;

  const sorted = allLatencies.slice().sort((a, b) => a - b);
  const avg = sorted.length ? (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(0) : '-';
  const med = sorted.length ? sorted[Math.floor(sorted.length / 2)] : '-';

  console.log(`\n[proxy-list] Done: ${totalTested} tested, ${totalWorking} working, ${totalFailed} failed`);
  console.log(`[proxy-list] http: ${counts.http} | https: ${counts.https} | socks5: ${counts.socks5} | socks4: ${counts.socks4}`);
  console.log(`[proxy-list] Latency: avg ${avg}ms, median ${med}ms, min ${sorted[0] || '-'}ms, max ${sorted[sorted.length - 1] || '-'}ms`);

  return results;
}

// Lazy-loaded mmdb reader for IP-to-country lookups
let _locationReader = null;
let _location6Reader = null;
function getCountryCode(ip) {
  if (!_locationReader) {
    try {
      const mmdb = require('mmdb-lib');
      const locationPath = path.join(__dirname, '..', 'ip_api_data', 'ipapi_database', 'mmdb', 'location.mmdb');
      const location6Path = path.join(__dirname, '..', 'ip_api_data', 'ipapi_database', 'mmdb', 'location6.mmdb');
      if (fs.existsSync(locationPath)) {
        _locationReader = new mmdb.Reader(fs.readFileSync(locationPath));
      }
      if (fs.existsSync(location6Path)) {
        _location6Reader = new mmdb.Reader(fs.readFileSync(location6Path));
      }
    } catch (err) {
      console.error(`[proxy-list] Failed to load mmdb for country lookup: ${err.message}`);
      return null;
    }
  }
  try {
    const reader = ip.includes(':') ? _location6Reader : _locationReader;
    if (!reader) return null;
    const result = reader.get(ip);
    return result?.countryCode || null;
  } catch {
    return null;
  }
}

function exportRankedProxiesForScrapeApi(results, verbose = true) {
  // scrapeapi.dev reads this as its proxy pool (src/config.js proxyPoolFile).
  // It lives under data/ there, not at the project root — keep the two in sync.
  const SCRAPEAPI_PROXY_FILE = path.join(__dirname, '..', 'scrapeapi.dev', 'data', 'ranked_proxies.json');
  const FREE_PROXY_LIST_FILE = path.join(__dirname, 'ranked_proxies.json');

  const ranked = [];
  for (const type of ['http', 'https', 'socks5', 'socks4']) {
    const working = (results[type] && results[type].working) || [];
    for (const entry of working) {
      if (!entry.proxy || !entry.ip || !entry.latencyMs) continue;
      const parts = entry.proxy.match(/^(\w+):\/\/(.+):(\d+)$/);
      if (!parts) continue;
      ranked.push({
        scheme: parts[1],
        host: parts[2],
        port: parseInt(parts[3], 10),
        exitIp: entry.ip,
        exitCountry: getCountryCode(entry.ip),
        latencyMs: entry.latencyMs,
      });
    }
  }

  ranked.sort((a, b) => a.latencyMs - b.latencyMs);

  const output = {
    generatedAt: new Date().toISOString(),
    count: ranked.length,
    proxies: ranked,
  };

  try {
    fs.mkdirSync(path.dirname(SCRAPEAPI_PROXY_FILE), { recursive: true });
    fs.writeFileSync(SCRAPEAPI_PROXY_FILE, JSON.stringify(output, null, 2));
    if (verbose) console.log(`[proxy-list] Exported ${ranked.length} ranked proxies to ${SCRAPEAPI_PROXY_FILE}`);
  } catch (err) {
    console.error(`[proxy-list] Failed to write ranked proxies to scrapeapi: ${err.message}`);
  }

  try {
    fs.writeFileSync(FREE_PROXY_LIST_FILE, JSON.stringify(output, null, 2));
    if (verbose) console.log(`[proxy-list] Exported ${ranked.length} ranked proxies to ${FREE_PROXY_LIST_FILE}`);
  } catch (err) {
    console.error(`[proxy-list] Failed to write ranked proxies to free-proxy-list: ${err.message}`);
  }
}

async function updateFreeProxyList() {
  const results = await detectProxies();

  // detectProxies() returns undefined when it aborts (e.g. the public IP could
  // not be determined). Previously this still exported files and reported
  // success, silently publishing stale/empty proxy lists.
  if (!results) {
    return { status: 'UPDATE_WARNING', message: 'Proxy detection aborted (no public IP?) — keeping previous proxy lists', error: null };
  }

  writeWorkingProxiesToFiles();
  await exportAllProxiesCsv();
  exportRankedProxiesForScrapeApi(results);

  const totalWorking = ['socks5', 'socks4', 'http', 'https']
    .reduce((sum, type) => sum + ((results[type] && results[type].working.length) || 0), 0);

  try {
    // Only commit when files actually changed; `git commit` exits non-zero on an
    // empty diff, which previously produced a misleading "Git push failed" error.
    const hasChanges = execSync('git status --porcelain', { cwd: __dirname, timeout: 15000 }).toString().trim().length > 0;
    if (hasChanges) {
      execSync('git add . && git commit -m "auto commit (I am lazy)" && git push origin main', {
        cwd: __dirname,
        stdio: 'inherit',
        timeout: 30000,
      });
      console.log('[proxy-list] Repository pushed successfully');
    } else {
      console.log('[proxy-list] No changes to commit');
    }
  } catch (err) {
    console.error('[proxy-list] Git push failed:', err.message);
    return { status: 'UPDATE_WARNING', message: `Free proxy list updated (${totalWorking} working proxies) but git push failed: ${err.message}`, error: null };
  }

  return { status: 'UPDATE_SUCCESS', message: `Free proxy list updated: ${totalWorking} working proxies`, error: null };
}

(async () => {
  // CLI entrypoints
  if (process.argv.includes('updateFreeProxyList')) {
    await updateFreeProxyList();
    process.exit(0);
  } else if (process.argv.includes('testProxy')) {
    const currentPublicIp = await getCurrentPublicIp();
    if (!isValidIp(currentPublicIp)) {
      console.log(`[-] Could not determine current public IP: Invalid IP format received: ${currentPublicIp}`);
      return;
    }
    const testSocks5 = false; // Set to true to test SOCKS5 proxies
    if (testSocks5) {
      const tests = [
        `socks5://45.12.132.212:51991`,
        'socks5://64.229.99.171:5678',
        'socks5://38.51.243.173:5678',
        'socks5://194.195.122.51:1080',
        'socks5://124.41.213.174:5678',
        'socks5://193.122.105.251:65535',
      ];
      for (const test of tests) {
        const norm = normalizeProxyLine(test);
        const result = await testProxy(norm, currentPublicIp);
        console.log(result);
      }
    }
    const httpsProxies = [
      'https://13.234.24.116:1080',
      'https://35.90.245.227:3128',
      'https://3.9.12.67:8001',
      'https://15.206.25.41:3128',
      'https://13.233.130.25:4255',
      'https://34.221.119.219:3128',
      'https://54.245.34.166:8000'
    ];
    console.log(`[+] Testing ${httpsProxies.length} HTTPS proxies...`);
    for (const test of httpsProxies) {
      const norm = normalizeProxyLine(test);
      if (norm) {
        const result = await testProxy(norm, currentPublicIp);
        console.log(`${test}: ${result.success ? 'SUCCESS' : 'FAILED'} - ${result.success ? result.ip : result.error}`);
      }
    }
  }
})();

module.exports = {
  updateFreeProxyList
};