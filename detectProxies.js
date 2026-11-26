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
  convertSourceLine,
} = require('./helpers.js');

const { readFile } = fs.promises;

// Tests run in-process (spawning curl per proxy triggered macOS XProtect).
// Separating TCP connect timeout (2.8s; 99% of working proxies SYN-ACK <2.3s)
// from handshake+TLS (5s) nearly halves wait time & SYN retries on dead IPs.
const TEST_HOST = new URL(TEST_URL).hostname;
const TCP_CONNECT_TIMEOUT = 2800;
const HANDSHAKE_TIMEOUT = 5000;
const MAX_CONNECT_REPLY_BYTES = 4096;
const MAX_HTTP_RESPONSE_BYTES = 2048;
const PORT_443 = Buffer.from([0x01, 0xbb]);
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const BACKOFF_MS = [0, 12 * HOUR_MS, 3 * DAY_MS, 7 * DAY_MS, 14 * DAY_MS];
const HEALTH_PRUNE_AGE_MS = 21 * DAY_MS;
const HEALTH_CACHE_PATH = path.join(__dirname, 'outputs', 'proxy_health.json');
const TCP_DEAD_CODES = new Set(['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT']);
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

// HTTP/HTTPS proxies get CONNECT :443; SOCKS proxies get TEST_HOST resolved locally.
async function openTunnel(socket, type) {
  if (type === 'http' || type === 'https') {
    socket.write(`CONNECT ${TEST_HOST}:443 HTTP/1.1\r\nHost: ${TEST_HOST}:443\r\n\r\n`);
    // Fail fast as soon as the first 12 bytes (or status line) are not HTTP 2xx,
    // avoiding kilobytes of error headers/HTML from the ~77k non-CONNECT servers.
    const reply = await readReply(socket, (b) => {
      if (b.length >= 12 && !/^HTTP\/1\.[01] 2\d\d/.test(b.subarray(0, 12).toString('latin1'))) return true;
      const eol = b.indexOf('\r\n');
      if (eol !== -1 && !/^HTTP\/1\.[01] 2\d\d/.test(b.subarray(0, eol).toString('latin1'))) return true;
      return b.includes('\r\n\r\n') || b.length >= MAX_CONNECT_REPLY_BYTES;
    });
    const status = reply.toString('latin1').split('\r\n', 1)[0];
    if (!/^HTTP\/1\.[01] 2\d\d/.test(status)) throw new Error(`Proxy CONNECT failed: ${status.substring(0, 80)}`);
    return;
  }
  testHostIp ??= (await dns.promises.lookup(TEST_HOST, { family: 4 })).address;
  const address = Buffer.from(testHostIp.split('.').map(Number));
  if (type === 'socks4') {
    socket.write(Buffer.concat([Buffer.from([4, 1]), PORT_443, address, Buffer.from([0])]));
    const reply = await readReply(socket, (b) => b.length >= 8 || (b.length >= 2 && b[1] !== 90));
    if (reply[1] !== 90) {
      const err = new Error(`SOCKS4 connect failed (reply ${reply[1]})`);
      if (reply[0] === 0x48 && reply[1] === 0x54) err.spokeHttp = true;
      throw err;
    }
    return;
  }
  socket.write(Buffer.from([5, 1, 0]));
  const [version, method] = await readReply(socket, (b) => b.length >= 2);
  if (version !== 5 || method !== 0) {
    const err = new Error(`SOCKS5 proxy refused unauthenticated access (method ${method})`);
    if (version === 0x48 && method === 0x54) err.spokeHttp = true;
    throw err;
  }
  socket.write(Buffer.concat([Buffer.from([5, 1, 0, 1]), address, PORT_443]));
  const reply = await readReply(socket, socks5ReplyComplete);
  if (reply[1] !== 0) throw new Error(`SOCKS5 connect failed (reply ${reply[1]})`);
}

async function fetchThroughProxy({ type, host, port }) {
  const socket = net.connect({ host, port: Number(port), family: 4 });
  let secure;
  let tcpConnected = false;
  let fail;
  const failed = new Promise((_, reject) => { fail = reject; });
  const tcpTimer = setTimeout(() => {
    const e = new Error('TCP connect timeout');
    e.tcpDead = true;
    fail(e);
  }, TCP_CONNECT_TIMEOUT);
  const handshakeTimer = setTimeout(() => fail(new Error('Handshake timeout')), HANDSHAKE_TIMEOUT);
  const totalTimer = setTimeout(() => fail(new Error('Timeout')), TIMEOUT);
  socket.on('error', (err) => {
    if (!tcpConnected || TCP_DEAD_CODES.has(err.code)) err.tcpDead = true;
    fail(err);
  });
  try {
    return await Promise.race([failed, (async () => {
      await once(socket, 'connect');
      tcpConnected = true;
      clearTimeout(tcpTimer);
      await openTunnel(socket, type);
      secure = tls.connect({ socket, servername: TEST_HOST, rejectUnauthorized: type.startsWith('socks') });
      secure.on('error', (err) => fail(err));
      await once(secure, 'secureConnect');
      clearTimeout(handshakeTimer);
      secure.write(`GET / HTTP/1.0\r\nHost: ${TEST_HOST}\r\nAccept: */*\r\nConnection: close\r\n\r\n`);
      let response = '';
      for await (const chunk of secure) {
        response += chunk;
        const headerEnd = response.indexOf('\r\n\r\n');
        if (headerEnd !== -1) {
          // Stop on non-200 or as soon as the IP body line arrives (avoids
          // reading 64 KB captive portals and saves a FIN wait on working proxies).
          if (!/^HTTP\/1\.[01] 200/.test(response)) throw new Error(`Unexpected HTTP status: ${response.split('\r\n', 1)[0].slice(0, 60)}`);
          const body = response.slice(headerEnd + 4);
          if (body.includes('\n') || body.length >= 64) break;
        }
        if (response.length >= MAX_HTTP_RESPONSE_BYTES) break;
      }
      const headerEnd = response.indexOf('\r\n\r\n');
      if (headerEnd < 0) throw new Error('No HTTP response');
      return response.slice(headerEnd + 4).trim().split(/\s+/)[0];
    })()]);
  } finally {
    clearTimeout(tcpTimer);
    clearTimeout(handshakeTimer);
    clearTimeout(totalTimer);
    socket.destroy();
    if (secure) secure.destroy();
  }
}

async function testProxy(proxyObj, currentPublicIp) {
  const started = Date.now();
  const failure = (error, extra = {}) => ({ success: false, proxy: proxyObj.normalized, error: error.substring(0, 200), ...extra });
  try {
    const ip = await fetchThroughProxy(proxyObj);
    if (ip === currentPublicIp) return failure('Proxy resolves to client IP, not a working proxy');
    if (!isValidIp(ip)) return failure(`Invalid IP format received: ${ip}`);
    return { success: true, ip, proxy: proxyObj.normalized, latencyMs: Date.now() - started };
  } catch (err) {
    return failure(err.message || err.code || 'Unknown error', {
      tcpDead: Boolean(err.tcpDead),
      spokeHttp: Boolean(err.spokeHttp),
    });
  }
}

function getInitialResults() {
  return {
    socks5: { working: [], failedCount: 0 },
    socks4: { working: [], failedCount: 0 },
    http: { working: [], failedCount: 0 },
    https: { working: [], failedCount: 0 },
  };
}

function groupProxiesByType(dedupedProxies) {
  const proxiesByType = { socks5: [], socks4: [], http: [], https: [] };
  for (const obj of dedupedProxies) {
    if (proxiesByType[obj.type]) proxiesByType[obj.type].push(obj);
  }
  return proxiesByType;
}

// Compact cross-run failure backoff cache: { "host:port": [streak, nextCheckAt, lastSeenAt] }
function loadHealthCache() {
  try {
    return JSON.parse(fs.readFileSync(HEALTH_CACHE_PATH, 'utf8'));
  } catch (_) {
    return {};
  }
}

function saveHealthCache(health, now) {
  const pruned = {};
  for (const [hp, rec] of Object.entries(health)) {
    if (Array.isArray(rec) && now - (rec[2] || 0) <= HEALTH_PRUNE_AGE_MS) {
      pruned[hp] = rec;
    }
  }
  try {
    fs.mkdirSync(path.dirname(HEALTH_CACHE_PATH), { recursive: true });
    fs.writeFileSync(HEALTH_CACHE_PATH, JSON.stringify(pruned));
  } catch (_) {}
}

async function loadProxiesFromSource({ url, type }) {
  const proxies = [];
  const filePath = await downloadSource(url);
  if (!filePath) return { type, proxies, error: 'download failed' };

  let content;
  try {
    content = await readFile(filePath, 'utf8');
  } catch (readError) {
    return { type, proxies, error: readError.message };
  }

  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const conversion = convertSourceLine(lines[i], type, url);
    if (conversion.skip || conversion.error) continue;
    const norm = normalizeProxyLine(conversion.value, type);
    if (norm) proxies.push({ ...norm, source: url });
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
      const existing = dedupedMap.get(proxy.normalized);
      if (!existing) {
        proxy.sourceCount = 1;
        dedupedMap.set(proxy.normalized, proxy);
      } else {
        existing.sourceCount += 1;
      }
    }
  }

  const dedupedProxies = Array.from(dedupedMap.values());
  return {
    combinedCount,
    dedupedProxies,
    proxiesByType: groupProxiesByType(dedupedProxies),
  };
}

function csvEscape(value) {
  if (value === undefined || value === null) return '';
  const stringValue = String(value);
  return /[",\n]/.test(stringValue) ? `"${stringValue.replace(/"/g, '""')}"` : stringValue;
}

async function exportAllProxiesCsv(dedupedProxies = null) {
  if (!dedupedProxies) {
    const allSources = [
      ...socks5sources.map((url) => ({ url, type: 'socks5' })),
      ...socks4sources.map((url) => ({ url, type: 'socks4' })),
      ...httpSources.map((url) => ({ url, type: 'http' })),
      ...httpsSources.map((url) => ({ url, type: 'https' })),
    ];
    ({ dedupedProxies } = await loadAndNormalizeSources(allSources));
  }

  const counts = { socks5: 0, socks4: 0, http: 0, https: 0 };
  const rows = ['host,port,protocol,source'];
  for (const proxy of dedupedProxies) {
    const { host, port, type, source } = proxy;
    if (counts[type] !== undefined) counts[type] += 1;
    rows.push([csvEscape(host), csvEscape(port), csvEscape(type), csvEscape(source || '')].join(','));
  }

  const outputPath = path.join(__dirname, 'all_proxies.csv');
  fs.writeFileSync(outputPath, rows.join('\n'), 'utf8');
  return { outputPath, total: dedupedProxies.length, counts };
}

/**
 * Process proxies of one protocol with fixed CONCURRENCY, skipping TCP-dead
 * endpoints, reusing identical HTTP CONNECT results for HTTPS, and honoring
 * cross-run failure backoff.
 */
async function processProxiesWithQueue(proxyObjs, type, ctx) {
  const {
    currentResults, currentPublicIp, results, outputPath, outputDir,
    deadTcpHp, spokeHttpHp, httpResultByHp, workingHpRun, testedHpRun,
    health, now, forceFull,
  } = ctx;

  const workingSet = new Set(currentResults.working.map((p) => p.proxy));
  const proxiesToTest = [];
  let skippedDeadTcp = 0;
  let skippedBackoff = 0;
  let reusedHttp = 0;

  for (const candidate of proxyObjs) {
    if (workingSet.has(candidate.normalized)) continue;
    const hp = candidate.hostPort;

    // `http` and `https` execute the exact same CONNECT :443 + TLS probe.
    if (type === 'https' && httpResultByHp.has(hp)) {
      reusedHttp++;
      const prev = httpResultByHp.get(hp);
      if (prev.success) {
        const entry = { ...prev, proxy: candidate.normalized };
        currentResults.working.push(entry);
        workingSet.add(entry.proxy);
      } else {
        currentResults.failedCount++;
      }
      continue;
    }

    if (deadTcpHp.has(hp) || (type === 'socks4' && spokeHttpHp.has(hp))) {
      skippedDeadTcp++;
      currentResults.failedCount++;
      continue;
    }

    const rec = health[hp];
    if (!forceFull && rec && rec[0] > 0 && now < rec[1]) {
      skippedBackoff++;
      continue;
    }

    proxiesToTest.push(candidate);
  }

  // Test previously working proxies first, then multi-source candidates, then
  // brand-new endpoints — surfaces healthy proxies earliest.
  proxiesToTest.sort((a, b) => {
    const aWork = health[a.hostPort]?.[0] === 0 ? 1 : 0;
    const bWork = health[b.hostPort]?.[0] === 0 ? 1 : 0;
    if (aWork !== bWork) return bWork - aWork;
    return (b.sourceCount || 1) - (a.sourceCount || 1);
  });

  const total = proxiesToTest.length;
  const startTime = Date.now();
  const skipNote = [
    reusedHttp ? `${reusedHttp} reused-http` : '',
    skippedDeadTcp ? `${skippedDeadTcp} tcp-dead` : '',
    skippedBackoff ? `${skippedBackoff} backoff` : '',
  ].filter(Boolean).join(', ');

  if (total === 0) {
    console.log(`[${type}] 0 tested | ${currentResults.working.length} working${skipNote ? ` (skipped: ${skipNote})` : ''}`);
    return;
  }

  let index = 0;
  let finished = 0;
  let testedSinceSave = 0;
  const latencies = [];

  function persistIfNeeded(force = false) {
    if (!force && testedSinceSave < SAVE_INTERVAL) return;
    results[type] = currentResults;
    try {
      saveResults(results, outputPath);
      saveUniqueIpResults(results, outputDir);
    } catch (_) {}
    testedSinceSave = 0;
  }

  const workerCount = Math.min(CONCURRENCY, total);
  const isTTY = process.stdout.isTTY;
  if (!isTTY) {
    console.log(`[${type}] Testing ${total} proxies with ${workerCount} workers${skipNote ? ` (skipped: ${skipNote})` : ''}...`);
  }

  let lastPlainLog = Date.now();
  const progressInterval = setInterval(() => {
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(0);
    const rate = (finished / Math.max(elapsed, 1)).toFixed(1);
    const line = `[${type}] ${finished}/${total} tested | ${currentResults.working.length} working | ${currentResults.failedCount} failed | ${rate}/s | ${elapsed}s`;
    if (isTTY) {
      process.stdout.write(`\r${line}`);
    } else if (Date.now() - lastPlainLog >= 60000) {
      lastPlainLog = Date.now();
      console.log(line);
    }
  }, 2000);

  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      const currentIndex = index++;
      if (currentIndex >= total) break;

      const proxyObj = proxiesToTest[currentIndex];
      const hp = proxyObj.hostPort;
      testedHpRun.add(hp);
      try {
        const result = await testProxy(proxyObj, currentPublicIp);
        if (result.success) {
          if (!workingSet.has(result.proxy)) {
            currentResults.working.push(result);
            workingSet.add(result.proxy);
          }
          workingHpRun.add(hp);
          if (result.latencyMs) latencies.push(result.latencyMs);
        } else {
          currentResults.failedCount++;
          if (result.tcpDead) deadTcpHp.add(hp);
          if (result.spokeHttp) spokeHttpHp.add(hp);
        }
        if (type === 'http') httpResultByHp.set(hp, result);
      } catch (_) {
        currentResults.failedCount++;
      } finally {
        finished++;
        testedSinceSave++;
        persistIfNeeded();
      }
    }
  });

  await Promise.all(workers);
  clearInterval(progressInterval);
  persistIfNeeded(true);

  const sorted = latencies.slice().sort((a, b) => a - b);
  const avg = sorted.length ? (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(0) : '-';
  const med = sorted.length ? sorted[Math.floor(sorted.length / 2)] : '-';
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
  process.stdout.write(
    `${isTTY ? '\r' : ''}[${type}] ${finished}/${total} tested | ${currentResults.working.length} working | `
    + `${currentResults.failedCount} failed | ${elapsed}s | avg ${avg}ms med ${med}ms`
    + `${skipNote ? ` | skipped: ${skipNote}` : ''}\n`,
  );
}

async function detectProxies({ forceFull = false } = {}) {
  const outputDir = path.join(__dirname, 'outputs');
  const outputPath = path.join(outputDir, 'proxy_results.json');
  const startedAt = Date.now();

  let currentPublicIp;
  try {
    currentPublicIp = await getCurrentPublicIp();
    if (!isValidIp(currentPublicIp)) {
      console.log('[-] Could not determine current public IP. Abort.');
      return null;
    }
  } catch (_) {
    console.log('[-] Unable to continue without current public IP. Abort.');
    return null;
  }

  const results = getInitialResults();
  const allSources = [
    ...socks5sources.map((url) => ({ url, type: 'socks5' })),
    ...socks4sources.map((url) => ({ url, type: 'socks4' })),
    ...httpSources.map((url) => ({ url, type: 'http' })),
    ...httpsSources.map((url) => ({ url, type: 'https' })),
  ];

  const { combinedCount, dedupedProxies, proxiesByType } = await loadAndNormalizeSources(allSources);
  const uniqueHp = new Set(dedupedProxies.map((p) => p.hostPort));
  const typeCounts = Object.entries(proxiesByType).map(([t, arr]) => `${t}: ${arr.length}`).join(' | ');
  console.log(`[proxy-list] Loaded ${dedupedProxies.length} unique entries (${uniqueHp.size} unique host:port) from ${allSources.length} sources (${combinedCount} raw, ${typeCounts})`);

  const now = Date.now();
  const health = loadHealthCache();
  // Touch lastSeenAt for every currently listed host:port so active entries stay tracked
  for (const hp of uniqueHp) {
    if (health[hp]) health[hp][2] = now;
  }

  const deadTcpHp = new Set();
  const spokeHttpHp = new Set();
  const httpResultByHp = new Map();
  const workingHpRun = new Set();
  const testedHpRun = new Set();
  const full = forceFull || process.env.FORCE_FULL_CHECK === '1' || process.argv.includes('--full');

  for (const type of ['socks5', 'socks4', 'http', 'https']) {
    const proxyObjs = proxiesByType[type];
    if (!proxyObjs || proxyObjs.length === 0) continue;
    await processProxiesWithQueue(proxyObjs, type, {
      currentResults: results[type],
      currentPublicIp,
      results,
      outputPath,
      outputDir,
      deadTcpHp,
      spokeHttpHp,
      httpResultByHp,
      workingHpRun,
      testedHpRun,
      health,
      now,
      forceFull: full,
    });
  }

  // Update cross-run backoff cache. A proxy that worked on the previous run
  // gets one free retry on the next run before entering multi-day backoff, so
  // a single transient blip doesn't lock out a healthy proxy for 12h.
  const finishNow = Date.now();
  for (const hp of workingHpRun) {
    health[hp] = [0, 0, finishNow];
  }
  for (const hp of testedHpRun) {
    if (workingHpRun.has(hp)) continue;
    const prev = health[hp];
    const wasWorking = prev && prev[0] === 0;
    const prevStreak = prev?.[0] || 0;
    const streak = Math.min(prevStreak + 1, BACKOFF_MS.length - 1);
    const cooldown = (wasWorking && !deadTcpHp.has(hp)) ? 0 : BACKOFF_MS[streak];
    health[hp] = [streak, finishNow + cooldown, finishNow];
  }
  saveHealthCache(health, finishNow);

  saveResults(results, outputPath);
  saveUniqueIpResults(results, outputDir);

  const allLatencies = [];
  const counts = {};
  let totalFailed = 0;
  for (const type of ['socks5', 'socks4', 'http', 'https']) {
    const w = results[type].working;
    counts[type] = w.length;
    totalFailed += results[type].failedCount;
    for (const entry of w) {
      if (entry.latencyMs) allLatencies.push(entry.latencyMs);
    }
  }
  const totalWorking = counts.socks5 + counts.socks4 + counts.http + counts.https;
  const sorted = allLatencies.slice().sort((a, b) => a - b);
  const avg = sorted.length ? (sorted.reduce((a, b) => a + b, 0) / sorted.length).toFixed(0) : '-';
  const med = sorted.length ? sorted[Math.floor(sorted.length / 2)] : '-';
  const totalSec = ((Date.now() - startedAt) / 1000).toFixed(1);

  console.log(`\n[proxy-list] Done in ${totalSec}s: ${testedHpRun.size} endpoints probed, ${totalWorking} working (${workingHpRun.size} unique host:port), ${totalFailed} failed`);
  console.log(`[proxy-list] http: ${counts.http} | https: ${counts.https} | socks5: ${counts.socks5} | socks4: ${counts.socks4}`);
  console.log(`[proxy-list] Latency: avg ${avg}ms, median ${med}ms, min ${sorted[0] || '-'}ms, max ${sorted[sorted.length - 1] || '-'}ms`);

  return { results, dedupedProxies };
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
      if (fs.existsSync(locationPath)) _locationReader = new mmdb.Reader(fs.readFileSync(locationPath));
      if (fs.existsSync(location6Path)) _location6Reader = new mmdb.Reader(fs.readFileSync(location6Path));
    } catch (err) {
      console.error(`[proxy-list] Failed to load mmdb for country lookup: ${err.message}`);
      return null;
    }
  }
  try {
    const reader = ip.includes(':') ? _location6Reader : _locationReader;
    return reader ? (reader.get(ip)?.countryCode || null) : null;
  } catch {
    return null;
  }
}

function exportRankedProxiesForScrapeApi(results, verbose = true) {
  // scrapeapi.dev reads this as its proxy pool (src/config.js proxyPoolFile).
  const SCRAPEAPI_PROXY_FILE = path.join(__dirname, '..', 'scrapeapi.dev', 'data', 'ranked_proxies.json');
  const FREE_PROXY_LIST_FILE = path.join(__dirname, 'ranked_proxies.json');

  // Dedupe identical host:port across http/https so scrapeapi doesn't get twin entries
  const byKey = new Map();
  for (const type of ['http', 'https', 'socks5', 'socks4']) {
    for (const entry of results[type]?.working || []) {
      if (!entry.proxy || !entry.ip || !entry.latencyMs) continue;
      const parts = entry.proxy.match(/^(\w+):\/\/(.+):(\d+)$/);
      if (!parts) continue;
      const scheme = parts[1];
      const host = parts[2];
      const port = parseInt(parts[3], 10);
      const dedupeKey = `${scheme === 'https' ? 'http' : scheme}|${host}:${port}`;
      const existing = byKey.get(dedupeKey);
      if (!existing || entry.latencyMs < existing.latencyMs) {
        byKey.set(dedupeKey, {
          scheme,
          host,
          port,
          exitIp: entry.ip,
          exitCountry: getCountryCode(entry.ip),
          latencyMs: entry.latencyMs,
        });
      }
    }
  }

  const ranked = [...byKey.values()].sort((a, b) => a.latencyMs - b.latencyMs);
  const output = {
    generatedAt: new Date().toISOString(),
    count: ranked.length,
    proxies: ranked,
  };
  const payload = JSON.stringify(output, null, 2);

  try {
    fs.mkdirSync(path.dirname(SCRAPEAPI_PROXY_FILE), { recursive: true });
    fs.writeFileSync(SCRAPEAPI_PROXY_FILE, payload);
    if (verbose) console.log(`[proxy-list] Exported ${ranked.length} ranked proxies to ${SCRAPEAPI_PROXY_FILE}`);
  } catch (err) {
    console.error(`[proxy-list] Failed to write ranked proxies to scrapeapi: ${err.message}`);
  }

  try {
    fs.writeFileSync(FREE_PROXY_LIST_FILE, payload);
    if (verbose) console.log(`[proxy-list] Exported ${ranked.length} ranked proxies to ${FREE_PROXY_LIST_FILE}`);
  } catch (err) {
    console.error(`[proxy-list] Failed to write ranked proxies to free-proxy-list: ${err.message}`);
  }
}

async function updateFreeProxyList() {
  const outcome = await detectProxies();
  if (!outcome) {
    return { status: 'UPDATE_WARNING', message: 'Proxy detection aborted (no public IP?) — keeping previous proxy lists', error: null };
  }

  const { results, dedupedProxies } = outcome;
  writeWorkingProxiesToFiles(results);
  await exportAllProxiesCsv(dedupedProxies);
  exportRankedProxiesForScrapeApi(results);

  const totalWorking = ['socks5', 'socks4', 'http', 'https']
    .reduce((sum, type) => sum + ((results[type] && results[type].working.length) || 0), 0);

  try {
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
  if (process.argv.includes('updateFreeProxyList')) {
    await updateFreeProxyList();
    process.exit(0);
  } else if (process.argv.includes('detectOnly')) {
    const outcome = await detectProxies();
    if (outcome) {
      writeWorkingProxiesToFiles(outcome.results);
      await exportAllProxiesCsv(outcome.dedupedProxies);
      exportRankedProxiesForScrapeApi(outcome.results);
    }
    process.exit(0);
  } else if (process.argv.includes('testProxy')) {
    const currentPublicIp = await getCurrentPublicIp();
    const tests = [
      'https://13.234.24.116:1080',
      'https://35.90.245.227:3128',
    ];
    for (const test of tests) {
      const norm = normalizeProxyLine(test);
      if (norm) console.log(test, await testProxy(norm, currentPublicIp));
    }
  }
})();

module.exports = {
  updateFreeProxyList,
  detectProxies,
  exportAllProxiesCsv,
  exportRankedProxiesForScrapeApi,
};
