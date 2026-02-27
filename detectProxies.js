const fs = require('fs');
const path = require('path');
const { spawn, execSync } = require('child_process');
const { socks5sources, socks4sources, httpSources, httpsSources } = require('./proxySources.js');
const {
  downloadSource,
  getCurrentPublicIp,
  normalizeProxyLine,
  TIMEOUT,
  TEST_URL,
  CONCURRENCY,
  SAVE_INTERVAL,
  RESULTS_CACHE_DIR,
  saveResults,
  saveUniqueIpResults,
  writeWorkingProxiesToFiles,
  isValidIp,
  convertSourceLine
} = require('./helpers.js');

const { readFile, writeFile, stat } = fs.promises;

const CURL_ERROR_DESCRIPTIONS = {
  7: 'Failed to connect to proxy host',
  28: 'Operation timed out before completion',
  35: 'TLS handshake failed',
  60: 'Peer certificate could not be authenticated',
  97: 'HTTP/2 stream error during transfer'
};

const ERROR_HINTS = {
  Timeout: 'Proxy did not respond within the configured timeout',
  'Connection refused': 'Proxy host actively rejected the connection',
  'Connection reset': 'Remote peer reset the TCP connection',
  'TLS error': 'TLS negotiation failed with the proxy',
  'Socket disconnected': 'Underlying socket closed unexpectedly',
  'DNS lookup failed': 'Unable to resolve proxy hostname',
  'Proxy resolves to client IP': 'Proxy response returned our own IP address',
  'Proxy error': 'Proxy reported an error while handling the request',
  ECONNREFUSED: 'Connection refused by proxy host',
  'Invalid IP format': 'Proxy returned invalid IP data'
};

// Helper to run curl and capture both stdout and stderr
function runCurl(cmdArgs, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn('curl', cmdArgs, {});

    let stdout = '';
    let stderr = '';
    let finished = false;
    let timeoutHandle;

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });
    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    child.on('error', (err) => {
      if (!finished) {
        finished = true;
        clearTimeout(timeoutHandle);
        reject({ error: err, stdout, stderr });
      }
    });

    child.on('close', (code, signal) => {
      if (!finished) {
        finished = true;
        clearTimeout(timeoutHandle);
        if (code === 0) {
          resolve({ stdout: stdout.trim(), stderr: stderr.trim() });
        } else {
          reject({ error: new Error(`curl exited with code ${code}${signal ? `, signal ${signal}` : ''}`), stdout: stdout.trim(), stderr: stderr.trim() });
        }
      }
    });

    // Handle timeout manually
    timeoutHandle = setTimeout(() => {
      if (!finished) {
        finished = true;
        try {
          child.kill('SIGKILL');
        } catch (e) {
          // Ignore kill errors
        }
        reject({ error: new Error('Process timed out'), stdout: stdout.trim(), stderr: stderr.trim(), killed: true });
      }
    }, timeoutMs + 500);
  });
}

/**
 * Test a single proxy for functionality and anonymity.
 * @param {Object} proxyObj - Proxy object with type, host, port, normalized.
 * @param {string} currentPublicIp - The current public IP of the client.
 * @param {boolean} useCache - Whether to use cached results if available.
 * @returns {Promise<Object>} - Result object with success, proxy, ip/error.
 */
async function testProxy(proxyObj, currentPublicIp, useCache = true) {
  const { type, host, port, normalized } = proxyObj;
  const cacheKey = `${type}_${host}_${port}`.replace(/[^a-zA-Z0-9]/g, '_');
  const cachePath = path.join(RESULTS_CACHE_DIR, `${cacheKey}.json`);
  const CACHE_VALIDITY_MS = 18 * 60 * 60 * 1000; // 18 hours

  // Check cache first, but only if useCache is true and cache is fresh (less than 6 hours old)
  let cacheIsFresh = false;
  if (useCache) {
    try {
      const cacheStat = await stat(cachePath);
      if (Date.now() - cacheStat.mtimeMs < CACHE_VALIDITY_MS) {
        cacheIsFresh = true;
      }
    } catch (e) {
      cacheIsFresh = false;
    }
  }

  if (useCache && cacheIsFresh) {
    try {
      const cachedRaw = await readFile(cachePath, 'utf8');
      const cachedResult = JSON.parse(cachedRaw);
      // If cached result is a false positive (proxy resolves to our own IP), mark as failed
      if (cachedResult.success && cachedResult.ip === currentPublicIp) {
        const failResult = {
          success: false,
          proxy: normalized,
          error: "Proxy resolves to client IP, not a working proxy"
        };
        try {
          await writeFile(cachePath, JSON.stringify(failResult, null, 2));
        } catch (writeError) {
          // Ignore cache write errors
        }
        return failResult;
      }
      return cachedResult;
    } catch (error) {
      // Cache read error, continue with fresh test
    }
  }

  try {
    // Prepare curl command arguments based on proxy type
    let curlArgs = [`--max-time`, `${TIMEOUT / 1000}`, '--silent', '-4', '--connect-timeout', '5']; // Prefer IPv4, faster connection timeout
    if (type === 'socks5') {
      curlArgs.push('--socks5', `${host}:${port}`);
    } else if (type === 'socks4') {
      curlArgs.push('--socks4', `${host}:${port}`);
    } else if (type === 'http') {
      curlArgs.push('-x', `http://${host}:${port}`);
      curlArgs.push('-k');
    } else if (type === 'https') {
      curlArgs.push('-x', `http://${host}:${port}`);
      curlArgs.push('-k');
    }
    curlArgs.push(TEST_URL);

    const t0 = Date.now();
    const { stdout: response, stderr } = await runCurl(curlArgs, TIMEOUT);
    const latencyMs = Date.now() - t0;

    if (response) {
      const ip = response.trim();
      if (ip === currentPublicIp) {
        const failResult = {
          success: false,
          proxy: normalized,
          error: "Proxy resolves to client IP, not a working proxy",
          stderr: stderr ? stderr.substring(0, 200) : undefined
        };
        try {
          await writeFile(cachePath, JSON.stringify(failResult, null, 2));
        } catch (writeError) { }
        return failResult;
      }
      if (!isValidIp(ip)) {
        throw { error: new Error(`Invalid IP format received: ${ip}`), stdout: response, stderr };
      }
      const result = {
        success: true,
        ip,
        proxy: normalized,
        latencyMs,
        stderr: stderr ? stderr.substring(0, 200) : undefined
      };
      try {
        await writeFile(cachePath, JSON.stringify(result, null, 2));
      } catch (writeError) { }
      return result;
    } else {
      throw { error: new Error(`Request failed or returned invalid data. Response: ${response}`), stdout: response, stderr };
    }

  } catch (errObj) {
    let errorMessage = 'Unknown error';
    let stderr = '';
    if (errObj && typeof errObj === 'object') {
      if (errObj.error && errObj.error.message) errorMessage = errObj.error.message;
      if (errObj.stderr) stderr = errObj.stderr;
      if (errObj.killed) errorMessage = 'Process timed out';
    } else if (errObj && errObj.message) {
      errorMessage = errObj.message;
    }

    // Map common error codes/messages to user-friendly errors
    if (errObj && errObj.error && errObj.error.code === 'ECONNRESET') {
      errorMessage = 'Connection reset by peer';
    } else if (errObj && errObj.error && errObj.error.code === 'ETIMEDOUT') {
      errorMessage = `Timeout of ${TIMEOUT}ms exceeded`;
    } else if (errObj && errObj.error && errObj.error.code === 'ECONNREFUSED') {
      errorMessage = 'Connection refused';
    } else if (errObj && errObj.error && (errObj.error.code === 'ENOTFOUND' || errObj.error.code === 'EAI_AGAIN')) {
      errorMessage = 'DNS lookup failed';
    } else if (errObj && errObj.killed) {
      errorMessage = 'Process timed out';
    }

    const result = {
      success: false,
      proxy: normalized,
      error: errorMessage ? errorMessage.substring(0, 200) : 'Unknown error',
      stderr: stderr ? stderr.substring(0, 200) : undefined
    };

    try {
      await writeFile(cachePath, JSON.stringify(result, null, 2));
    } catch (writeError) {
      // Ignore cache write errors
    }
    return result;
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

/**
 * Log statistics for proxy testing, including error histogram.
 * Also logs how many proxies were already tested and how many still need to be processed.
 */
function formatErrorLabel(bucket) {
  if (!bucket || typeof bucket !== 'string') {
    return bucket;
  }

  const curlMatch = bucket.match(/curl exited with code (\d+)/);
  if (curlMatch) {
    const code = Number(curlMatch[1]);
    const detail = CURL_ERROR_DESCRIPTIONS[code];
    if (detail) {
      return `${bucket} – ${detail}`;
    }
    return `${bucket} – see curl exit code ${code}`;
  }

  const hintKey = ERROR_HINTS[bucket] ? bucket : bucket.split(':')[0];
  if (ERROR_HINTS[hintKey]) {
    return `${bucket} – ${ERROR_HINTS[hintKey]}`;
  }

  return bucket;
}

function logStats(stats, type, final = false) {
  // Only log final summary, not intermediate stats
  if (!final) return;

  const now = Date.now();
  const elapsed = Math.max((now - stats.startTime) / 1000, 0.001);
  const totalWorking = stats.totalWorking !== undefined ? stats.totalWorking : (stats.detected || 0);
  const totalFailed = stats.totalFailed !== undefined ? stats.totalFailed : (stats.failed || 0);
  const total = stats.total !== undefined ? stats.total : 0;
  const finishedPerSec = (stats.finished / elapsed).toFixed(1);

  console.log(`[${type}] Tested ${stats.finished}/${total} -> ${totalWorking} working, ${totalFailed} failed (${finishedPerSec}/sec)`);
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
 * Process proxies with a concurrency queue.
 * Tracks error histogram for failed proxies and persists progress regularly.
 */
async function processProxiesWithQueue(proxyObjs, type, currentResults, workingSet, failedSet, currentPublicIp, results, outputPath, outputDir) {
  let testedCountSinceSave = 0;
  const errorHistogram = {};
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
  const stats = {
    startTime: Date.now(),
    finished: 0,
    detected: 0,
    failed: 0,
    active: 0,
    errorHistogram,
    total,
    totalWorking: totalWorkingCount,
    totalFailed: totalFailedCount
  };

  if (total === 0) {
    // No new proxies to test, skip silently
    return;
  }

  let index = 0;
  let active = 0;
  let finished = 0;
  let detected = 0;
  let failed = 0;

  const LOG_INTERVAL_MS = 15000;

  function getErrorType(errorMsg) {
    if (!errorMsg) return 'Unknown error';
    const lowerMsg = errorMsg.toLowerCase();
    if (lowerMsg.includes('timeout')) return 'Timeout';
    if (lowerMsg.includes('connection refused')) return 'Connection refused';
    if (lowerMsg.includes('reset by peer')) return 'Connection reset';
    if (lowerMsg.includes('tls connection')) return 'TLS error';
    if (lowerMsg.includes('socket disconnected')) return 'Socket disconnected';
    if (lowerMsg.includes('dns lookup failed')) return 'DNS lookup failed';
    if (lowerMsg.includes('proxy resolves to client ip')) return 'Proxy resolves to client IP';
    if (lowerMsg.includes('proxy')) return 'Proxy error';
    if (lowerMsg.includes('econnrefused')) return 'ECONNREFUSED';
    if (lowerMsg.includes('invalid ip format received')) return 'Invalid IP format';
    return errorMsg.split(':')[0].trim().substring(0, 40);
  }

  function recordResult(result) {
    if (!result) return;

    if (result.success) {
      if (!workingSet.has(result.proxy)) {
        currentResults.working.push(result);
        workingSet.add(result.proxy);
        detected++;
        totalWorkingCount++;
      }
    } else {
      if (!failedSet.has(result.proxy)) {
        currentResults.failed.push(result);
        failedSet.add(result.proxy);
        failed++;
        totalFailedCount++;
        const errType = getErrorType(result.error);
        errorHistogram[errType] = (errorHistogram[errType] || 0) + 1;
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
      exportRankedProxiesForScrapeApi(results);
    } catch (saveError) {
      // ignore persistence errors
    }
    testedCountSinceSave = 0;
  }

  const latencies = [];

  const progressInterval = setInterval(() => {
    const elapsed = ((Date.now() - stats.startTime) / 1000).toFixed(0);
    const rate = (finished / Math.max(elapsed, 1)).toFixed(1);
    process.stdout.write(`\r[${type}] ${finished}/${total} tested | ${totalWorkingCount} working | ${totalFailedCount} failed | ${rate}/s | ${elapsed}s`);
  }, 2000);

  const workerCount = Math.min(CONCURRENCY, total);
  const workers = Array.from({ length: workerCount }, async () => {
    while (true) {
      const currentIndex = index++;
      if (currentIndex >= total) {
        break;
      }

      const proxyObj = proxiesToTest[currentIndex];
      active++;
      try {
        const result = await testProxy(proxyObj, currentPublicIp, false);
        recordResult(result);
        if (result.success && result.latencyMs) {
          latencies.push(result.latencyMs);
        }
      } catch (err) {
        recordInternalError(err, proxyObj);
      } finally {
        active--;
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
  const elapsed = ((Date.now() - stats.startTime) / 1000).toFixed(1);

  process.stdout.write(`\r[${type}] ${finished}/${total} tested | ${totalWorkingCount} working | ${totalFailedCount} failed | ${elapsed}s | avg ${avgLatency}ms med ${medianLatency}ms min ${minLatency}ms max ${maxLatency}ms\n`);
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

function exportRankedProxiesForScrapeApi(results) {
  const SCRAPEAPI_PROXY_FILE = path.join(__dirname, '..', 'scrapeapi.dev', 'ranked_proxies.json');

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
    fs.writeFileSync(SCRAPEAPI_PROXY_FILE, JSON.stringify(output, null, 2));
    console.log(`[proxy-list] Exported ${ranked.length} ranked proxies to ${SCRAPEAPI_PROXY_FILE}`);
  } catch (err) {
    console.error(`[proxy-list] Failed to write ranked proxies: ${err.message}`);
  }
}

async function updateFreeProxyList() {
  const results = await detectProxies();
  writeWorkingProxiesToFiles();
  await exportAllProxiesCsv();
  if (results) {
    exportRankedProxiesForScrapeApi(results);
  }

  try {
    execSync('git add . && git commit -m "auto commit (I am lazy)" && git push origin main', {
      cwd: __dirname,
      stdio: 'inherit',
      timeout: 30000,
    });
    console.log('[proxy-list] Repository pushed successfully');
  } catch (err) {
    console.error('[proxy-list] Git push failed:', err.message);
  }

  return { status: 'UPDATE_SUCCESS', message: 'Free proxy list updated successfully', error: null };
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
        const result = await testProxy(norm, currentPublicIp, false);
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
        const result = await testProxy(norm, currentPublicIp, false);
        console.log(`${test}: ${result.success ? 'SUCCESS' : 'FAILED'} - ${result.success ? result.ip : result.error}`);
      }
    }
  }
})();

module.exports = {
  updateFreeProxyList
};