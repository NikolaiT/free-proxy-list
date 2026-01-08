const fs = require('fs');
const path = require('path');
const { spawn } = require('child_process');
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

    const { stdout: response, stderr } = await runCurl(curlArgs, TIMEOUT);

    // Check if response is a valid IP address (IPv4 or IPv6)
    if (response) {
      const ip = response.trim();
      // If proxy resolves to our own IP, it's not a working proxy
      if (ip === currentPublicIp) {
        const failResult = {
          success: false,
          proxy: normalized,
          error: "Proxy resolves to client IP, not a working proxy",
          stderr: stderr ? stderr.substring(0, 200) : undefined
        };
        try {
          await writeFile(cachePath, JSON.stringify(failResult, null, 2));
        } catch (writeError) {
          // Ignore cache write errors
        }
        return failResult;
      }
      if (!isValidIp(ip)) {
        // Not a valid IP, treat as error
        throw { error: new Error(`Invalid IP format received: ${ip}`), stdout: response, stderr };
      }
      const result = {
        success: true,
        ip,
        proxy: normalized,
        stderr: stderr ? stderr.substring(0, 200) : undefined
      };
      try {
        await writeFile(cachePath, JSON.stringify(result, null, 2));
      } catch (writeError) {
        // Ignore cache write errors
      }
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

function logStats(stats, type) {
  const now = Date.now();
  const elapsed = Math.max((now - stats.startTime) / 1000, 0.001);
  const finished = stats.finished;
  const newWorking = stats.detected || 0;
  const newFailed = stats.failed || 0;
  const totalWorking = stats.totalWorking !== undefined ? stats.totalWorking : newWorking;
  const totalFailed = stats.totalFailed !== undefined ? stats.totalFailed : newFailed;
  const concurrency = stats.active;
  const total = stats.total !== undefined ? stats.total : undefined;
  const finishedPerSec = (finished / elapsed).toFixed(2);
  const workingPerSec = (newWorking / elapsed).toFixed(2);
  const failedPerSec = (newFailed / elapsed).toFixed(2);

  const workingDisplay = newWorking > 0 ? `${totalWorking} (+${newWorking})` : `${totalWorking}`;
  const failedDisplay = newFailed > 0 ? `${totalFailed} (+${newFailed})` : `${totalFailed}`;

  let testedMsg = '';
  if (typeof total === 'number') {
    const remaining = Math.max(total - finished, 0);
    testedMsg = ` | Tested: ${finished} / ${total} | Remaining: ${remaining}`;
  }

  const timestamp = new Date().toISOString();
  console.log(`[${type}] [${timestamp}] Concurrency: ${concurrency}, Finished: ${finished}, Working: ${workingDisplay}, Failed: ${failedDisplay}${testedMsg}`);
  console.log(`[${type}] Proxies/sec: Finished: ${finishedPerSec}, Working: ${workingPerSec}, Failed: ${failedPerSec}`);

  if (stats.errorHistogram) {
    const totalErrors = Object.values(stats.errorHistogram).reduce((a, b) => a + b, 0);
    if (totalErrors > 0) {
      console.log(`[${type}] Error distribution:`);
      for (const [errType, count] of Object.entries(stats.errorHistogram)) {
        console.log(`    ${formatErrorLabel(errType)}: ${count}`);
      }
    }
  }
}

async function loadProxiesFromSource({ url, type }) {
  const filename = path.basename(url);
  const proxies = [];

  const filePath = await downloadSource(url);
  if (!filePath) {
    console.warn(`[-] Failed to download ${url}`);
    return { type, proxies };
  }

  let content;
  try {
    content = await readFile(filePath, 'utf8');
  } catch (readError) {
    console.warn(`[-] Failed to read ${filePath}: ${readError.message}`);
    return { type, proxies };
  }

  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const conversion = convertSourceLine(lines[i], type, url);
    if (conversion.skip) {
      continue;
    }
    if (conversion.error) {
      const offendingLine = conversion.raw || lines[i].trim();
      console.warn(`[-] Skipped invalid entry from ${filename}:${i + 1} (${type}) -> ${conversion.error}. Line: ${offendingLine}`);
      continue;
    }
    const norm = normalizeProxyLine(conversion.value, type);
    if (norm) {
      proxies.push({ ...norm, source: url });
    }
  }

  console.log(`[+] ${filename} (${type}) -> ${proxies.length} candidates`);
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

  console.log(`[+] Wrote ${dedupedProxies.length} unique proxies to ${outputPath}`);
  for (const [type, count] of Object.entries(counts)) {
    console.log(`    ${type}: ${count}`);
  }

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

  if (alreadyKnown > 0) {
    console.log(`[${type}] Skipping ${alreadyKnown} proxies already tested.`);
  }

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
    stats.totalWorking = totalWorkingCount;
    stats.totalFailed = totalFailedCount;
    logStats(stats, type);
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

        // Extract IP, port, and type from the proxy result
        const proxyParts = result.proxy.split('://');
        const protocol = proxyParts[0];
        const hostPort = proxyParts[1];
        const [ip, port] = hostPort.split(':');

        // Print colorful message for found proxy
        console.log(`\x1b[32m+++ found proxy:\x1b[0m \x1b[33m${ip}\x1b[0m, \x1b[33m${port}\x1b[0m, \x1b[36m${protocol}\x1b[0m`);
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
    } catch (saveError) {
      // ignore persistence errors
    }
    testedCountSinceSave = 0;
  }

  const logInterval = setInterval(() => {
    stats.active = active;
    stats.finished = finished;
    stats.detected = detected;
    stats.failed = failed;
    stats.errorHistogram = errorHistogram;
    stats.totalWorking = totalWorkingCount;
    stats.totalFailed = totalFailedCount;
    logStats(stats, type);
  }, LOG_INTERVAL_MS);

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
        const result = await testProxy(proxyObj, currentPublicIp);
        recordResult(result);
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

  clearInterval(logInterval);
  persistIfNeeded(true);
  stats.active = active;
  stats.finished = finished;
  stats.detected = detected;
  stats.failed = failed;
  stats.errorHistogram = errorHistogram;
  stats.totalWorking = totalWorkingCount;
  stats.totalFailed = totalFailedCount;
  logStats(stats, type);
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
      console.log(`[-] Could not determine current public IP: Invalid IP format received: ${currentPublicIp}`);
      console.log('[-] Unable to continue without current public IP. Abort.');
      return;
    }
    console.log(`[+] Public IP: ${currentPublicIp}`);
  } catch (err) {
    if (err && err.message && err.message.startsWith('Invalid IP format received:')) {
      console.log(`[-] Could not determine current public IP: ${err.message}`);
    } else {
      console.log('[-] Unable to continue without current public IP. Abort.');
    }
    return;
  }

  // Load previous results if available
  if (fs.existsSync(outputPath)) {
    try {
      results = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
      console.log(`[+] Loaded existing results`);
      results.socks5 = results.socks5 || { working: [], failed: [] };
      results.socks4 = results.socks4 || { working: [], failed: [] };
      results.http = results.http || { working: [], failed: [] };
      results.https = results.https || { working: [], failed: [] };
    } catch (error) {
      console.log(`[-] Starting fresh results`);
      results = getInitialResults();
    }
  } else {
    results = getInitialResults();
  }

  // Gather all proxy sources
  const allSources = [
    ...socks5sources.map(url => ({ url, type: 'socks5' })),
    ...socks4sources.map(url => ({ url, type: 'socks4' })),
    ...httpSources.map(url => ({ url, type: 'http' })),
    ...httpsSources.map(url => ({ url, type: 'https' })),
  ];

  const { combinedCount, dedupedProxies, proxiesByType } = await loadAndNormalizeSources(allSources);
  console.log(`[+] Loaded ${combinedCount} proxy entries, ${dedupedProxies.length} unique after normalization.`);

  // Process proxies by type
  for (const type of ['socks5', 'socks4', 'http', 'https']) {
    const proxyObjs = proxiesByType[type];
    if (!proxyObjs || proxyObjs.length === 0) continue;

    const currentResults = results[type] || { working: [], failed: [] };
    const workingSet = new Set(currentResults.working.map(p => p.proxy));
    const failedSet = new Set(currentResults.failed.map(p => p.proxy));

    console.log(`[+] Processing ${proxyObjs.length} ${type} proxies...`);
    await processProxiesWithQueue(proxyObjs, type, currentResults, workingSet, failedSet, currentPublicIp, results, outputPath, outputDir);
    console.log(`[+] ${type} proxies completed.`);
    results[type] = currentResults;
  }

  saveResults(results, outputPath);
  saveUniqueIpResults(results, outputDir);
  console.log(`[+] Detection completed. Results saved to ${outputPath}`);
  console.log(`    SOCKS5: ${results.socks5.working.length} working, SOCKS4: ${results.socks4.working.length} working, HTTP: ${results.http.working.length} working, HTTPS: ${results.https.working.length} working`);
  return results;
}

async function updateFreeProxyList() {
  await detectProxies();
  console.log('[+] Proxy detection completed. Writing working proxies to files and exporting all proxies to CSV.');
  writeWorkingProxiesToFiles();
  exportAllProxiesCsv();
  console.log('[+] All completed.');
  return { status: 'UPDATE_SUCCESS', message: 'Free proxy list updated successfully', error: null };
}

(async () => {
  // CLI entrypoints
  if (process.argv.includes('writeWorkingProxiesToFiles')) {
    writeWorkingProxiesToFiles();
    process.exit(0);
  } else if (process.argv.includes('detectProxies')) {
    try {
      const results = await detectProxies();
      console.log('[+] Proxy detection completed.');
      process.exit(0);
    } catch (error) {
      console.error('[-] Critical error in proxy detection process:', error);
      process.exit(1);
    }
  } else if (process.argv.includes('exportAllProxies')) {
    try {
      await exportAllProxiesCsv();
      console.log('[+] Proxy export completed.');
      process.exit(0);
    } catch (error) {
      console.error('[-] Failed to export proxies:', error);
      process.exit(1);
    }
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
  } else if (process.argv.includes('isValidIp')) {
    console.log(isValidIp('2a01:4f8:1c1a:b453::1'));
    const myIp = await getCurrentPublicIp();
    console.log(isValidIp(myIp), myIp);
  }
})();

module.exports = {
  updateFreeProxyList
};