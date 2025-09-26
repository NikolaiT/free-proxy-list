import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { socks5sources, socks4sources, httpSources, httpsSources } from './proxySources.js';
import {
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
  __filename,
  __dirname,
  writeWorkingProxiesToFiles,
  isValidIp
} from './helpers.js';

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
  if (useCache && fs.existsSync(cachePath)) {
    try {
      const stat = fs.statSync(cachePath);
      const now = Date.now();
      if (now - stat.mtimeMs < CACHE_VALIDITY_MS) {
        cacheIsFresh = true;
      }
    } catch (e) {
      // Cache stat error, treat as not fresh
      cacheIsFresh = false;
    }
  }

  if (useCache && cacheIsFresh) {
    try {
      const cachedResult = JSON.parse(fs.readFileSync(cachePath, 'utf8'));
      // If cached result is a false positive (proxy resolves to our own IP), mark as failed
      if (cachedResult.success && cachedResult.ip === currentPublicIp) {
        const failResult = {
          success: false,
          proxy: normalized,
          error: "Proxy resolves to client IP, not a working proxy"
        };
        try {
          fs.writeFileSync(cachePath, JSON.stringify(failResult, null, 2));
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
          fs.writeFileSync(cachePath, JSON.stringify(failResult, null, 2));
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
        fs.writeFileSync(cachePath, JSON.stringify(result, null, 2));
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
      fs.writeFileSync(cachePath, JSON.stringify(result, null, 2));
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
function logStats(stats, type) {
  const now = Date.now();
  const elapsed = (now - stats.startTime) / 1000;
  const finished = stats.finished;
  const detected = stats.detected;
  const failed = stats.failed;
  const concurrency = stats.active;
  const total = stats.total !== undefined ? stats.total : undefined;
  const finishedPerSec = (finished / elapsed).toFixed(2);
  const detectedPerSec = (detected / elapsed).toFixed(2);
  const failedPerSec = (failed / elapsed).toFixed(2);

  let testedMsg = '';
  if (typeof total === 'number') {
    const remaining = total - finished;
    testedMsg = ` | Tested: ${finished} / ${total} | Remaining: ${remaining}`;
  }
  console.log(`[${type}] [${new Date().toISOString()}] Concurrency: ${concurrency}, Finished: ${finished}, Working: ${detected}, Failed: ${failed}${testedMsg}`);
  console.log(`[${type}] Proxies/sec: Finished: ${finishedPerSec}, Working: ${detectedPerSec}, Failed: ${failedPerSec}`);

  // Print error histogram if available
  if (stats.errorHistogram) {
    const totalErrors = Object.values(stats.errorHistogram).reduce((a, b) => a + b, 0);
    if (totalErrors > 0) {
      console.log(`[${type}] Error distribution:`);
      for (const [errType, count] of Object.entries(stats.errorHistogram)) {
        console.log(`    ${errType}: ${count}`);
      }
    }
  }
}

/**
 * Process proxies with a concurrency queue.
 * Tracks error histogram for failed proxies.
 * Also tracks and logs how many proxies were already tested and how many still need to be processed.
 * 
 * FIX: Ensure the logInterval is cleared as soon as all proxies are finished, even if all are skipped (already tested).
 */
async function processProxiesWithQueue(proxyObjs, type, currentResults, workingSet, failedSet, currentPublicIp, results, outputPath, outputDir) {
  let testedCountSinceSave = 0;
  let nextIndex = 0;
  let active = 0;
  let finished = 0;
  let detected = 0;
  let failed = 0;
  const total = proxyObjs.length;
  const errorHistogram = {}; // Track error types

  const stats = {
    startTime: Date.now(),
    finished: 0,
    detected: 0,
    failed: 0,
    active: 0,
    errorHistogram,
    total // Add total to stats for logging
  };

  let resolvePromise;
  const promise = new Promise((resolve) => { resolvePromise = resolve; });

  const logInterval = setInterval(() => {
    stats.active = active;
    stats.finished = finished;
    stats.detected = detected;
    stats.failed = failed;
    stats.errorHistogram = errorHistogram;
    stats.total = total;
    logStats(stats, type);
  }, 15000); // Reduced frequency from 10s to 15s

  function getErrorType(errorMsg) {
    // Normalize error messages to a few buckets (optimized with early returns)
    if (!errorMsg) return 'Unknown error';

    const lowerMsg = errorMsg.toLowerCase();
    if (lowerMsg.includes('timeout')) return 'Timeout';
    if (lowerMsg.includes('connection refused')) return 'Connection refused';
    if (lowerMsg.includes('reset by peer')) return 'Connection reset';
    if (lowerMsg.includes('tls connection')) return 'TLS error';
    if (lowerMsg.includes('socket disconnected')) return 'Socket disconnected';
    if (lowerMsg.includes('dns lookup failed')) return 'DNS lookup failed';
    if (lowerMsg.includes('proxy')) return 'Proxy error';
    if (lowerMsg.includes('proxy resolves to client ip')) return 'Proxy resolves to client IP';
    if (lowerMsg.includes('econnrefused')) return 'ECONNREFUSED';
    if (lowerMsg.includes('invalid ip format received')) return 'Invalid IP format';

    return errorMsg.split(':')[0].trim().substring(0, 40); // fallback: first part of error
  }

  function onProxyTested(result, proxyObj) {
    if (result) {
      if (result.success) {
        if (!workingSet.has(result.proxy)) {
          currentResults.working.push(result);
          workingSet.add(result.proxy);
          detected++;
          // Working proxy found - reduce output verbosity
        }
      } else {
        if (!failedSet.has(result.proxy)) {
          currentResults.failed.push(result);
          failedSet.add(result.proxy);
          failed++;
          // Track error type
          const errType = getErrorType(result.error);
          errorHistogram[errType] = (errorHistogram[errType] || 0) + 1;
        }
      }
      testedCountSinceSave++;
    }
  }

  function onProxyTestError(err, proxyObj) {
    // Reduce error logging verbosity
    const errorResult = { success: false, proxy: proxyObj.normalized, error: `Internal test error: ${err.message}`.substring(0, 200) };
    if (!failedSet.has(proxyObj.normalized)) {
      currentResults.failed.push(errorResult);
      failedSet.add(proxyObj.normalized);
      failed++;
      // Track error type
      const errType = getErrorType(errorResult.error);
      errorHistogram[errType] = (errorHistogram[errType] || 0) + 1;
    }
    testedCountSinceSave++;
  }

  function onProxyTestFinally() {
    active--;
    finished++;
    if (testedCountSinceSave >= SAVE_INTERVAL) {
      results[type] = currentResults;
      try {
        saveResults(results, outputPath);
        saveUniqueIpResults(results, outputDir);
      } catch (saveError) {
        // Ignore save errors, continue processing
      }
      testedCountSinceSave = 0;
    }
    if (finished >= total) {
      results[type] = currentResults;
      clearInterval(logInterval);
      // Final log with error histogram
      stats.active = active;
      stats.finished = finished;
      stats.detected = detected;
      stats.failed = failed;
      stats.errorHistogram = errorHistogram;
      stats.total = total;
      logStats(stats, type);
      resolvePromise();
    } else {
      launchNext();
    }
  }

  function launchNext() {
    // If all proxies are already tested, immediately finish and clear logInterval
    if (nextIndex >= total && active === 0) {
      // This can happen if all proxies are already in workingSet/failedSet
      if (finished >= total) {
        clearInterval(logInterval);
        stats.active = active;
        stats.finished = finished;
        stats.detected = detected;
        stats.failed = failed;
        stats.errorHistogram = errorHistogram;
        stats.total = total;
        logStats(stats, type);
        resolvePromise();
      }
      return;
    }
    while (active < CONCURRENCY && nextIndex < total) {
      const proxyObj = proxyObjs[nextIndex++];
      if (workingSet.has(proxyObj.normalized) || failedSet.has(proxyObj.normalized)) {
        finished++;
        // If this was the last one, check for completion
        if (finished >= total && active === 0) {
          clearInterval(logInterval);
          stats.active = active;
          stats.finished = finished;
          stats.detected = detected;
          stats.failed = failed;
          stats.errorHistogram = errorHistogram;
          stats.total = total;
          logStats(stats, type);
          resolvePromise();
          return;
        }
        continue;
      }
      active++;
      testProxy(proxyObj, currentPublicIp)
        .then(result => onProxyTested(result, proxyObj))
        .catch(err => onProxyTestError(err, proxyObj))
        .finally(() => onProxyTestFinally());
    }
  }

  launchNext();
  return promise;
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

  let allProxyObjs = [];
  for (const { url, type } of allSources) {
    const filePath = await downloadSource(url);
    if (!filePath) continue;
    let content;
    try {
      content = fs.readFileSync(filePath, 'utf8');
    } catch (readError) {
      // Skip failed source file
      continue;
    }
    const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
    for (const line of lines) {
      const norm = normalizeProxyLine(line, type);
      if (norm) {
        allProxyObjs.push(norm);
      }
    }
    // Reduced logging verbosity
  }

  // Deduplicate proxies by normalized string (more efficient)
  const dedupedMap = new Map();
  for (const obj of allProxyObjs) {
    dedupedMap.set(obj.normalized, obj); // Map.set() overwrites duplicates automatically
  }
  const dedupedProxies = Array.from(dedupedMap.values());
  console.log(`[+] Total unique proxies: ${dedupedProxies.length}`);

  const proxiesByType = groupProxiesByType(dedupedProxies);

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