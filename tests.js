async function run() {
  try {
    const { validateNormalizeProxyLine } = await import('./helpers.js');
    const summary = await validateNormalizeProxyLine({ verbose: true });

    if (summary.failures.length > 0) {
      console.error(`[-] Found ${summary.failures.length} normalization issues across proxy sources.`);
      process.exitCode = 1;
    } else {
      console.log('[+] All proxy sources normalized successfully.');
    }
  } catch (error) {
    console.error(`[-] normalizeProxyLine validation encountered an error: ${error.message}`);
    process.exitCode = 1;
  }
}

run();
