// ClassiGuard CyFence Standalone Zero-Dependency Executable Bundle
// Generated: 2026-10-24T16:26:46.449Z

const fs = require('node:fs/promises');
const path = require('node:path');
const http = require('node:http');
const readline = require('node:readline');


// --- Start: src/utils/scoring.mjs ---
/**
 * Scoring and metrics computation for SentinelAudit
 */

const SEVERITY = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
  PASS: 'PASS'
};

const SEVERITY_WEIGHTS = {
  [SEVERITY.CRITICAL]: 25,
  [SEVERITY.HIGH]: 15,
  [SEVERITY.MEDIUM]: 8,
  [SEVERITY.LOW]: 3,
  [SEVERITY.INFO]: 0
};

/**
 * Calculates aggregate compliance score and metrics from auditor findings
 * @param {Array<object>} findings - List of findings produced by auditors
 * @returns {object} Calculated scores, grade, and summary counts
 */
function calculateCompliance(findings) {
  const counts = {
    total: findings.length,
    passed: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };

  let penalty = 0;

  for (const f of findings) {
    const sev = f.severity?.toUpperCase();
    if (sev === SEVERITY.PASS) {
      counts.passed++;
    } else if (sev === SEVERITY.CRITICAL) {
      counts.critical++;
      penalty += SEVERITY_WEIGHTS[SEVERITY.CRITICAL];
    } else if (sev === SEVERITY.HIGH) {
      counts.high++;
      penalty += SEVERITY_WEIGHTS[SEVERITY.HIGH];
    } else if (sev === SEVERITY.MEDIUM) {
      counts.medium++;
      penalty += SEVERITY_WEIGHTS[SEVERITY.MEDIUM];
    } else if (sev === SEVERITY.LOW) {
      counts.low++;
      penalty += SEVERITY_WEIGHTS[SEVERITY.LOW];
    } else {
      counts.info++;
    }
  }

  const score = Math.max(0, Math.min(100, 100 - penalty));

  let grade = 'F';
  if (score >= 90) grade = 'A';
  else if (score >= 75) grade = 'B';
  else if (score >= 60) grade = 'C';
  else if (score >= 40) grade = 'D';

  return {
    score,
    grade,
    counts,
    totalDefects: counts.critical + counts.high + counts.medium + counts.low
  };
}

// --- End: src/utils/scoring.mjs ---


// --- Start: src/utils/http.mjs ---
/**
 * Safe HTTP Client utility using native Node fetch
 * Hardened against SSRF to cloud metadata endpoints, invalid URL schemes, and OOM buffer exhaustion
 */

/**
 * Cloud metadata endpoints strictly blocked by default to prevent SSRF
 */
const CLOUD_METADATA_HOSTS = new Set([
  '169.254.169.254',
  'metadata.google.internal',
  '100.100.100.200',
  'fd00:ec2::254'
]);

/**
 * Fetch a target URL with configurable options and error handling
 * @param {string} url - Target URL to probe
 * @param {object} options - Fetch options (headers, method, timeout, etc.)
 * @returns {Promise<{response: Response, rawHeaders: Record<string, string>, cookies: string[], bodySnippet: string, error?: string, status: number, statusText: string, url: string}>}
 */
async function safeFetch(url, options = {}) {
  // 1. Strict Protocol & Scheme Validation
  let parsedUrl;
  try {
    parsedUrl = new URL(url);
    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return {
        error: `Invalid URL protocol: '${parsedUrl.protocol}'. Only http: and https: are permitted.`,
        status: 0,
        statusText: 'Invalid Protocol',
        url,
        rawHeaders: {},
        cookies: [],
        bodySnippet: ''
      };
    }
  } catch (err) {
    return {
      error: `Malformed target URL: ${err.message}`,
      status: 0,
      statusText: 'Malformed URL',
      url,
      rawHeaders: {},
      cookies: [],
      bodySnippet: ''
    };
  }

  // 2. Cloud Metadata SSRF Protection
  const hostname = parsedUrl.hostname.toLowerCase();
  if (!options.allowMetadata && CLOUD_METADATA_HOSTS.has(hostname)) {
    return {
      error: `SSRF Guard: Probing cloud metadata address '${hostname}' is prohibited.`,
      status: 0,
      statusText: 'Blocked SSRF',
      url,
      rawHeaders: {},
      cookies: [],
      bodySnippet: ''
    };
  }

  const timeoutMs = options.timeout || 8000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  const defaultHeaders = {
    'User-Agent': 'ClassiGuard-CyFence/1.0 (+https://github.com/classiguard/cyfence; OWASP-ASVS-Auditor)',
    'Accept': '*/*',
    ...(options.headers || {})
  };

  try {
    const res = await fetch(url, {
      method: options.method || 'GET',
      headers: defaultHeaders,
      signal: controller.signal,
      redirect: options.redirect || 'manual', // do not auto-follow redirects so we inspect initial headers
      ...options
    });

    clearTimeout(timeoutId);

    // Extract headers into a clean lowercase map
    const rawHeaders = {};
    for (const [key, value] of res.headers.entries()) {
      rawHeaders[key.toLowerCase()] = value;
    }

    // Extract Set-Cookie headers properly (can be multiple)
    let cookies = [];
    if (typeof res.headers.getSetCookie === 'function') {
      cookies = res.headers.getSetCookie();
    } else {
      const setCookie = res.headers.get('set-cookie');
      if (setCookie) cookies = [setCookie];
    }

    // 3. Memory-Safe Chunked Stream Reader (Prevents Heap OOM on huge bodies / zip bombs)
    let bodySnippet = '';
    const contentType = rawHeaders['content-type'] || '';
    if (contentType.includes('text') || contentType.includes('json') || contentType.includes('html') || contentType.includes('xml')) {
      try {
        if (res.body && typeof res.body.getReader === 'function') {
          const reader = res.body.getReader();
          const decoder = new TextDecoder('utf-8');
          let bytesAccumulated = 0;
          const maxBytes = 4096;
          let textAcc = '';

          while (bytesAccumulated < maxBytes) {
            const { done, value } = await reader.read();
            if (done) break;
            bytesAccumulated += value.byteLength;
            textAcc += decoder.decode(value, { stream: !done });
          }
          try { await reader.cancel(); } catch { /* ignore cancel errors */ }
          bodySnippet = textAcc.slice(0, 4096);
        } else {
          const text = await res.text();
          bodySnippet = text.slice(0, 4096);
        }
      } catch {
        bodySnippet = '';
      }
    }

    return {
      status: res.status,
      statusText: res.statusText,
      url: res.url,
      rawHeaders,
      cookies,
      bodySnippet,
      response: res
    };
  } catch (err) {
    clearTimeout(timeoutId);
    return {
      error: err.name === 'AbortError' ? `Request timed out after ${timeoutMs}ms` : err.message,
      status: 0,
      statusText: 'Error',
      url,
      rawHeaders: {},
      cookies: [],
      bodySnippet: ''
    };
  }
}

// --- End: src/utils/http.mjs ---


// --- Start: src/utils/config.mjs ---
/**
 * Configuration File Loader (cyfence.config.json)
 */




/**
 * Loads and parses a JSON configuration file if present
 * @param {string} [configPath='cyfence.config.json'] - Path to configuration file
 * @returns {Promise<object>} Parsed configuration or empty object if not found
 */
async function loadConfigFile(configPath = 'cyfence.config.json') {
  try {
    const resolvedPath = path.resolve(configPath);
    const content = await fs.readFile(resolvedPath, 'utf8');
    const parsed = JSON.parse(content);
    return parsed;
  } catch {
    // If default file doesn't exist, return empty object
    return {};
  }
}

// --- End: src/utils/config.mjs ---


// --- Start: src/auditors/headers.mjs ---
/**
 * HTTP Security Headers Auditor
 * Aligned with OWASP ASVS v4.0 Chapter 14 (Configuration) & OWASP Secure Headers Project
 */



/**
 * Audits HTTP response headers for defensive security posture
 * @param {string} targetUrl - Target URL probed
 * @param {Record<string, string>} headers - Normalized response headers map
 * @returns {Array<object>} List of findings
 */
function auditHeaders(targetUrl, headers) {
  const findings = [];
  const isHttps = targetUrl.startsWith('https://');

  // 1. Strict-Transport-Security (HSTS) - ASVS V14.1.1, CWE-319
  const hsts = headers['strict-transport-security'];
  if (isHttps) {
    if (!hsts) {
      findings.push({
        id: 'SEC-HDR-01',
        title: 'Missing HTTP Strict Transport Security (HSTS)',
        standard: 'OWASP ASVS V14.1.1',
        cwe: 'CWE-319: Cleartext Transmission of Sensitive Information',
        severity: SEVERITY.HIGH,
        details: 'The HSTS header was not returned over HTTPS. Browsers will not enforce encrypted connections for subsequent visits.',
        remediation: 'Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to all HTTPS responses.'
      });
    } else {
      const maxAgeMatch = hsts.match(/max-age=(\d+)/i);
      const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
      if (maxAge < 15552000) {
        findings.push({
          id: 'SEC-HDR-01-WEAK',
          title: 'HSTS max-age duration is insufficient (< 180 days)',
          standard: 'OWASP ASVS V14.1.1',
          cwe: 'CWE-319',
          severity: SEVERITY.LOW,
          details: `Current max-age is ${maxAge} seconds. OWASP recommends at least 31536000 seconds (1 year).`,
          remediation: 'Increase `max-age` to at least 31536000 and ensure `includeSubDomains` is present.'
        });
      } else {
        findings.push({
          id: 'SEC-HDR-01-PASS',
          title: 'HSTS properly configured',
          standard: 'OWASP ASVS V14.1.1',
          severity: SEVERITY.PASS,
          details: `HSTS enforced with max-age=${maxAge}.`
        });
      }
    }
  }

  // 2. Content-Security-Policy (CSP) - ASVS V14.4.1, V14.4.2, CWE-79, CWE-1021
  const csp = headers['content-security-policy'];
  if (!csp) {
    findings.push({
      id: 'SEC-HDR-02',
      title: 'Missing Content-Security-Policy (CSP)',
      standard: 'OWASP ASVS V14.4.1',
      cwe: 'CWE-79: Cross-Site Scripting (XSS), CWE-1021: Clickjacking',
      severity: SEVERITY.HIGH,
      details: 'No Content-Security-Policy header detected. The browser lacks directive restrictions on resource loading and script execution.',
      remediation: "Implement a baseline CSP, e.g.: `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';`"
    });
  } else {
    // Check for unsafe CSP directives
    const unsafeIssues = [];
    if (csp.includes("'unsafe-inline'") && !csp.includes('nonce-') && !csp.includes('sha256-')) {
      unsafeIssues.push("contains `'unsafe-inline'` without nonces or hashes");
    }
    if (csp.includes("'unsafe-eval'")) {
      unsafeIssues.push("contains `'unsafe-eval'` allowing dynamic code execution");
    }
    if (!csp.includes('object-src')) {
      unsafeIssues.push("missing `object-src` (allowing plugin execution)");
    }
    if (!csp.includes('base-uri')) {
      unsafeIssues.push("missing `base-uri` (susceptible to base-tag hijacking)");
    }

    if (unsafeIssues.length > 0) {
      findings.push({
        id: 'SEC-HDR-02-WEAK',
        title: 'Content-Security-Policy has weak or permissive directives',
        standard: 'OWASP ASVS V14.4.2',
        cwe: 'CWE-16: Configuration',
        severity: SEVERITY.MEDIUM,
        details: `CSP weaknesses detected: ${unsafeIssues.join('; ')}.`,
        remediation: "Harden CSP by removing 'unsafe-inline' and 'unsafe-eval', adopting cryptographic nonces for necessary scripts, and setting `object-src 'none'`."
      });
    } else {
      findings.push({
        id: 'SEC-HDR-02-PASS',
        title: 'Content-Security-Policy is present and configured',
        standard: 'OWASP ASVS V14.4.1',
        severity: SEVERITY.PASS,
        details: 'CSP header detected with restrictive baseline directives.'
      });
    }
  }

  // 3. X-Frame-Options - ASVS V14.4.3, CWE-1021
  const xfo = headers['x-frame-options'];
  const hasFrameAncestors = csp && csp.includes('frame-ancestors');
  if (!xfo && !hasFrameAncestors) {
    findings.push({
      id: 'SEC-HDR-03',
      title: 'Missing Clickjacking Defense (X-Frame-Options or CSP frame-ancestors)',
      standard: 'OWASP ASVS V14.4.3',
      cwe: 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
      severity: SEVERITY.MEDIUM,
      details: 'The web page can be embedded inside an iframe on malicious origins, facilitating UI redressing / clickjacking.',
      remediation: "Set `X-Frame-Options: DENY` (or `SAMEORIGIN`) and configure `frame-ancestors 'none'` in CSP."
    });
  } else {
    findings.push({
      id: 'SEC-HDR-03-PASS',
      title: 'Clickjacking protections verified',
      standard: 'OWASP ASVS V14.4.3',
      severity: SEVERITY.PASS,
      details: xfo ? `X-Frame-Options set to ${xfo}.` : 'CSP frame-ancestors directive configured.'
    });
  }

  // 4. X-Content-Type-Options - ASVS V14.4.4, CWE-16
  const xcto = headers['x-content-type-options'];
  if (!xcto || xcto.toLowerCase() !== 'nosniff') {
    findings.push({
      id: 'SEC-HDR-04',
      title: 'Missing or Invalid X-Content-Type-Options',
      standard: 'OWASP ASVS V14.4.4',
      cwe: 'CWE-16: Configuration, CWE-79: Cross-Site Scripting',
      severity: SEVERITY.LOW,
      details: 'MIME-type sniffing is not disabled. Browsers may interpret non-executable MIME types as executable JavaScript or CSS.',
      remediation: 'Send `X-Content-Type-Options: nosniff` on all HTTP responses.'
    });
  } else {
    findings.push({
      id: 'SEC-HDR-04-PASS',
      title: 'MIME-type sniffing protection active',
      standard: 'OWASP ASVS V14.4.4',
      severity: SEVERITY.PASS,
      details: 'X-Content-Type-Options is correctly set to `nosniff`.'
    });
  }

  // 5. Referrer-Policy - ASVS V14.4.5, CWE-200
  const refPol = headers['referrer-policy'];
  const secureReferrers = ['no-referrer', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade', 'same-origin', 'strict-origin'];
  if (!refPol || !secureReferrers.includes(refPol.toLowerCase())) {
    findings.push({
      id: 'SEC-HDR-05',
      title: 'Missing or Permissive Referrer-Policy',
      standard: 'OWASP ASVS V14.4.5',
      cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
      severity: SEVERITY.LOW,
      details: refPol ? `Current Referrer-Policy (${refPol}) may leak URL paths or tokens.` : 'Referrer-Policy header missing; browser defaults may expose sensitive query parameters across cross-origin links.',
      remediation: 'Specify `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer`.'
    });
  } else {
    findings.push({
      id: 'SEC-HDR-05-PASS',
      title: 'Referrer-Policy configured securely',
      standard: 'OWASP ASVS V14.4.5',
      severity: SEVERITY.PASS,
      details: `Referrer-Policy set to ${refPol}.`
    });
  }

  // 6. Permissions-Policy - ASVS V14.4.6, CWE-16
  const permPol = headers['permissions-policy'];
  if (!permPol) {
    findings.push({
      id: 'SEC-HDR-06',
      title: 'Missing Permissions-Policy Header',
      standard: 'OWASP ASVS V14.4.6',
      cwe: 'CWE-16: Configuration',
      severity: SEVERITY.LOW,
      details: 'Browser features (geolocation, camera, microphone, payment APIs) are not explicitly restricted.',
      remediation: 'Configure `Permissions-Policy: camera=(), microphone=(), geolocation=()` to restrict unneeded browser hardware capabilities.'
    });
  } else {
    findings.push({
      id: 'SEC-HDR-06-PASS',
      title: 'Permissions-Policy configured',
      standard: 'OWASP ASVS V14.4.6',
      severity: SEVERITY.PASS,
      details: 'Browser features explicitly restricted via Permissions-Policy.'
    });
  }

  return findings;
}

// --- End: src/auditors/headers.mjs ---


// --- Start: src/auditors/cookies.mjs ---
/**
 * Cookie Security & Session Management Auditor
 * Aligned with OWASP ASVS v4.0 Chapter 3 (Session Management) & OWASP WSTG-SESS-02
 */



/**
 * Parses a raw Set-Cookie header string into a structured attribute object
 * @param {string} cookieStr - Raw Set-Cookie header value
 * @returns {object} Parsed cookie name, value, and attributes
 */
function parseCookie(cookieStr) {
  const parts = cookieStr.split(';').map(p => p.trim());
  const [nameValue, ...attrParts] = parts;
  const equalsIdx = nameValue.indexOf('=');
  const name = equalsIdx > -1 ? nameValue.slice(0, equalsIdx) : nameValue;
  const value = equalsIdx > -1 ? nameValue.slice(equalsIdx + 1) : '';

  const attributes = {
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    maxAge: null,
    expires: null
  };

  for (const attr of attrParts) {
    const [attrKey, ...valParts] = attr.split('=');
    const key = attrKey.toLowerCase().trim();
    const val = valParts.join('=').trim();

    if (key === 'secure') attributes.secure = true;
    else if (key === 'httponly') attributes.httpOnly = true;
    else if (key === 'samesite') attributes.sameSite = val.toLowerCase();
    else if (key === 'domain') attributes.domain = val;
    else if (key === 'path') attributes.path = val;
    else if (key === 'max-age') attributes.maxAge = parseInt(val, 10);
    else if (key === 'expires') attributes.expires = val;
  }

  return { name, value, attributes, raw: cookieStr };
}

/**
 * Audits all cookies returned in Set-Cookie headers against OWASP ASVS V3.4
 * @param {string} targetUrl - Target URL probed
 * @param {Array<string>} rawCookies - List of raw Set-Cookie header strings
 * @returns {Array<object>} List of findings
 */
function auditCookies(targetUrl, rawCookies) {
  const findings = [];
  const isHttps = targetUrl.startsWith('https://');

  if (!rawCookies || rawCookies.length === 0) {
    findings.push({
      id: 'SEC-COOKIE-NONE',
      title: 'No cookies set in response',
      standard: 'OWASP ASVS V3.4',
      severity: SEVERITY.INFO,
      details: 'Endpoint returned no Set-Cookie headers in the response.'
    });
    return findings;
  }

  for (const raw of rawCookies) {
    const { name, attributes } = parseCookie(raw);

    // 1. Check HttpOnly flag - ASVS V3.4.2, CWE-1004
    if (!attributes.httpOnly) {
      findings.push({
        id: 'SEC-COOKIE-01',
        title: `Cookie '${name}' missing HttpOnly flag`,
        standard: 'OWASP ASVS V3.4.2',
        cwe: 'CWE-1004: Sensitive Cookie Without HttpOnly Flag',
        severity: SEVERITY.MEDIUM,
        details: `Cookie '${name}' can be accessed by client-side JavaScript (e.g., via document.cookie), making it vulnerable to XSS exfiltration.`,
        remediation: `Add the \`HttpOnly\` flag to the '${name}' Set-Cookie definition.`
      });
    } else {
      findings.push({
        id: 'SEC-COOKIE-01-PASS',
        title: `Cookie '${name}' has HttpOnly flag set`,
        standard: 'OWASP ASVS V3.4.2',
        severity: SEVERITY.PASS,
        details: `HttpOnly protects cookie '${name}' from script-based exfiltration.`
      });
    }

    // 2. Check Secure flag - ASVS V3.4.1, CWE-614
    if (isHttps && !attributes.secure) {
      findings.push({
        id: 'SEC-COOKIE-02',
        title: `Cookie '${name}' missing Secure flag over HTTPS`,
        standard: 'OWASP ASVS V3.4.1',
        cwe: 'CWE-614: Sensitive Cookie in HTTPS Session Without Secure Attribute',
        severity: SEVERITY.HIGH,
        details: `Cookie '${name}' was transmitted over HTTPS without the Secure flag, allowing the browser to transmit it in cleartext over unencrypted HTTP requests.`,
        remediation: `Append \`; Secure\` to the Set-Cookie definition for '${name}'.`
      });
    } else if (attributes.secure) {
      findings.push({
        id: 'SEC-COOKIE-02-PASS',
        title: `Cookie '${name}' has Secure attribute set`,
        standard: 'OWASP ASVS V3.4.1',
        severity: SEVERITY.PASS,
        details: `Cookie '${name}' is restricted to encrypted transport.`
      });
    }

    // 3. Check SameSite attribute - ASVS V3.4.3, CWE-1275
    if (!attributes.sameSite) {
      findings.push({
        id: 'SEC-COOKIE-03',
        title: `Cookie '${name}' missing SameSite attribute`,
        standard: 'OWASP ASVS V3.4.3',
        cwe: 'CWE-1275: Sensitive Cookie with Improper SameSite Attribute',
        severity: SEVERITY.MEDIUM,
        details: `Cookie '${name}' does not specify SameSite. Default browser behavior varies and may expose the application to CSRF attacks.`,
        remediation: `Set \`SameSite=Lax\` (standard navigation) or \`SameSite=Strict\` (sensitive actions).`
      });
    } else if (attributes.sameSite === 'none' && !attributes.secure) {
      findings.push({
        id: 'SEC-COOKIE-03-INVALID',
        title: `Cookie '${name}' specifies SameSite=None without Secure attribute`,
        standard: 'OWASP ASVS V3.4.3',
        cwe: 'CWE-1275',
        severity: SEVERITY.HIGH,
        details: `Browsers will reject cookies with SameSite=None unless the Secure flag is also set.`,
        remediation: `Add \`; Secure\` or change to \`SameSite=Lax\`.`
      });
    } else {
      findings.push({
        id: 'SEC-COOKIE-03-PASS',
        title: `Cookie '${name}' SameSite attribute set to ${attributes.sameSite}`,
        standard: 'OWASP ASVS V3.4.3',
        severity: SEVERITY.PASS,
        details: `SameSite=${attributes.sameSite} mitigates cross-site request forgery.`
      });
    }

    // 4. Check Cookie Prefix compliance - ASVS V3.4.4
    if (name.startsWith('__Host-')) {
      const isHostCompliant = attributes.secure && attributes.path === '/' && !attributes.domain;
      if (!isHostCompliant) {
        findings.push({
          id: 'SEC-COOKIE-PREFIX-HOST',
          title: `Cookie '${name}' violates __Host- prefix requirements`,
          standard: 'OWASP ASVS V3.4.4',
          cwe: 'CWE-16: Configuration',
          severity: SEVERITY.MEDIUM,
          details: `The __Host- prefix requires \`Secure\`, \`Path=/\`, and NO \`Domain\` attribute specified.`,
          remediation: `Configure cookie '${name}' with Secure, Path=/, and omit the Domain attribute.`
        });
      }
    }
  }

  return findings;
}

// --- End: src/auditors/cookies.mjs ---


// --- Start: src/auditors/cors.mjs ---
/**
 * Cross-Origin Resource Sharing (CORS) Configuration Auditor
 * Aligned with OWASP ASVS v4.0 V14.4.7 & OWASP WSTG-CONF-07
 */




/**
 * Audits CORS headers on the primary response and optionally tests preflight behavior
 * @param {string} targetUrl - Target URL probed
 * @param {Record<string, string>} initialHeaders - Normalized headers from initial response
 * @returns {Promise<Array<object>>} List of findings
 */
async function auditCors(targetUrl, initialHeaders) {
  const findings = [];

  const acao = initialHeaders['access-control-allow-origin'];
  const acac = initialHeaders['access-control-allow-credentials'];

  // Check 1: Wildcard origin with credentials allowed - ASVS V14.4.7, CWE-942
  if (acao === '*' && acac === 'true') {
    findings.push({
      id: 'SEC-CORS-01',
      title: 'CORS Wildcard with Allow-Credentials Enabled',
      standard: 'OWASP ASVS V14.4.7',
      cwe: 'CWE-942: Permissive Cross-Domain Policy with Untrusted Domains',
      severity: SEVERITY.CRITICAL,
      details: '`Access-Control-Allow-Origin: *` is combined with `Access-Control-Allow-Credentials: true`. While modern browsers reject this combination, it exposes older user agents and indicates broken CORS design.',
      remediation: 'Never use wildcard `*` with credentials. Explicitly whitelist trusted origins, e.g., `Access-Control-Allow-Origin: https://trusted.app.com`.'
    });
  }

  // Check 2: Null origin allowed - ASVS V14.4.7, CWE-942
  if (acao === 'null') {
    findings.push({
      id: 'SEC-CORS-02',
      title: 'CORS Allows `null` Origin',
      standard: 'OWASP ASVS V14.4.7',
      cwe: 'CWE-942',
      severity: SEVERITY.HIGH,
      details: 'The origin `null` is trusted in `Access-Control-Allow-Origin`. Sandboxed iframes, local file schemes, and data: URIs produce a null origin, enabling cross-origin data theft.',
      remediation: 'Do not whitelist `null` origins in CORS policies.'
    });
  }

  // Check 3: Passive Origin probe to test for dynamic origin reflection
  try {
    const probeOrigin = 'https://untrusted-audit-probe.example.com';
    const probeRes = await safeFetch(targetUrl, {
      method: 'OPTIONS',
      headers: {
        'Origin': probeOrigin,
        'Access-Control-Request-Method': 'GET'
      }
    });

    const probeAcao = probeRes.rawHeaders['access-control-allow-origin'];
    const probeAcac = probeRes.rawHeaders['access-control-allow-credentials'];

    if (probeAcao === probeOrigin) {
      const isCritical = probeAcac === 'true';
      findings.push({
        id: 'SEC-CORS-03',
        title: isCritical
          ? 'CORS Dynamically Reflects Arbitrary Origin with Credentials'
          : 'CORS Dynamically Reflects Arbitrary Origin',
        standard: 'OWASP ASVS V14.4.7',
        cwe: 'CWE-942: Permissive Cross-Domain Policy with Untrusted Domains',
        severity: isCritical ? SEVERITY.CRITICAL : SEVERITY.HIGH,
        details: `The server dynamically reflected arbitrary untrusted Origin header \`${probeOrigin}\` back into \`Access-Control-Allow-Origin\`${isCritical ? ' with credentials enabled' : ''}.`,
        remediation: 'Validate incoming Origin headers against an explicit, strict server-side whitelist before reflecting.'
      });
    } else if (!acao && !probeAcao) {
      findings.push({
        id: 'SEC-CORS-NONE',
        title: 'No Permissive CORS Headers Exposed',
        standard: 'OWASP ASVS V14.4.7',
        severity: SEVERITY.PASS,
        details: 'The endpoint does not expose cross-origin access headers to untrusted origins.'
      });
    }
  } catch {
    // If OPTIONS fails, proceed with base checks
  }

  return findings;
}

// --- End: src/auditors/cors.mjs ---


// --- Start: src/auditors/jwt.mjs ---
/**
 * JSON Web Token (JWT) Defensive Security Auditor
 * Aligned with RFC 8725 (JWT Best Current Practices) & OWASP ASVS v4.0 Chapter 8 (Cryptography)
 */



/**
 * Safely decodes base64url string without executing code
 * @param {string} str - Base64url encoded string
 * @returns {object|null} Decoded JSON object or null
 */
function safeBase64UrlDecode(str) {
  try {
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    const jsonStr = Buffer.from(base64, 'base64').toString('utf8');
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

/**
 * Audits a JWT string against RFC 8725 and OWASP ASVS V8.3
 * @param {string} jwtStr - Raw dot-separated JWT string
 * @param {string} sourceName - Source description (e.g., "Authorization Header" or "Cookie session")
 * @returns {Array<object>} List of findings
 */
function auditJwt(jwtStr, sourceName = 'JWT Token') {
  const findings = [];

  if (!jwtStr || typeof jwtStr !== 'string') {
    return findings;
  }

  // Strip 'Bearer ' if present
  const cleanToken = jwtStr.replace(/^Bearer\s+/i, '').trim();
  const parts = cleanToken.split('.');

  if (parts.length !== 3) {
    // Not a valid JWT structure, ignore
    return findings;
  }

  const header = safeBase64UrlDecode(parts[0]);
  const payload = safeBase64UrlDecode(parts[1]);

  if (!header || !payload) {
    findings.push({
      id: 'SEC-JWT-MALFORMED',
      title: `Malformed ${sourceName}`,
      standard: 'RFC 7519 / RFC 8725',
      cwe: 'CWE-1287: Improper Validation of Specified Type of Input',
      severity: SEVERITY.MEDIUM,
      details: 'The token does not contain valid Base64URL-encoded JSON headers or payloads.'
    });
    return findings;
  }

  // 1. Check Algorithm: "none" algorithm rejection - RFC 8725 Section 2.1, ASVS V8.3.1, CWE-347
  const alg = header.alg;
  if (!alg || alg.toLowerCase() === 'none') {
    findings.push({
      id: 'SEC-JWT-01',
      title: `${sourceName} uses 'none' Algorithm (Unsigned Token)`,
      standard: 'RFC 8725 Section 2.1 / OWASP ASVS V8.3.1',
      cwe: 'CWE-347: Improper Verification of Cryptographic Signature',
      severity: SEVERITY.CRITICAL,
      details: "The JWT header specifies `alg: 'none'` (or is missing an algorithm). An unverified token allows an attacker to forge arbitrary claims without possessing a cryptographic key.",
      remediation: "Enforce strict algorithm verification on the server. Reject tokens with `alg: 'none'` and mandate strong algorithms like EdDSA, ES256, or RS256."
    });
  } else {
    findings.push({
      id: 'SEC-JWT-01-PASS',
      title: `${sourceName} specifies cryptographic algorithm (${alg})`,
      standard: 'RFC 8725 Section 2.1',
      severity: SEVERITY.PASS,
      details: `Token is signed using algorithm ${alg}.`
    });
  }

  // 2. Check for Embedded JWK Header Injection - RFC 8725 Section 2.2, CWE-347
  if (header.jwk) {
    findings.push({
      id: 'SEC-JWT-02',
      title: `${sourceName} contains embedded 'jwk' header parameter`,
      standard: 'RFC 8725 Section 2.2',
      cwe: 'CWE-347',
      severity: SEVERITY.HIGH,
      details: "The JWT contains an embedded `jwk` (JSON Web Key). If the server trusts this header parameter to verify signatures without whitelisting, attackers can sign tokens with their own keys.",
      remediation: 'Ensure the server only verifies signatures using pre-configured public keys and does not trust arbitrary `jwk` header values supplied by clients.'
    });
  }

  // 3. Check for Remote JKU URL Parameter - RFC 8725 Section 2.2, CWE-918 (SSRF)
  if (header.jku) {
    findings.push({
      id: 'SEC-JWT-03',
      title: `${sourceName} uses 'jku' (JWK Set URL) parameter`,
      standard: 'RFC 8725 Section 2.2',
      cwe: 'CWE-918: Server-Side Request Forgery (SSRF)',
      severity: SEVERITY.MEDIUM,
      details: `The JWT header contains a \`jku\` parameter (${header.jku}). Servers must strictly validate this URL against a whitelist to prevent SSRF and key-spoofing attacks.`,
      remediation: 'Validate `jku` against a strict allowlist of authorized domain names and ensure transport is HTTPS.'
    });
  }

  // 4. Check Expiration Claim ('exp') - RFC 8725 Section 2.3, ASVS V3.5, CWE-613
  const now = Math.floor(Date.now() / 1000);
  if (!payload.exp) {
    findings.push({
      id: 'SEC-JWT-04',
      title: `${sourceName} missing 'exp' (Expiration Time) claim`,
      standard: 'RFC 8725 Section 2.3 / OWASP ASVS V3.5',
      cwe: 'CWE-613: Insufficient Session Expiration',
      severity: SEVERITY.HIGH,
      details: "The JWT does not specify an `exp` claim. The token is perpetually valid, meaning a compromised token cannot expire naturally.",
      remediation: "Always include an `exp` claim with a short lifespan (e.g., 15–60 minutes for access tokens) and handle renewal via secure refresh tokens."
    });
  } else {
    const remainingSeconds = payload.exp - now;
    if (remainingSeconds < 0) {
      findings.push({
        id: 'SEC-JWT-EXPIRED',
        title: `${sourceName} is expired`,
        standard: 'RFC 7519 Section 4.1.4',
        severity: SEVERITY.INFO,
        details: `The token expired ${Math.abs(remainingSeconds)} seconds ago.`
      });
    } else if (remainingSeconds > 30 * 86400) {
      // Valid for more than 30 days
      findings.push({
        id: 'SEC-JWT-04-LONG',
        title: `${sourceName} has excessively long lifetime (> 30 days)`,
        standard: 'OWASP ASVS V3.5',
        cwe: 'CWE-613',
        severity: SEVERITY.LOW,
        details: `Token is configured to be valid for ${Math.round(remainingSeconds / 86400)} days.`,
        remediation: 'Shorten access token validity to mitigate credential exposure risks.'
      });
    } else {
      findings.push({
        id: 'SEC-JWT-04-PASS',
        title: `${sourceName} includes active 'exp' claim`,
        standard: 'RFC 8725 Section 2.3',
        severity: SEVERITY.PASS,
        details: `Token lifetime is properly bound by an expiration timestamp.`
      });
    }
  }

  return findings;
}

// --- End: src/auditors/jwt.mjs ---


// --- Start: src/auditors/apiSurface.mjs ---
/**
 * API Surface & Information Leakage Auditor
 * Aligned with OWASP ASVS v4.0 Chapter 13 (API & Web Service) and Chapter 14 (Configuration)
 */




/**
 * Audits server fingerprinting, error leakages, and HTTP method exposures
 * @param {string} targetUrl - Target URL probed
 * @param {Record<string, string>} headers - Normalized response headers map
 * @param {string} bodySnippet - Response body sample
 * @returns {Promise<Array<object>>} List of findings
 */
async function auditApiSurface(targetUrl, headers, bodySnippet = '') {
  const findings = [];

  // 1. Check Server header information disclosure - ASVS V14.3.3, CWE-200
  const server = headers['server'];
  if (server) {
    const hasVersion = /\d+\.\d+/.test(server);
    findings.push({
      id: 'SEC-LEAK-SERVER',
      title: hasVersion
        ? `Server header exposes specific version details: '${server}'`
        : `Server header exposes technology banner: '${server}'`,
      standard: 'OWASP ASVS V14.3.3',
      cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
      severity: hasVersion ? SEVERITY.LOW : SEVERITY.INFO,
      details: `The web server identifies its software banner as '${server}'. Exact version disclosure aids attackers in targeted CVE research.`,
      remediation: 'Configure the web server or reverse proxy to strip or genericize the Server header.'
    });
  }

  // 2. Check X-Powered-By header - ASVS V14.3.3, CWE-200
  const poweredBy = headers['x-powered-by'] || headers['x-runtime'] || headers['x-aspnet-version'];
  if (poweredBy) {
    findings.push({
      id: 'SEC-LEAK-POWEREDBY',
      title: `Technology fingerprint revealed via X-Powered-By: '${poweredBy}'`,
      standard: 'OWASP ASVS V14.3.3',
      cwe: 'CWE-200',
      severity: SEVERITY.LOW,
      details: `The framework or runtime environment discloses its stack as '${poweredBy}'.`,
      remediation: "Disable X-Powered-By in your application framework (e.g., `app.disable('x-powered-by')` in Express)."
    });
  }

  // 3. Inspect body for sensitive stack traces / internal error leakage - ASVS V13.1.5, CWE-209
  const stackTracePatterns = [
    /at\s+[\w\d_$.]+\s+\(.*:\d+:\d+\)/i, // Node / JS stack trace
    /Traceback\s+\(most\s+recent\s+call\s+last\):/i, // Python stack trace
    /\bException\s+in\s+thread\b/i, // Java stack trace
    /\bNullPointerException\b/i,
    /System\.Web\.HttpUnhandledException/i, // ASP.NET stack trace
    /SQLSTATE\[\w+\]/i // Database error
  ];

  for (const pattern of stackTracePatterns) {
    if (pattern.test(bodySnippet)) {
      findings.push({
        id: 'SEC-LEAK-STACKTRACE',
        title: 'Verbose debug stack trace detected in response body',
        standard: 'OWASP ASVS V13.1.5',
        cwe: 'CWE-209: Generation of Error Message Containing Sensitive Information',
        severity: SEVERITY.HIGH,
        details: 'The response contains raw internal framework or database error messages, exposing internal file paths, code structures, or database schemas.',
        remediation: 'Enable generic custom error pages in production and log detailed exception traces internally.'
      });
      break;
    }
  }

  // 4. Test for dangerous HTTP methods (TRACE / TRACK) - ASVS V14.3.2, CWE-16
  try {
    const traceRes = await safeFetch(targetUrl, { method: 'TRACE' });
    if (traceRes.status === 200) {
      findings.push({
        id: 'SEC-METHOD-TRACE',
        title: 'HTTP TRACE method is enabled on web server',
        standard: 'OWASP ASVS V14.3.2',
        cwe: 'CWE-16: Configuration, CWE-200',
        severity: SEVERITY.MEDIUM,
        details: 'The web server responds to HTTP TRACE requests, echoing back request headers and potentially facilitating Cross-Site Tracing (XST).',
        remediation: 'Disable HTTP TRACE and TRACK methods in web server configuration.'
      });
    }
  } catch {
    // Ignore network or connection error
  }

  return findings;
}

// --- End: src/auditors/apiSurface.mjs ---


// --- Start: src/auditors/sensitiveRoutes.mjs ---
/**
 * Sensitive Routes & Exposed Files Auditor (Red Team / Recon)
 * Aligned with OWASP ASVS v4.0 Chapter 14 (Configuration) & MITRE ATT&CK T1592 / T1595
 */




/**
 * List of critical sensitive paths and verification signatures
 */
const SENSITIVE_PROBES = [
  {
    path: '/.git/HEAD',
    title: 'Exposed Git Repository Metadata (/.git/HEAD)',
    standard: 'OWASP ASVS V14.3.1',
    cwe: 'CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory',
    attackId: 'T1592.002',
    d3fendId: 'D3-IRA (Inbound Restriction Analysis)',
    severity: SEVERITY.CRITICAL,
    check: (res) => res.status === 200 && res.bodySnippet.includes('ref: refs/'),
    details: 'The `/.git` repository metadata directory is publicly accessible. Attackers can reconstruct the complete source code history and commit secrets.',
    remediation: 'Block public access to `.git` directories and all hidden files at the web server / reverse proxy layer.'
  },
  {
    path: '/.env',
    title: 'Exposed Environment File (/.env)',
    standard: 'OWASP ASVS V14.3.1',
    cwe: 'CWE-538',
    attackId: 'T1552.001',
    d3fendId: 'D3-IRA',
    severity: SEVERITY.CRITICAL,
    check: (res) => res.status === 200 && /(?:DB_PASSWORD|SECRET_KEY|API_KEY|DATABASE_URL)=/i.test(res.bodySnippet),
    details: 'The production `/.env` configuration file is exposed, disclosing sensitive database credentials, API secrets, and encryption keys.',
    remediation: 'Store `.env` outside the web document root and enforce web server rules blocking access to dotfiles.'
  },
  {
    path: '/actuator/health',
    title: 'Exposed Spring Boot Actuator Health Endpoint (/actuator/health)',
    standard: 'OWASP ASVS V14.3.3',
    cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
    attackId: 'T1592',
    d3fendId: 'D3-ACA (Access Control Architecture)',
    severity: SEVERITY.LOW,
    check: (res) => res.status === 200 && /"status"\s*:\s*"(?:UP|DOWN)"/i.test(res.bodySnippet),
    details: 'Spring Boot Actuator health route is exposed without authentication, disclosing component status.',
    remediation: 'Restrict actuator endpoints to internal management networks or enforce Spring Security authorization.'
  },
  {
    path: '/actuator/env',
    title: 'Exposed Spring Boot Actuator Environment Endpoint (/actuator/env)',
    standard: 'OWASP ASVS V14.3.1',
    cwe: 'CWE-538',
    attackId: 'T1552',
    d3fendId: 'D3-ACA',
    severity: SEVERITY.CRITICAL,
    check: (res) => res.status === 200 && (res.bodySnippet.includes('activeProfiles') || res.bodySnippet.includes('propertySources')),
    details: 'Spring Boot Actuator environment route exposes system environment variables and configuration properties.',
    remediation: 'Disable `/actuator/env` in production configuration (`management.endpoints.web.exposure.exclude=env`).'
  },
  {
    path: '/swagger.json',
    title: 'Publicly Accessible OpenAPI/Swagger Specification (/swagger.json)',
    standard: 'OWASP ASVS V13.1.4',
    cwe: 'CWE-200',
    attackId: 'T1595.002',
    d3fendId: 'D3-ACA',
    severity: SEVERITY.INFO,
    check: (res) => res.status === 200 && (res.bodySnippet.includes('"swagger"') || res.bodySnippet.includes('"openapi"')),
    details: 'OpenAPI specification document is exposed publicly, detailing all internal routes, schemas, and parameter specifications.',
    remediation: 'Require authentication for API documentation or place behind internal developer portals in production.'
  },
  {
    path: '/docker-compose.yml',
    title: 'Exposed Docker Compose Configuration (/docker-compose.yml)',
    standard: 'OWASP ASVS V14.3.1',
    cwe: 'CWE-538',
    attackId: 'T1592.002',
    d3fendId: 'D3-IRA',
    severity: SEVERITY.HIGH,
    check: (res) => res.status === 200 && /(?:services|version)\s*:/i.test(res.bodySnippet),
    details: 'Container architecture file is accessible, exposing internal container names, network links, and port mappings.',
    remediation: 'Ensure non-static deployment artifacts are excluded from the web server root.'
  }
];

/**
 * Audits common sensitive paths for accidental public exposure
 * @param {string} baseUrl - Base URL of the target
 * @param {object} [options] - Optional configurations including custom headers
 * @returns {Promise<Array<object>>} List of findings
 */
async function auditSensitiveRoutes(baseUrl, options = {}) {
  const findings = [];
  const parsed = new URL(baseUrl);
  const root = `${parsed.protocol}//${parsed.host}`;

  for (const probe of SENSITIVE_PROBES) {
    try {
      const probeUrl = `${root}${probe.path}`;
      const res = await safeFetch(probeUrl, {
        method: 'GET',
        timeout: 4000,
        headers: options.headers || {}
      });

      if (probe.check(res)) {
        findings.push({
          id: `SEC-ROUTE-${probe.path.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
          title: probe.title,
          standard: probe.standard,
          cwe: probe.cwe,
          attackId: probe.attackId,
          d3fendId: probe.d3fendId,
          severity: probe.severity,
          details: `${probe.details} (Confirmed at ${probeUrl})`,
          remediation: probe.remediation
        });
      }
    } catch {
      // Ignore network failures on specific probes
    }
  }

  if (findings.length === 0) {
    findings.push({
      id: 'SEC-ROUTE-CLEAN',
      title: 'No standard sensitive files or management routes exposed',
      standard: 'OWASP ASVS V14.3.1',
      attackId: 'T1592',
      severity: SEVERITY.PASS,
      details: 'Tested sensitive routes (e.g., /.git, /.env, /actuator, /docker-compose) returned restricted or not found status codes.'
    });
  }

  return findings;
}

// --- End: src/auditors/sensitiveRoutes.mjs ---


// --- Start: src/auditors/wafDetector.mjs ---
/**
 * Web Application Firewall (WAF) & Perimeter CDN Fingerprinting Auditor (Red Team / Recon)
 * Aligned with MITRE ATT&CK T1590 (Gather Victim Network Information)
 */



/**
 * Fingerprint signatures for major WAF and CDN providers
 */
const WAF_SIGNATURES = [
  {
    name: 'Cloudflare',
    detect: (headers, cookies) =>
      headers['cf-ray'] ||
      headers['cf-cache-status'] ||
      (headers['server'] && headers['server'].toLowerCase().includes('cloudflare')) ||
      cookies.some(c => c.toLowerCase().includes('__cf_bm') || c.toLowerCase().includes('cf_clearance')),
    details: 'Cloudflare Edge Proxy / WAF active. Rate limiting, DDoS protection, and managed rule sets may be enforced.'
  },
  {
    name: 'AWS CloudFront / AWS WAF',
    detect: (headers) =>
      headers['x-amz-cf-id'] ||
      headers['x-amzn-waf-action'] ||
      (headers['server'] && headers['server'].toLowerCase().includes('cloudfront')),
    details: 'Amazon CloudFront CDN and AWS WAF integration detected. Edge caching and AWS managed rulesets active.'
  },
  {
    name: 'Akamai',
    detect: (headers) =>
      headers['x-akamai-transformed'] ||
      headers['akamai-grn'] ||
      (headers['server'] && headers['server'].toLowerCase().includes('akamaighost')),
    details: 'Akamai Kona Site Defender / CDN active. Behavioral DDoS and application security filtering present.'
  },
  {
    name: 'Imperva Incapsula',
    detect: (headers, cookies) =>
      headers['x-iinfo'] ||
      headers['x-cdn'] === 'Incapsula' ||
      cookies.some(c => c.toLowerCase().includes('incap_ses') || c.toLowerCase().includes('visid_incap')),
    details: 'Imperva Incapsula Cloud WAF detected. Advanced bot management and layer-7 filtering active.'
  },
  {
    name: 'Fastly',
    detect: (headers) =>
      headers['x-fastly-request-id'] ||
      headers['fastly-restarts'],
    details: 'Fastly Edge Cloud / Next-Gen WAF (Signal Sciences) active.'
  },
  {
    name: 'F5 BIG-IP',
    detect: (headers, cookies) =>
      cookies.some(c => c.toLowerCase().includes('bigipserver')) ||
      headers['x-cnection'],
    details: 'F5 BIG-IP Application Security Manager (ASM) / Local Traffic Manager detected.'
  }
];

/**
 * Fingerprints WAF and CDN perimeters
 * @param {Record<string, string>} headers - Normalized response headers
 * @param {Array<string>} cookies - Raw Set-Cookie header strings
 * @returns {Array<object>} List of findings
 */
function auditWaf(headers, cookies = []) {
  const findings = [];
  const detected = [];

  for (const sig of WAF_SIGNATURES) {
    if (sig.detect(headers, cookies)) {
      detected.push(sig);
    }
  }

  if (detected.length > 0) {
    for (const d of detected) {
      findings.push({
        id: `SEC-WAF-${d.name.replace(/[^a-zA-Z0-9]/g, '_').toUpperCase()}`,
        title: `Perimeter Defense Identified: ${d.name}`,
        standard: 'Network Architecture Identification',
        attackId: 'T1590.001',
        d3fendId: 'D3-BRF (Boundary Rule Filtering)',
        severity: SEVERITY.INFO,
        details: d.details,
        remediation: 'Ensure origin web server is not directly accessible by bypassing the perimeter WAF IP ranges.'
      });
    }
  } else {
    findings.push({
      id: 'SEC-WAF-DIRECT',
      title: 'Direct Origin Exposure (No Major Cloud WAF Detected)',
      standard: 'Network Architecture Identification',
      attackId: 'T1590',
      d3fendId: 'D3-BRF',
      severity: SEVERITY.LOW,
      details: 'No common cloud WAF headers (Cloudflare, AWS WAF, Akamai, Imperva) were detected. The host may be directly accessible without edge layer-7 filtering.',
      remediation: 'Consider deploying a reverse-proxy WAF (Cloudflare, AWS WAF, or ModSecurity) in front of production web services.'
    });
  }

  return findings;
}

// --- End: src/auditors/wafDetector.mjs ---


// --- Start: src/auditors/discovery.mjs ---
/**
 * Well-Known Endpoints & Discovery Protocols Auditor (Red Team / Recon)
 * Aligned with RFC 9116 (security.txt), RFC 8414 (OAuth Discovery), and MITRE ATT&CK T1592
 */




/**
 * Audits discovery files and well-known paths
 * @param {string} baseUrl - Base URL of the target
 * @param {object} [options] - Optional probe options
 * @returns {Promise<Array<object>>} List of findings
 */
async function auditDiscovery(baseUrl, options = {}) {
  const findings = [];
  const parsed = new URL(baseUrl);
  const root = `${parsed.protocol}//${parsed.host}`;
  const customHeaders = options.headers || {};

  // 1. Audit RFC 9116 security.txt
  try {
    const secRes = await safeFetch(`${root}/.well-known/security.txt`, {
      method: 'GET',
      timeout: 4000,
      headers: customHeaders
    });
    if (secRes.status === 200 && secRes.bodySnippet.includes('Contact:')) {
      const hasExpires = secRes.bodySnippet.includes('Expires:');
      findings.push({
        id: 'SEC-DISC-SECTXT-PASS',
        title: 'RFC 9116 security.txt is present and configured',
        standard: 'RFC 9116',
        attackId: 'T1592',
        d3fendId: 'D3-ACA',
        severity: SEVERITY.PASS,
        details: `Security vulnerability disclosure policy is declared at /.well-known/security.txt${hasExpires ? ' with an active Expires declaration' : ''}.`
      });
    } else {
      findings.push({
        id: 'SEC-DISC-SECTXT-MISSING',
        title: 'Missing RFC 9116 security.txt Vulnerability Disclosure Policy',
        standard: 'RFC 9116',
        cwe: 'CWE-16: Configuration',
        attackId: 'T1592',
        d3fendId: 'D3-ACA',
        severity: SEVERITY.INFO,
        details: 'The organization does not publish a security.txt file at `/.well-known/security.txt`. Security researchers lack a designated path to responsibly disclose vulnerabilities.',
        remediation: 'Publish a compliant security.txt file at `/.well-known/security.txt` with `Contact:` and `Expires:` directives.'
      });
    }
  } catch {}

  // 2. Audit robots.txt for administrative path disclosure
  try {
    const robRes = await safeFetch(`${root}/robots.txt`, {
      method: 'GET',
      timeout: 4000,
      headers: customHeaders
    });
    if (robRes.status === 200 && robRes.bodySnippet.includes('Disallow:')) {
      const sensitiveDisallows = [];
      const lines = robRes.bodySnippet.split('\n');
      for (const line of lines) {
        const match = line.match(/^\s*Disallow:\s*(\/\S+)/i);
        if (match) {
          const path = match[1];
          if (/admin|secret|backup|internal|private|config|stage|dev/i.test(path)) {
            sensitiveDisallows.push(path);
          }
        }
      }

      if (sensitiveDisallows.length > 0) {
        findings.push({
          id: 'SEC-DISC-ROBOTS-LEAK',
          title: 'robots.txt Discloses Sensitive Administrative Paths',
          standard: 'OWASP ASVS V14.3.3',
          cwe: 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
          attackId: 'T1592.002',
          d3fendId: 'D3-ACA',
          severity: SEVERITY.LOW,
          details: `The robots.txt file contains Disallow rules that highlight sensitive or administrative paths to scrapers and attackers: ${sensitiveDisallows.slice(0, 5).join(', ')}.`,
          remediation: 'Do not rely on robots.txt for access control. Enforce proper server-side authentication on private endpoints.'
        });
      } else {
        findings.push({
          id: 'SEC-DISC-ROBOTS-PASS',
          title: 'robots.txt present with standard crawler instructions',
          standard: 'OWASP ASVS V14.3.3',
          severity: SEVERITY.PASS,
          details: 'robots.txt does not leak sensitive administrative directory names.'
        });
      }
    }
  } catch {}

  // 3. Check for OpenID Connect Discovery
  try {
    const oidcRes = await safeFetch(`${root}/.well-known/openid-configuration`, {
      method: 'GET',
      timeout: 4000,
      headers: customHeaders
    });
    if (oidcRes.status === 200 && oidcRes.bodySnippet.includes('authorization_endpoint')) {
      findings.push({
        id: 'SEC-DISC-OIDC',
        title: 'OpenID Connect Discovery Profile Identified',
        standard: 'RFC 8414',
        attackId: 'T1592',
        d3fendId: 'D3-ACA',
        severity: SEVERITY.INFO,
        details: 'Discovered public OAuth 2.0 / OpenID Connect authorization and token issuance metadata.',
        remediation: 'Ensure token endpoints enforce strict rate limiting and state parameter validation.'
      });
    }
  } catch {}

  return findings;
}

// --- End: src/auditors/discovery.mjs ---


// --- Start: src/blueTeam/autoHardening.mjs ---
/**
 * Automated Hardening Configuration Generator (Blue Team)
 * Generates copy-paste remediation configurations for Nginx, Apache, Caddy, and Cloudflare
 */




/**
 * Analyzes findings and generates server-specific configuration patches
 * @param {Array<object>} findings - List of audit findings
 * @returns {object} Formatted configuration blocks for each server
 */
function generateHardeningConfigs(findings) {
  const defectIds = new Set(findings.map(f => f.id));

  // Determine needed directives
  const needsHsts = defectIds.has('SEC-HDR-01') || defectIds.has('SEC-HDR-01-WEAK');
  const needsCsp = defectIds.has('SEC-HDR-02') || defectIds.has('SEC-HDR-02-WEAK');
  const needsXfo = defectIds.has('SEC-HDR-03');
  const needsXcto = defectIds.has('SEC-HDR-04');
  const needsRefPol = defectIds.has('SEC-HDR-05');
  const needsPermPol = defectIds.has('SEC-HDR-06');
  const needsServerTokens = defectIds.has('SEC-LEAK-SERVER') || defectIds.has('SEC-LEAK-POWEREDBY');
  const needsDotfileBlock = findings.some(f => f.id.startsWith('SEC-ROUTE-'));
  const needsCorsFix = defectIds.has('SEC-CORS-01') || defectIds.has('SEC-CORS-02') || defectIds.has('SEC-CORS-03');

  // 1. NGINX Hardening Snippet
  const nginxDirectives = [];
  if (needsServerTokens) {
    nginxDirectives.push('    server_tokens off;');
  }
  if (needsHsts) {
    nginxDirectives.push('    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;');
  }
  if (needsCsp) {
    nginxDirectives.push('    add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';" always;');
  }
  if (needsXfo) {
    nginxDirectives.push('    add_header X-Frame-Options "DENY" always;');
  }
  if (needsXcto) {
    nginxDirectives.push('    add_header X-Content-Type-Options "nosniff" always;');
  }
  if (needsRefPol) {
    nginxDirectives.push('    add_header Referrer-Policy "strict-origin-when-cross-origin" always;');
  }
  if (needsPermPol) {
    nginxDirectives.push('    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;');
  }
  if (needsCorsFix) {
    nginxDirectives.push('\n    # Secure CORS Policy (Strict Origin Allowlist, No Wildcard with Credentials)\n    set $cors_origin "";\n    if ($http_origin ~* "^https?://(trusted\\.company\\.com|app\\.company\\.com)$") {\n        set $cors_origin $http_origin;\n    }\n    add_header Access-Control-Allow-Origin $cors_origin always;\n    add_header Access-Control-Allow-Credentials "true" always;');
  }
  if (needsDotfileBlock) {
    nginxDirectives.push('\n    # Block access to hidden files and metadata (.git, .env, docker configs, etc.)\n    location ~ /\\.(?!well-known).* {\n        deny all;\n        access_log off;\n        log_not_found off;\n    }\n    location ~ /(actuator|swagger|metrics|debug) {\n        allow 127.0.0.1;\n        allow 10.0.0.0/8;\n        deny all;\n    }');
  }

  const nginxConfig = `## ClassiGuard CyFence Auto-Remediation: Nginx Configuration
## Paste inside your server { ... } block:
server {
${nginxDirectives.length > 0 ? nginxDirectives.join('\n') : '    # All assessed headers already conform to OWASP ASVS!'}
}`;

  // 2. APACHE Hardening Snippet
  const apacheDirectives = [];
  if (needsServerTokens) {
    apacheDirectives.push('ServerTokens Prod\nServerSignature Off');
  }
  apacheDirectives.push('<IfModule mod_headers.c>');
  if (needsHsts) apacheDirectives.push('    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"');
  if (needsCsp) apacheDirectives.push('    Header always set Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';"');
  if (needsXfo) apacheDirectives.push('    Header always set X-Frame-Options "DENY"');
  if (needsXcto) apacheDirectives.push('    Header always set X-Content-Type-Options "nosniff"');
  if (needsRefPol) apacheDirectives.push('    Header always set Referrer-Policy "strict-origin-when-cross-origin"');
  if (needsPermPol) apacheDirectives.push('    Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"');
  apacheDirectives.push('</IfModule>');

  if (needsDotfileBlock) {
    apacheDirectives.push('\n# Deny public access to hidden dotfiles\n<FilesMatch "^\\.">\n    Require all denied\n</FilesMatch>');
  }

  const apacheConfig = `## ClassiGuard CyFence Auto-Remediation: Apache (.htaccess / httpd.conf)
${apacheDirectives.join('\n')}`;

  // 3. CADDY Hardening Snippet
  const caddyDirectives = [];
  if (needsHsts) caddyDirectives.push('        Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"');
  if (needsCsp) caddyDirectives.push('        Content-Security-Policy "default-src \'self\'; script-src \'self\'; object-src \'none\'; base-uri \'self\'; frame-ancestors \'none\';"');
  if (needsXfo) caddyDirectives.push('        X-Frame-Options "DENY"');
  if (needsXcto) caddyDirectives.push('        X-Content-Type-Options "nosniff"');
  if (needsRefPol) caddyDirectives.push('        Referrer-Policy "strict-origin-when-cross-origin"');
  if (needsPermPol) caddyDirectives.push('        Permissions-Policy "camera=(), microphone=(), geolocation=()"');

  const caddyConfig = `## ClassiGuard CyFence Auto-Remediation: Caddyfile
example.com {
    header {
${caddyDirectives.join('\n')}
    }
    @dotFiles path */.*
    respond @dotFiles 403
}`;

  return {
    nginx: nginxConfig,
    apache: apacheConfig,
    caddy: caddyConfig
  };
}

/**
 * Exports complete, ready-to-deploy hardening config files into a directory
 * @param {Array<object>} findings - List of findings
 * @param {string} [targetDir='reports/hardening'] - Target directory to write configs
 * @returns {Promise<string[]>} Array of written file paths
 */
async function exportHardeningFiles(findings, targetDir = 'reports/hardening') {
  await fs.mkdir(targetDir, { recursive: true });
  const configs = generateHardeningConfigs(findings);

  const nginxPath = path.join(targetDir, 'nginx-hardened.conf');
  const apachePath = path.join(targetDir, 'apache-hardened.conf');
  const caddyPath = path.join(targetDir, 'caddy-hardened.Caddyfile');

  await fs.writeFile(nginxPath, configs.nginx, 'utf8');
  await fs.writeFile(apachePath, configs.apache, 'utf8');
  await fs.writeFile(caddyPath, configs.caddy, 'utf8');

  return [nginxPath, apachePath, caddyPath];
}

// --- End: src/blueTeam/autoHardening.mjs ---


// --- Start: src/blueTeam/sigmaRules.mjs ---
/**
 * Sigma & SIEM Alert Rule Generator (Blue Team / Detection Engineering)
 * Generates ready-to-deploy Sigma detection rules and Elasticsearch queries based on discovered risks
 */

/**
 * Generates Sigma detection rule in YAML format
 * @param {Array<object>} findings - List of findings from the audit
 * @param {string} targetUrl - Target audited
 * @returns {object} Formatted Sigma rule YAML and Elasticsearch query
 */
function generateDetectionRules(findings, targetUrl) {
  const defectIds = new Set(findings.map(f => f.id));
  let hostname = '';
  try {
    const rawTarget = String(targetUrl || '');
    const urlObj = new URL(rawTarget.includes('://') ? rawTarget : `https://${rawTarget}`);
    hostname = (urlObj.hostname || '').replace(/[^a-zA-Z0-9.-]/g, '_');
  } catch {
    hostname = '';
  }
  if (!hostname) {
    hostname = String(targetUrl || 'target-host').replace(/[^a-zA-Z0-9.-]/g, '_');
  }
  if (!hostname) {
    hostname = 'target-host';
  }

  const uriPatterns = [];
  const tags = ['attack.initial_access', 'attack.reconnaissance'];

  if (defectIds.has('SEC-ROUTE-_.GIT_HEAD')) uriPatterns.push('/.git');
  if (defectIds.has('SEC-ROUTE-_.ENV')) uriPatterns.push('/.env');
  if (defectIds.has('SEC-ROUTE-_ACTUATOR_HEALTH') || defectIds.has('SEC-ROUTE-_ACTUATOR_ENV')) {
    uriPatterns.push('/actuator');
  }
  if (defectIds.has('SEC-ROUTE-_SWAGGER_JSON')) uriPatterns.push('/swagger.json');
  if (defectIds.has('SEC-ROUTE-_DOCKER_COMPOSE_YML')) uriPatterns.push('/docker-compose.yml');

  const hasTrace = defectIds.has('SEC-METHOD-TRACE');

  const yamlLines = [
    `title: Web Application Reconnaissance & Probing against ${hostname}`,
    `id: c1a55190-4d2b-4e6f-9a1b-${Date.now().toString(16).slice(-12)}`,
    `status: experimental`,
    `description: Detects suspicious HTTP reconnaissance attempts targeting exposed endpoints or dangerous methods identified by ClassiGuard CyFence.`,
    `references:`,
    `  - https://attack.mitre.org/techniques/T1595/`,
    `  - https://attack.mitre.org/techniques/T1592/`,
    `author: ClassiGuard CyFence Detection Engine`,
    `date: ${new Date().toISOString().slice(0, 10)}`,
    `logsource:`,
    `  category: webserver`,
    `detection:`,
    `  selection_paths:`
  ];

  if (uriPatterns.length > 0) {
    yamlLines.push(`    cs-uri-stem|contains:`);
    for (const p of uriPatterns) {
      yamlLines.push(`      - '${p}'`);
    }
  } else {
    yamlLines.push(`    cs-uri-stem|contains:`);
    yamlLines.push(`      - '/.git'`);
    yamlLines.push(`      - '/.env'`);
  }

  if (hasTrace) {
    yamlLines.push(`  selection_method:`);
    yamlLines.push(`    cs-method: 'TRACE'`);
    yamlLines.push(`  condition: selection_paths or selection_method`);
  } else {
    yamlLines.push(`  condition: selection_paths`);
  }

  yamlLines.push(`level: high`);
  yamlLines.push(`tags:`);
  for (const t of tags) {
    yamlLines.push(`  - ${t}`);
  }

  const sigmaYaml = yamlLines.join('\n');

  // Elasticsearch Query DSL
  const elasticQuery = JSON.stringify({
    query: {
      bool: {
        should: [
          ...uriPatterns.map(p => ({ wildcard: { 'url.path': `*${p}*` } })),
          ...(hasTrace ? [{ match: { 'http.request.method': 'TRACE' } }] : [])
        ],
        minimum_should_match: 1
      }
    }
  }, null, 2);

  return {
    sigmaYaml,
    elasticQuery
  };
}

// --- End: src/blueTeam/sigmaRules.mjs ---


// --- Start: src/blueTeam/driftDiff.mjs ---
/**
 * Configuration Drift & Audit Diff Engine (Blue / Purple Team)
 * Compares two JSON audit reports to identify regressions, resolved vulnerabilities, and score drift
 */



/**
 * Compares two audit result objects
 * @param {object} baseAudit - Previous / baseline audit report
 * @param {object} currentAudit - Latest / current audit report
 * @returns {object} Structured drift comparison
 */
function computeAuditDiff(baseAudit, currentAudit) {
  const baseFindings = baseAudit.findings || [];
  const currentFindings = currentAudit.findings || [];

  const baseDefects = baseFindings.filter(f => f.severity !== 'PASS');
  const currentDefects = currentFindings.filter(f => f.severity !== 'PASS');

  const baseMap = new Map(baseDefects.map(f => [f.id, f]));
  const currentMap = new Map(currentDefects.map(f => [f.id, f]));

  const newDefects = [];
  const resolvedDefects = [];
  const persistentDefects = [];

  for (const [id, finding] of currentMap.entries()) {
    if (!baseMap.has(id)) {
      newDefects.push(finding);
    } else {
      persistentDefects.push(finding);
    }
  }

  for (const [id, finding] of baseMap.entries()) {
    if (!currentMap.has(id)) {
      resolvedDefects.push(finding);
    }
  }

  const baseScore = baseAudit.compliance?.score || 0;
  const currentScore = currentAudit.compliance?.score || 0;
  const scoreDelta = currentScore - baseScore;

  let status = 'UNCHANGED';
  if (scoreDelta > 0) status = 'IMPROVED';
  else if (scoreDelta < 0) status = 'DEGRADED';

  return {
    baseTimestamp: baseAudit.timestamp,
    currentTimestamp: currentAudit.timestamp,
    baseScore,
    currentScore,
    scoreDelta,
    baseGrade: baseAudit.compliance?.grade,
    currentGrade: currentAudit.compliance?.grade,
    status,
    newDefects,
    resolvedDefects,
    persistentDefects,
    summary: {
      newCount: newDefects.length,
      resolvedCount: resolvedDefects.length,
      persistentCount: persistentDefects.length
    }
  };
}

/**
 * Formats diff results into a human-readable terminal summary
 * @param {object} diff - Result from computeAuditDiff
 * @returns {string} Formatted text
 */
function formatDiffTerminal(diff) {
  const lines = [
    `\n================================================================================`,
    `  📊 CLASSIGUARD CYFENCE: CONFIGURATION DRIFT & REGRESSION ANALYSIS`,
    `================================================================================`,
    `  Baseline Run: ${new Date(diff.baseTimestamp).toLocaleString()} (Score: ${diff.baseScore}, Grade: ${diff.baseGrade})`,
    `  Current Run:  ${new Date(diff.currentTimestamp).toLocaleString()} (Score: ${diff.currentScore}, Grade: ${diff.currentGrade})`,
    `--------------------------------------------------------------------------------`,
    `  Posture Trend: ${diff.status === 'IMPROVED' ? '📈 IMPROVED (+' + diff.scoreDelta + ')' : diff.status === 'DEGRADED' ? '📉 DEGRADED (' + diff.scoreDelta + ')' : '➡️ STABLE'}`,
    `  New Regressions:    ${diff.newDefects.length}`,
    `  Resolved Defects:   ${diff.resolvedDefects.length}`,
    `  Persistent Defects: ${diff.persistentDefects.length}`,
    `--------------------------------------------------------------------------------`
  ];

  if (diff.newDefects.length > 0) {
    lines.push(`\n  🚨 NEW SECURITY REGRESSIONS INTRODUCED:`);
    for (const d of diff.newDefects) {
      lines.push(`    [${d.severity}] ${d.title} (${d.standard})`);
    }
  }

  if (diff.resolvedDefects.length > 0) {
    lines.push(`\n  ✅ RESOLVED VULNERABILITIES:`);
    for (const r of diff.resolvedDefects) {
      lines.push(`    ✓ ${r.title} (${r.standard})`);
    }
  }

  lines.push(`================================================================================\n`);
  return lines.join('\n');
}

/**
 * Loads two JSON report files and computes diff
 * @param {string} basePath - Path to base report
 * @param {string} currentPath - Path to current report
 */
async function diffReportFiles(basePath, currentPath) {
  const baseContent = await fs.readFile(basePath, 'utf8');
  const currentContent = await fs.readFile(currentPath, 'utf8');
  const baseAudit = JSON.parse(baseContent);
  const currentAudit = JSON.parse(currentContent);
  return computeAuditDiff(baseAudit, currentAudit);
}

// --- End: src/blueTeam/driftDiff.mjs ---


// --- Start: src/ai/advisor.mjs ---
/**
 * AI Security Advisor & Remediation Synthesizer
 * Supports: Ollama (Offline / Air-gapped), Anthropic Claude, OpenAI, and Codex APIs
 * 
 * CORE ARCHITECTURAL PRINCIPLE:
 * "Human in the loop. No self-decision by AI. Human review is mandatory."
 */



/**
 * Generates AI-assisted remediation analysis and custom guidance
 * @param {object} auditResult - Output of engine run
 * @param {object} options - AI configuration options
 * @param {string} [options.provider='ollama'] - AI Provider: 'ollama', 'openai', 'claude', 'custom'
 * @param {string} [options.model] - Specific model name
 * @param {string} [options.apiKey] - API key for cloud providers
 * @param {string} [options.endpoint] - Custom endpoint URL
 * @returns {Promise<{advisory: string, model: string, approved: boolean, error?: string}>}
 */
async function getAiSecurityAdvisory(auditResult, options = {}) {
  const provider = (options.provider || process.env.SENTINEL_AI_PROVIDER || 'ollama').toLowerCase();
  const defects = auditResult.findings.filter(f => f.severity !== 'PASS');

  if (defects.length === 0) {
    return {
      advisory: '✨ All evaluated defensive security controls conform to OWASP ASVS. No remediation required.',
      model: 'rule-engine',
      requiresHumanApproval: false
    };
  }

  // Sanitize target URL to prevent credential or sensitive parameter leakage (CWE-200 / CWE-359)
  let sanitizedUrl = auditResult.targetUrl;
  try {
    const parsed = new URL(auditResult.targetUrl);
    sanitizedUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
  } catch {
    sanitizedUrl = 'redacted-target';
  }

  // Build isolated context summary for AI to prevent prompt injection (CWE-20)
  const promptContext = `You are evaluating security findings for an enterprise system.
<target_environment>
Host: ${sanitizedUrl}
Compliance Score: ${auditResult.compliance.score}/100 (Grade: ${auditResult.compliance.grade})
</target_environment>

<verified_defects>
${defects.map(d => `- [${d.severity}] ${d.title.replace(/[<>]/g, '')} (Standard: ${d.standard}, CWE: ${d.cwe || 'N/A'})`).join('\n')}
</verified_defects>

Instruction: Provide a concise, professional security engineering remediation plan prioritizing critical/high risks. Include exact web server or code snippets. Remind the engineer that all changes require human review before production deployment.`;

  let advisoryText = '';
  let modelUsed = '';

  try {
    if (provider === 'ollama') {
      // Offline / Local Air-gapped Ollama instance
      const endpoint = options.endpoint || process.env.OLLAMA_ENDPOINT || 'http://localhost:11434/api/generate';
      const model = options.model || process.env.OLLAMA_MODEL || 'llama3';

      const res = await safeFetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model,
          prompt: promptContext,
          stream: false
        }),
        timeout: 15000
      });

      if (res.status === 200) {
        const data = JSON.parse(res.bodySnippet || '{}');
        advisoryText = data.response;
        modelUsed = `Ollama (${model})`;
      } else {
        throw new Error(`Ollama request failed with status ${res.status}. Is Ollama running on localhost:11434?`);
      }
    } else if (provider === 'openai' || provider === 'codex') {
      const apiKey = options.apiKey || process.env.OPENAI_API_KEY;
      if (!apiKey) throw new Error('OPENAI_API_KEY environment variable or --ai-key is required.');

      const endpoint = options.endpoint || 'https://api.openai.com/v1/chat/completions';
      const model = options.model || 'gpt-4o-mini';

      const res = await safeFetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model,
          messages: [
            { role: 'system', content: 'You are a principal application security architect advising on OWASP ASVS remediation.' },
            { role: 'user', content: promptContext }
          ],
          temperature: 0.2
        }),
        timeout: 20000
      });

      if (res.status === 200) {
        const data = JSON.parse(res.bodySnippet || '{}');
        advisoryText = data.choices?.[0]?.message?.content || 'No advisory generated.';
        modelUsed = `OpenAI (${model})`;
      } else {
        throw new Error(`OpenAI API returned status ${res.status}: ${res.bodySnippet}`);
      }
    } else if (provider === 'claude') {
      const apiKey = options.apiKey || process.env.ANTHROPIC_API_KEY;
      if (!apiKey) throw new Error('ANTHROPIC_API_KEY environment variable or --ai-key is required.');

      const endpoint = options.endpoint || 'https://api.anthropic.com/v1/messages';
      const model = options.model || 'claude-3-5-sonnet-20241022';

      const res = await safeFetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        },
        body: JSON.stringify({
          model,
          max_tokens: 1500,
          messages: [{ role: 'user', content: promptContext }]
        }),
        timeout: 20000
      });

      if (res.status === 200) {
        const data = JSON.parse(res.bodySnippet || '{}');
        advisoryText = data.content?.[0]?.text || 'No advisory generated.';
        modelUsed = `Claude (${model})`;
      } else {
        throw new Error(`Anthropic API returned status ${res.status}: ${res.bodySnippet}`);
      }
    } else {
      throw new Error(`Unsupported AI provider: ${provider}. Supported: ollama, openai, claude, codex.`);
    }

    return {
      advisory: advisoryText,
      model: modelUsed,
      requiresHumanApproval: true,
      mandatoryDisclaimer: '⚠️ [MANDATORY HUMAN APPROVAL]: AI-generated recommendations are assistive proposals. Human review and staging verification are required before applying any changes to production systems.'
    };
  } catch (err) {
    return {
      advisory: `⚠️ AI Advisory unavailable: ${err.message}\n(Falling back to built-in deterministic remediation engine).`,
      model: 'none',
      error: err.message,
      requiresHumanApproval: true
    };
  }
}

// --- End: src/ai/advisor.mjs ---


// --- Start: src/reporter/terminal.mjs ---
/**
 * Rich Terminal Reporter with ANSI color styling
 */



const COLORS = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m\x1b[37m',
  bgYellow: '\x1b[43m\x1b[30m',
  bgGreen: '\x1b[42m\x1b[30m',
  bgCyan: '\x1b[46m\x1b[30m'
};

function badge(severity) {
  switch (severity) {
    case SEVERITY.CRITICAL:
      return `${COLORS.bgRed}${COLORS.bold} CRITICAL ${COLORS.reset}`;
    case SEVERITY.HIGH:
      return `${COLORS.red}${COLORS.bold}[ HIGH ]${COLORS.reset}`;
    case SEVERITY.MEDIUM:
      return `${COLORS.yellow}${COLORS.bold}[ MEDIUM ]${COLORS.reset}`;
    case SEVERITY.LOW:
      return `${COLORS.cyan}[ LOW ]${COLORS.reset}`;
    case SEVERITY.INFO:
      return `${COLORS.blue}[ INFO ]${COLORS.reset}`;
    case SEVERITY.PASS:
      return `${COLORS.green}[ PASS ]${COLORS.reset}`;
    default:
      return `[ ${severity} ]`;
  }
}

/**
 * Prints the audit findings report to stdout
 * @param {object} auditResult - Output of engine run
 * @param {object} [options] - Output display options
 */
function printTerminalReport(auditResult, options = {}) {
  const { targetUrl, timestamp, compliance, findings, blueTeam, aiAdvisory } = auditResult;
  const { score, grade, counts } = compliance;

  console.log(`\n${COLORS.cyan}${COLORS.bold}================================================================================${COLORS.reset}`);
  console.log(`${COLORS.bold}  🛡️  CLASSIGUARD CYFENCE: DEFENSIVE WEB SECURITY & POSTURE ASSESSMENT${COLORS.reset}`);
  console.log(`${COLORS.dim}  OWASP ASVS v4.0 | MITRE ATT&CK & D3FEND | RFC 8725 | Pure Node.js${COLORS.reset}`);
  console.log(`${COLORS.cyan}================================================================================${COLORS.reset}`);
  console.log(`  ${COLORS.bold}Target URL:${COLORS.reset}  ${targetUrl}`);
  console.log(`  ${COLORS.bold}Timestamp:${COLORS.reset}   ${new Date(timestamp).toLocaleString()}`);
  console.log(`--------------------------------------------------------------------------------`);

  // Score & Grade Banner
  let gradeColor = COLORS.green;
  if (grade === 'C') gradeColor = COLORS.yellow;
  else if (grade === 'D' || grade === 'F') gradeColor = COLORS.red;

  console.log(`  ${COLORS.bold}Security Score:${COLORS.reset} ${gradeColor}${COLORS.bold}${score}/100${COLORS.reset}  |  ${COLORS.bold}Grade:${COLORS.reset} ${gradeColor}${COLORS.bold}${grade}${COLORS.reset}`);
  console.log(`  ${COLORS.bold}Findings Summary:${COLORS.reset} ` +
    `${COLORS.red}Critical: ${counts.critical}${COLORS.reset} | ` +
    `${COLORS.yellow}High: ${counts.high}${COLORS.reset} | ` +
    `${COLORS.magenta}Medium: ${counts.medium}${COLORS.reset} | ` +
    `${COLORS.cyan}Low: ${counts.low}${COLORS.reset} | ` +
    `${COLORS.green}Passed: ${counts.passed}${COLORS.reset}`
  );
  console.log(`--------------------------------------------------------------------------------\n`);

  // Print Issues First, then Passes
  const defects = findings.filter(f => f.severity !== SEVERITY.PASS);
  const passes = findings.filter(f => f.severity === SEVERITY.PASS);

  if (defects.length === 0) {
    console.log(`${COLORS.green}${COLORS.bold}  ✨ All evaluated baseline security controls passed!${COLORS.reset}\n`);
  } else {
    console.log(`${COLORS.bold}  DETAILED SECURITY DEFECTS & REMEDIATIONS:${COLORS.reset}`);
    for (const f of defects) {
      console.log(`  ${badge(f.severity)} ${COLORS.bold}${f.title}${COLORS.reset}`);
      console.log(`    ${COLORS.dim}Standard:${COLORS.reset} ${f.standard}  ${f.cwe ? `|  ${COLORS.dim}CWE:${COLORS.reset} ${f.cwe}` : ''}`);
      if (f.attackId || f.d3fendId) {
        console.log(`    ${COLORS.dim}Frameworks:${COLORS.reset} ${f.attackId ? `[ATT&CK: ${f.attackId}] ` : ''}${f.d3fendId ? `[D3FEND: ${f.d3fendId}]` : ''}`);
      }
      console.log(`    ${COLORS.dim}Details:${COLORS.reset}  ${f.details}`);
      if (f.remediation) {
        console.log(`    ${COLORS.green}${COLORS.bold}Fix:${COLORS.reset}      ${f.remediation}`);
      }
      console.log('');
    }
  }

  // Print Passed Verifications
  if (passes.length > 0) {
    console.log(`${COLORS.bold}  VERIFIED DEFENSIVE CONTROLS (${passes.length} Passed):${COLORS.reset}`);
    for (const p of passes) {
      console.log(`    ${COLORS.green}✓${COLORS.reset} [${p.standard}] ${p.title}`);
    }
    console.log('');
  }

  // Blue Team Auto-Remediation Preview
  if (blueTeam && options.showRemediation) {
    console.log(`${COLORS.bold}  🔵 BLUE TEAM: AUTO-REMEDIATION PATCH (NGINX):${COLORS.reset}`);
    console.log(`${COLORS.dim}${blueTeam.hardeningConfigs.nginx}${COLORS.reset}\n`);
  }

  // AI Security Advisor Output
  if (aiAdvisory) {
    console.log(`${COLORS.yellow}${COLORS.bold}================================================================================${COLORS.reset}`);
    console.log(`  🤖 AI-ASSISTED REMEDIATION PLAN (${aiAdvisory.model})`);
    console.log(`${COLORS.yellow}  ⚠️  HUMAN APPROVAL MANDATORY: Human review is required before applying changes!${COLORS.reset}`);
    console.log(`--------------------------------------------------------------------------------`);
    console.log(aiAdvisory.advisory);
    console.log(`${COLORS.yellow}================================================================================${COLORS.reset}\n`);
  }

  console.log(`${COLORS.cyan}================================================================================${COLORS.reset}\n`);
}

// --- End: src/reporter/terminal.mjs ---


// --- Start: src/reporter/json.mjs ---
/**
 * Machine-readable JSON report exporter
 */




/**
 * Serializes and writes audit result to JSON file
 * @param {object} auditResult - Output of engine run
 * @param {string} filePath - Target file path
 * @returns {Promise<string>} Written file path
 */
async function writeJsonReport(auditResult, filePath) {
  const dir = path.dirname(filePath);
  if (dir && dir !== '.') {
    await fs.mkdir(dir, { recursive: true });
  }

  const jsonContent = JSON.stringify(auditResult, null, 2);
  await fs.writeFile(filePath, jsonContent, 'utf8');
  return filePath;
}

// --- End: src/reporter/json.mjs ---


// --- Start: src/reporter/html.mjs ---
/**
 * Standalone HTML Report Generator with Cybersecurity UI Styling
 * Zero external dependencies, zero CDN requests (100% air-gapped safe)
 */





function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Builds and writes an interactive HTML report to disk
 * @param {object} auditResult - Output of engine run
 * @param {string} filePath - Path to save the HTML file
 * @returns {Promise<string>} Written file path
 */
async function writeHtmlReport(auditResult, filePath) {
  const dir = path.dirname(filePath);
  if (dir && dir !== '.') {
    await fs.mkdir(dir, { recursive: true });
  }

  const { targetUrl, timestamp, compliance, findings, blueTeam, aiAdvisory } = auditResult;
  const { score, grade, counts } = compliance;

  let gradeBadgeClass = 'grade-green';
  if (grade === 'C') gradeBadgeClass = 'grade-yellow';
  else if (grade === 'D' || grade === 'F') gradeBadgeClass = 'grade-red';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>ClassiGuard CyFence: ${escapeHtml(targetUrl)}</title>
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: #111827;
      --card-border: #1f2937;
      --text-main: #f9fafb;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --red: #ef4444;
      --yellow: #f59e0b;
      --purple: #a855f7;
      --cyan: #06b6d4;
      --green: #10b981;
      --code-bg: #030712;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text-main);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      line-height: 1.5;
      padding: 2rem 1.5rem;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    header {
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 1.5rem;
      margin-bottom: 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
    }
    .brand h1 { font-size: 1.6rem; font-weight: 700; color: #fff; }
    .brand p { color: var(--text-muted); font-size: 0.9rem; }
    .meta-tag {
      background: #1f2937;
      color: #93c5fd;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      font-size: 0.85rem;
      font-family: monospace;
    }
    .summary-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }
    .score-card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.25rem;
      text-align: center;
    }
    .score-card .title { font-size: 0.85rem; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
    .score-card .value { font-size: 2.2rem; font-weight: 800; margin-top: 0.25rem; }
    .grade-green { color: var(--green); }
    .grade-yellow { color: var(--yellow); }
    .grade-red { color: var(--red); }

    .stat-badge {
      display: inline-block;
      padding: 0.25rem 0.6rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      margin-right: 0.5rem;
    }
    .badge-critical { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }
    .badge-high { background: rgba(245, 158, 11, 0.2); color: var(--yellow); border: 1px solid var(--yellow); }
    .badge-medium { background: rgba(168, 85, 247, 0.2); color: var(--purple); border: 1px solid var(--purple); }
    .badge-low { background: rgba(6, 182, 212, 0.2); color: var(--cyan); border: 1px solid var(--cyan); }
    .badge-pass { background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }
    .badge-info { background: rgba(59, 130, 246, 0.2); color: var(--primary); border: 1px solid var(--primary); }

    .framework-pill {
      display: inline-block;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      background: #1e293b;
      color: #94a3b8;
      border: 1px solid #334155;
      margin-left: 0.4rem;
    }

    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 1rem;
    }
    .card-title-row {
      display: flex;
      align-items: center;
      margin-bottom: 0.5rem;
    }
    .card-title { font-size: 1.05rem; font-weight: 600; color: #fff; }
    .card-meta {
      font-size: 0.8rem;
      color: var(--text-muted);
      margin-bottom: 0.75rem;
    }
    .card-details {
      color: #d1d5db;
      font-size: 0.95rem;
      margin-bottom: 0.75rem;
    }
    .remediation-box {
      background: #0d131f;
      border-left: 3px solid var(--green);
      padding: 0.75rem 1rem;
      border-radius: 0 6px 6px 0;
      font-size: 0.9rem;
      color: #a7f3d0;
    }
    .remediation-box strong { color: #fff; }

    pre code {
      display: block;
      background: var(--code-bg);
      padding: 1rem;
      border-radius: 6px;
      font-family: monospace;
      font-size: 0.85rem;
      color: #7dd3fc;
      overflow-x: auto;
      border: 1px solid #1e293b;
      margin-top: 0.5rem;
    }

    .ai-banner {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid var(--yellow);
      border-radius: 8px;
      padding: 1.25rem;
      margin-bottom: 2rem;
    }
    .ai-banner h3 { color: var(--yellow); font-size: 1.1rem; margin-bottom: 0.5rem; }
    .ai-warning { color: #fbbf24; font-size: 0.85rem; font-weight: 700; margin-bottom: 0.75rem; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <h1>🛡️ ClassiGuard CyFence Report</h1>
        <p>OWASP ASVS v4.0 &bull; MITRE ATT&CK &bull; MITRE D3FEND &bull; RFC 8725</p>
      </div>
      <div>
        <span class="meta-tag">${escapeHtml(targetUrl)}</span>
      </div>
    </header>

    <div class="summary-grid">
      <div class="score-card">
        <div class="title">ASVS Compliance Score</div>
        <div class="value ${gradeBadgeClass}">${score} / 100</div>
      </div>
      <div class="score-card">
        <div class="title">Security Grade</div>
        <div class="value ${gradeBadgeClass}">${grade}</div>
      </div>
      <div class="score-card">
        <div class="title">Critical / High Defects</div>
        <div class="value" style="color: ${counts.critical + counts.high > 0 ? 'var(--red)' : 'var(--green)'};">
          ${counts.critical + counts.high}
        </div>
      </div>
      <div class="score-card">
        <div class="title">Controls Verified</div>
        <div class="value" style="color: var(--green);">${counts.passed}</div>
      </div>
    </div>

    ${aiAdvisory ? `
    <div class="ai-banner">
      <h3>🤖 AI-Assisted Security Advisory (${escapeHtml(aiAdvisory.model)})</h3>
      <div class="ai-warning">⚠️ HUMAN APPROVAL MANDATORY: All AI proposals must be reviewed and tested by human engineers prior to production implementation.</div>
      <p style="white-space: pre-wrap; font-size: 0.95rem; color: #f3f4f6;">${escapeHtml(aiAdvisory.advisory)}</p>
    </div>` : ''}

    <h2 style="margin-bottom: 1rem;">Defensive Assessment Findings (${findings.length})</h2>

    ${findings.map(f => {
      let bClass = 'badge-info';
      if (f.severity === SEVERITY.CRITICAL) bClass = 'badge-critical';
      else if (f.severity === SEVERITY.HIGH) bClass = 'badge-high';
      else if (f.severity === SEVERITY.MEDIUM) bClass = 'badge-medium';
      else if (f.severity === SEVERITY.LOW) bClass = 'badge-low';
      else if (f.severity === SEVERITY.PASS) bClass = 'badge-pass';

      return `
      <div class="card">
        <div class="card-title-row">
          <span class="stat-badge ${bClass}">${f.severity}</span>
          <span class="card-title">${escapeHtml(f.title)}</span>
          ${f.attackId ? `<span class="framework-pill">ATT&CK ${escapeHtml(f.attackId)}</span>` : ''}
          ${f.d3fendId ? `<span class="framework-pill">D3FEND ${escapeHtml(f.d3fendId)}</span>` : ''}
        </div>
        <div class="card-meta">
          Standard: <strong>${escapeHtml(f.standard)}</strong>
          ${f.cwe ? ` &bull; CWE: <strong>${escapeHtml(f.cwe)}</strong>` : ''}
        </div>
        <div class="card-details">${escapeHtml(f.details)}</div>
        ${f.remediation ? `
        <div class="remediation-box">
          <strong>Recommended Fix:</strong> ${escapeHtml(f.remediation)}
        </div>` : ''}
      </div>`;
    }).join('\n')}

    ${blueTeam ? `
    <h2 style="margin: 2rem 0 1rem 0;">🔵 Blue Team: Automated Hardening Patches</h2>
    <div class="card">
      <div class="card-title">Nginx Security Headers & Blocking Snippet</div>
      <pre><code>${escapeHtml(blueTeam.hardeningConfigs.nginx)}</code></pre>
    </div>
    <div class="card">
      <div class="card-title">Apache Security Directives</div>
      <pre><code>${escapeHtml(blueTeam.hardeningConfigs.apache)}</code></pre>
    </div>
    <div class="card">
      <div class="card-title">Generated Sigma SIEM Rule (YAML)</div>
      <pre><code>${escapeHtml(blueTeam.detectionRules.sigmaYaml)}</code></pre>
    </div>` : ''}
  </div>
</body>
</html>`;

  await fs.writeFile(filePath, html, 'utf8');
  return filePath;
}

// --- End: src/reporter/html.mjs ---


// --- Start: src/reporter/markdown.mjs ---
/**
 * Markdown Report Generator (GitHub Flavored Markdown)
 * Generates structured Markdown reports suitable for PR comments, Jira, and documentation
 */





/**
 * Builds and writes a Markdown report to disk
 * @param {object} auditResult - Output of engine run
 * @param {string} filePath - Path to save the Markdown file
 * @returns {Promise<string>} Written file path
 */
async function writeMarkdownReport(auditResult, filePath) {
  const dir = path.dirname(filePath);
  if (dir && dir !== '.') {
    await fs.mkdir(dir, { recursive: true });
  }

  const { targetUrl, timestamp, compliance, findings, blueTeam, aiAdvisory } = auditResult;
  const { score, grade, counts } = compliance;

  const lines = [
    `# 🛡️ ClassiGuard CyFence Security Audit Report`,
    ``,
    `* **Target:** \`${targetUrl}\``,
    `* **Timestamp:** \`${new Date(timestamp).toUTCString()}\``,
    `* **Compliance Score:** **${score}/100** (Grade: **${grade}**)`,
    `* **Defect Counts:** ${counts.critical} Critical | ${counts.high} High | ${counts.medium} Medium | ${counts.low} Low | ${counts.passed} Passed`,
    ``,
    `---`,
    ``,
    `## 📊 Executive Summary`,
    ``,
    `| Metric | Value |`,
    `| :--- | :--- |`,
    `| **Target URL** | \`${targetUrl}\` |`,
    `| **Security Score** | **${score} / 100** |`,
    `| **Security Grade** | **${grade}** |`,
    `| **Critical Defects** | \`${counts.critical}\` |`,
    `| **High Defects** | \`${counts.high}\` |`,
    `| **Medium Defects** | \`${counts.medium}\` |`,
    `| **Low Defects** | \`${counts.low}\` |`,
    `| **Passed Verifications** | \`${counts.passed}\` |`,
    ``
  ];

  if (aiAdvisory) {
    lines.push(`## 🤖 AI-Assisted Security Advisory (${aiAdvisory.model})`);
    lines.push(`> ⚠️ **MANDATORY HUMAN APPROVAL**: Human review and testing are required before applying any suggested patch.`);
    lines.push(``);
    lines.push(aiAdvisory.advisory);
    lines.push(``);
    lines.push(`---`);
    lines.push(``);
  }

  lines.push(`## 🔍 Detailed Findings`);
  lines.push(``);

  const defects = findings.filter(f => f.severity !== SEVERITY.PASS);
  const passes = findings.filter(f => f.severity === SEVERITY.PASS);

  if (defects.length === 0) {
    lines.push(`✨ *All evaluated security controls passed successfully.*`);
    lines.push(``);
  } else {
    for (const f of defects) {
      lines.push(`### [${f.severity}] ${f.title}`);
      lines.push(`* **Standard:** ${f.standard}${f.cwe ? ` | **CWE:** ${f.cwe}` : ''}`);
      if (f.attackId || f.d3fendId) {
        lines.push(`* **Frameworks:** ${f.attackId ? `MITRE ATT&CK: \`${f.attackId}\` ` : ''}${f.d3fendId ? `| MITRE D3FEND: \`${f.d3fendId}\`` : ''}`);
      }
      lines.push(`* **Details:** ${f.details}`);
      if (f.remediation) {
        lines.push(`* **Recommended Fix:** ${f.remediation}`);
      }
      lines.push(``);
    }
  }

  if (passes.length > 0) {
    lines.push(`## ✅ Verified Defensive Controls (${passes.length} Passed)`);
    lines.push(``);
    for (const p of passes) {
      lines.push(`* ✓ **[${p.standard}]** ${p.title}`);
    }
    lines.push(``);
  }

  if (blueTeam) {
    lines.push(`## 🔵 Blue Team: Automated Remediation Snippets`);
    lines.push(``);
    lines.push(`### Nginx Hardening Configuration`);
    lines.push('```nginx');
    lines.push(blueTeam.hardeningConfigs.nginx);
    lines.push('```');
    lines.push(``);
    lines.push(`### Apache Hardening Configuration`);
    lines.push('```apache');
    lines.push(blueTeam.hardeningConfigs.apache);
    lines.push('```');
    lines.push(``);
    lines.push(`### Sigma SIEM Detection Rule`);
    lines.push('```yaml');
    lines.push(blueTeam.detectionRules.sigmaYaml);
    lines.push('```');
    lines.push(``);
  }

  lines.push(`---`);
  lines.push(`*Report generated by [ClassiGuard CyFence](https://github.com/classiguard/cyfence)*`);

  const content = lines.join('\n');
  await fs.writeFile(filePath, content, 'utf8');
  return filePath;
}

// --- End: src/reporter/markdown.mjs ---


// --- Start: src/reporter/webhook.mjs ---
/**
 * Security Operations Webhook Dispatcher (Slack / Discord / Teams)
 */



/**
 * Dispatches an audit alert payload to a Slack/Discord/Teams webhook
 * @param {string} webhookUrl - Incoming webhook URL
 * @param {object} auditResult - Output of engine run
 * @returns {Promise<{success: boolean, error?: string, status?: number}>}
 */
async function sendWebhookAlert(webhookUrl, auditResult) {
  if (!webhookUrl) return { success: false, error: 'No webhook URL provided' };

  const { targetUrl, compliance, findings } = auditResult;
  const { score, grade, counts } = compliance;

  const defects = findings.filter(f => f.severity !== 'PASS');
  const criticalAndHigh = defects.filter(f => f.severity === 'CRITICAL' || f.severity === 'HIGH');

  // Generic Markdown payload compatible with Slack, Discord, and Teams
  const payload = {
    username: 'ClassiGuard CyFence Bot',
    content: `🛡️ **ClassiGuard CyFence Security Assessment Completed**\n**Target:** \`${targetUrl}\`\n**Score:** **${score}/100** (Grade: **${grade}**)\n**Findings:** ${counts.critical} Critical, ${counts.high} High, ${counts.medium} Medium, ${counts.low} Low\n` +
      (criticalAndHigh.length > 0
        ? `\n🚨 **Priority Defects:**\n${criticalAndHigh.slice(0, 5).map(d => `• [${d.severity}] ${d.title}`).join('\n')}`
        : '✨ No critical or high severity defects detected.')
  };

  try {
    const res = await safeFetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      timeout: 5000
    });

    return { success: res.status >= 200 && res.status < 300, status: res.status };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

// --- End: src/reporter/webhook.mjs ---


// --- Start: src/batch/batchAuditor.mjs ---
/**
 * Batch & Multi-Target Auditing Subsystem
 * Executes audits across multiple endpoints with aggregated matrix reporting
 */





/**
 * Loads target URLs from a plain text file (one per line)
 * @param {string} filePath - Path to targets text file
 * @returns {Promise<string[]>} Array of valid target URLs
 */
async function loadTargetsFromFile(filePath) {
  const content = await fs.readFile(filePath, 'utf8');
  return content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'));
}

/**
 * Runs audits sequentially or with concurrency across multiple targets
 * @param {string[]} targets - Array of target URLs
 * @param {object} [options] - Options passed to auditUrl
 * @returns {Promise<object[]>} Array of audit results
 */
async function auditBatch(targets, options = {}) {
  const results = [];
  console.log(`\n📋 Initiating batch audit across ${targets.length} target(s)...\n`);

  for (let i = 0; i < targets.length; i++) {
    let url = targets[i];
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    console.log(`[${i + 1}/${targets.length}] Auditing: ${url}...`);
    try {
      const res = await auditUrl(url, options);
      results.push(res);
      console.log(`       Score: ${res.compliance.score}/100 (Grade: ${res.compliance.grade}) | Defects: ${res.compliance.totalDefects}`);
    } catch (err) {
      console.error(`       Failed to audit ${url}: ${err.message}`);
      results.push({
        targetUrl: url,
        timestamp: new Date().toISOString(),
        error: err.message,
        compliance: { score: 0, grade: 'F', counts: { total: 0, passed: 0, critical: 1, high: 0, medium: 0, low: 0, info: 0 }, totalDefects: 1 },
        findings: [{ id: 'SEC-BATCH-ERR', title: 'Target Execution Failure', severity: 'CRITICAL', standard: 'Operational', details: err.message }]
      });
    }
  }

  return results;
}

/**
 * Prints an aggregated terminal summary matrix for batch results
 * @param {object[]} batchResults - Output from auditBatch
 */
function printBatchTerminal(batchResults) {
  console.log(`\n========================================================================================================`);
  console.log(`  📊 CLASSIGUARD CYFENCE: BATCH ASSESSMENT SUMMARY MATRIX`);
  console.log(`========================================================================================================`);
  console.log(`  Target URL                                   | Score | Grade | Crit | High | Med  | Low  | Pass `);
  console.log(`--------------------------------------------------------------------------------------------------------`);

  for (const r of batchResults) {
    const padUrl = r.targetUrl.padEnd(42).slice(0, 42);
    const score = String(r.compliance.score).padStart(3) + '/100';
    const grade = (r.compliance.grade || 'F').padStart(2);
    const crit = String(r.compliance.counts.critical).padStart(4);
    const high = String(r.compliance.counts.high).padStart(4);
    const med = String(r.compliance.counts.medium).padStart(4);
    const low = String(r.compliance.counts.low).padStart(4);
    const pass = String(r.compliance.counts.passed).padStart(4);

    console.log(`  ${padUrl} | ${score} |   ${grade}  | ${crit} | ${high} | ${med} | ${low} | ${pass} `);
  }

  console.log(`========================================================================================================\n`);
}

/**
 * Writes an aggregated multi-target HTML report
 * @param {object[]} batchResults - Array of audit results
 * @param {string} filePath - Path to save the HTML file
 * @returns {Promise<string>} Written file path
 */
async function writeBatchHtmlReport(batchResults, filePath) {
  const dir = path.dirname(filePath);
  if (dir && dir !== '.') {
    await fs.mkdir(dir, { recursive: true });
  }

  const avgScore = Math.round(batchResults.reduce((acc, r) => acc + (r.compliance.score || 0), 0) / (batchResults.length || 1));
  const totalCritical = batchResults.reduce((acc, r) => acc + (r.compliance.counts.critical || 0), 0);
  const totalHigh = batchResults.reduce((acc, r) => acc + (r.compliance.counts.high || 0), 0);

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ClassiGuard CyFence: Batch Security Assessment</title>
  <style>
    body { background: #0b0f19; color: #f9fafb; font-family: -apple-system, sans-serif; padding: 2rem; }
    .container { max-width: 1200px; margin: 0 auto; }
    h1 { margin-bottom: 0.5rem; font-size: 1.8rem; }
    .subtitle { color: #9ca3af; margin-bottom: 2rem; }
    table { width: 100%; border-collapse: collapse; background: #111827; border-radius: 8px; overflow: hidden; margin-top: 1rem; }
    th, td { padding: 1rem; text-align: left; border-bottom: 1px solid #1f2937; }
    th { background: #1f2937; color: #93c5fd; font-size: 0.85rem; text-transform: uppercase; }
    .grade-A { color: #10b981; font-weight: bold; }
    .grade-B { color: #3b82f6; font-weight: bold; }
    .grade-C { color: #f59e0b; font-weight: bold; }
    .grade-D, .grade-F { color: #ef4444; font-weight: bold; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ ClassiGuard CyFence: Multi-Target Assessment Summary</h1>
    <div class="subtitle">Evaluated ${batchResults.length} target(s) &bull; Average Score: <strong>${avgScore}/100</strong> &bull; Total Critical Defects: <strong>${totalCritical}</strong> &bull; Total High Defects: <strong>${totalHigh}</strong></div>
    <table>
      <thead>
        <tr>
          <th>Target URL</th>
          <th>Score</th>
          <th>Grade</th>
          <th>Critical</th>
          <th>High</th>
          <th>Medium</th>
          <th>Low</th>
          <th>Passed</th>
        </tr>
      </thead>
      <tbody>
        ${batchResults.map(r => `
        <tr>
          <td><a href="${r.targetUrl}" target="_blank" style="color: #93c5fd; text-decoration: none;">${r.targetUrl}</a></td>
          <td><strong>${r.compliance.score}/100</strong></td>
          <td class="grade-${r.compliance.grade}">${r.compliance.grade}</td>
          <td style="color: ${r.compliance.counts.critical > 0 ? '#ef4444' : 'inherit'}; font-weight: ${r.compliance.counts.critical > 0 ? 'bold' : 'normal'};">${r.compliance.counts.critical}</td>
          <td style="color: ${r.compliance.counts.high > 0 ? '#f59e0b' : 'inherit'};">${r.compliance.counts.high}</td>
          <td>${r.compliance.counts.medium}</td>
          <td>${r.compliance.counts.low}</td>
          <td style="color: #10b981;">${r.compliance.counts.passed}</td>
        </tr>`).join('\n')}
      </tbody>
    </table>
  </div>
</body>
</html>`;

  await fs.writeFile(filePath, html, 'utf8');
  return filePath;
}

// --- End: src/batch/batchAuditor.mjs ---


// --- Start: src/server/guiServer.mjs ---
/**
 * Embedded Local Web GUI Dashboard & Enterprise Security Suite Server
 * Zero external dependencies, pure Node.js HTTP server
 * 100% self-contained (air-gapped and offline friendly)
 * Hardened with Anti-CSRF nonces, strict 127.0.0.1 binding, defensive CSP/security headers, and DOM XSS protection.
 */






/**
 * Defensive Security Headers enforced on all Web GUI HTTP responses
 */
const DEFENSIVE_HEADERS = {
  'Content-Security-Policy': "default-src 'self' 'unsafe-inline' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none';",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store, no-cache, must-revalidate, private'
};

/**
 * Opens a URL in the user's default web browser across Windows, macOS, and Linux
 * @param {string} url - Target URL to launch
 */
function openBrowser(url) {
  try {
    const platform = process.platform;
    let cmd = '';
    if (platform === 'win32') {
      cmd = `start "" "${url}"`;
    } else if (platform === 'darwin') {
      cmd = `open "${url}"`;
    } else {
      cmd = `xdg-open "${url}"`;
    }
    exec(cmd, () => {});
  } catch {
    // Graceful fallback if shell launch fails
  }
}

/**
 * Starts the embedded ClassiGuard CyFence Web GUI server
 * @param {number} [port=9090] - Port to listen on
 * @param {string} [host='127.0.0.1'] - Interface to bind on (defaults to loopback for security)
 * @param {object} [options] - Server options
 * @param {boolean} [options.autoOpen=false] - Whether to launch the browser automatically
 * @returns {Promise<http.Server>} Active HTTP server instance
 */
function startGuiServer(port = 9090, host = '127.0.0.1', options = {}) {
  return new Promise((resolve, reject) => {
    // Generate an ephemeral cryptographic anti-CSRF token per server session
    const csrfToken = crypto.randomBytes(24).toString('hex');

    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url, `http://${req.headers.host || '127.0.0.1'}`);
      const pathname = url.pathname;

      // Security Guard: Verify Origin on state-changing API endpoints
      if (pathname.startsWith('/api/') && req.method === 'POST') {
        const origin = req.headers.origin;
        if (origin) {
          try {
            const parsedOrigin = new URL(origin);
            if (parsedOrigin.hostname !== '127.0.0.1' && parsedOrigin.hostname !== 'localhost') {
              res.writeHead(403, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
              res.end(JSON.stringify({ error: 'Forbidden: Cross-Origin Request Blocked by CyFence CSRF Guard.' }));
              return;
            }
          } catch {
            res.writeHead(403, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify({ error: 'Forbidden: Malformed Origin header.' }));
            return;
          }
        }

        const clientToken = req.headers['x-cyfence-token'];
        if (clientToken !== csrfToken) {
          res.writeHead(403, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
          res.end(JSON.stringify({ error: 'Forbidden: Invalid or missing CSRF security token.' }));
          return;
        }
      }

      // 1. API: POST /api/audit (Single Target Audit)
      if (pathname === '/api/audit' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
          body += chunk;
          if (body.length > 131072) req.destroy();
        });

        req.on('end', async () => {
          try {
            const data = JSON.parse(body || '{}');
            const targetUrl = data.url;
            if (!targetUrl) {
              res.writeHead(400, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
              res.end(JSON.stringify({ error: 'Missing target URL' }));
              return;
            }

            let parsedTarget;
            try {
              parsedTarget = new URL(targetUrl);
              if (parsedTarget.protocol !== 'http:' && parsedTarget.protocol !== 'https:') {
                res.writeHead(400, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
                res.end(JSON.stringify({ error: 'Target URL must use http: or https: protocol.' }));
                return;
              }
            } catch {
              res.writeHead(400, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
              res.end(JSON.stringify({ error: 'Malformed target URL provided.' }));
              return;
            }

            console.log(`[CyFence GUI] Auditing single target: ${targetUrl}`);
            const result = await auditUrl(targetUrl, {
              skipRoutes: data.skipRoutes || false,
              jwt: data.jwt || null,
              headers: data.headers || {},
              ai: data.enableAi ? {
                provider: data.aiProvider || 'ollama',
                model: data.aiModel || null,
                apiKey: data.aiKey || null,
                endpoint: data.aiEndpoint || null
              } : null
            });

            res.writeHead(200, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify(result));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }

      // 2. API: POST /api/batch (Multi-Target Batch Audit)
      if (pathname === '/api/batch' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
          body += chunk;
          if (body.length > 262144) req.destroy();
        });

        req.on('end', async () => {
          try {
            const data = JSON.parse(body || '{}');
            const rawUrls = Array.isArray(data.urls) ? data.urls : [];
            const targets = rawUrls.map(u => String(u || '').trim()).filter(u => u && !u.startsWith('#'));

            if (targets.length === 0) {
              res.writeHead(400, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
              res.end(JSON.stringify({ error: 'No valid target URLs provided for batch execution.' }));
              return;
            }

            console.log(`[CyFence GUI] Running batch audit across ${targets.length} targets...`);
            const batchResults = await auditBatch(targets, {
              skipRoutes: data.skipRoutes || false
            });

            const avgScore = Math.round(batchResults.reduce((acc, r) => acc + (r.compliance?.score || 0), 0) / (batchResults.length || 1));
            const totalCritical = batchResults.reduce((acc, r) => acc + (r.compliance?.counts?.critical || 0), 0);
            const totalHigh = batchResults.reduce((acc, r) => acc + (r.compliance?.counts?.high || 0), 0);
            const totalPassed = batchResults.reduce((acc, r) => acc + (r.compliance?.counts?.passed || 0), 0);

            res.writeHead(200, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify({
              count: targets.length,
              avgScore,
              totalCritical,
              totalHigh,
              totalPassed,
              results: batchResults
            }));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }

      // 3. API: POST /api/diff (Posture Drift & Regression Diff)
      if (pathname === '/api/diff' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
          body += chunk;
          if (body.length > 262144) req.destroy();
        });

        req.on('end', async () => {
          try {
            const data = JSON.parse(body || '{}');
            if (!data.base || !data.current) {
              res.writeHead(400, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
              res.end(JSON.stringify({ error: 'Both baseline and current audit JSON objects are required.' }));
              return;
            }

            const diff = computeAuditDiff(data.base, data.current);
            res.writeHead(200, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify(diff));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }

      // 4. API: POST /api/ai/advise (AI Security Advisor Call)
      if (pathname === '/api/ai/advise' && req.method === 'POST') {
        let body = '';
        req.on('data', chunk => {
          body += chunk;
          if (body.length > 131072) req.destroy();
        });

        req.on('end', async () => {
          try {
            const data = JSON.parse(body || '{}');
            const auditResult = data.result;
            if (!auditResult || !auditResult.findings) {
              res.writeHead(400, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
              res.end(JSON.stringify({ error: 'Valid audit result object is required for AI synthesis.' }));
              return;
            }

            const advisory = await getAiSecurityAdvisory(auditResult, {
              provider: data.provider || 'ollama',
              model: data.model || null,
              apiKey: data.apiKey || null,
              endpoint: data.endpoint || null
            });

            res.writeHead(200, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify(advisory));
          } catch (err) {
            res.writeHead(500, { 'Content-Type': 'application/json', ...DEFENSIVE_HEADERS });
            res.end(JSON.stringify({ error: err.message }));
          }
        });
        return;
      }

      // Root GUI Dashboard Page: GET / or /index.html
      if (pathname === '/' || pathname === '/index.html') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', ...DEFENSIVE_HEADERS });
        res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="cyfence-token" content="${csrfToken}">
  <title>ClassiGuard CyFence: Complete Defensive Security Suite</title>
  <style>
    :root {
      --bg: #0b0f19; --card: #111827; --card-hover: #172033; --border: #1f2937; --text: #f9fafb;
      --muted: #9ca3af; --primary: #3b82f6; --primary-hover: #2563eb; --red: #ef4444; --yellow: #f59e0b;
      --green: #10b981; --purple: #a855f7; --cyan: #06b6d4;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; padding: 1.5rem; line-height: 1.5; }
    .container { max-width: 1200px; margin: 0 auto; }
    
    /* Header */
    header { display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.25rem; margin-bottom: 1.5rem; flex-wrap: wrap; gap: 1rem; }
    .brand { display: flex; align-items: center; gap: 0.75rem; }
    .brand-icon { width: 42px; height: 42px; background: rgba(59, 130, 246, 0.2); border: 1px solid rgba(59, 130, 246, 0.4); border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 1.4rem; }
    .brand h1 { font-size: 1.4rem; color: #fff; font-weight: 700; letter-spacing: -0.02em; }
    .brand p { color: var(--muted); font-size: 0.8rem; }
    .badges-row { display: flex; gap: 0.5rem; align-items: center; }
    .badge-pill { padding: 0.3rem 0.65rem; border-radius: 999px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
    .pill-green { background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.3); }
    .pill-blue { background: rgba(59, 130, 246, 0.15); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }

    /* Navigation Bar */
    .nav-bar { display: flex; gap: 0.4rem; background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 0.35rem; margin-bottom: 1.5rem; overflow-x: auto; }
    .nav-btn { flex: 1; min-width: 140px; padding: 0.65rem 0.9rem; background: transparent; border: none; color: var(--muted); font-weight: 600; font-size: 0.85rem; border-radius: 7px; cursor: pointer; transition: all 0.15s; display: flex; align-items: center; justify-content: center; gap: 0.4rem; }
    .nav-btn:hover { color: #fff; background: var(--card-hover); }
    .nav-btn.active { color: #fff; background: var(--primary); box-shadow: 0 2px 4px rgba(0,0,0,0.2); }

    /* View Sections */
    .view-section { display: none; }
    .view-section.active { display: block; }

    /* Cards & Inputs */
    .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.25rem; margin-bottom: 1.25rem; }
    .card-title { font-size: 1rem; font-weight: 700; color: #fff; margin-bottom: 0.35rem; display: flex; align-items: center; justify-content: space-between; }
    .card-subtitle { font-size: 0.8rem; color: var(--muted); margin-bottom: 1rem; }
    
    .input-row { display: flex; gap: 0.75rem; margin-bottom: 1rem; flex-wrap: wrap; }
    input[type="text"], input[type="password"], textarea, select { flex: 1; background: #030712; border: 1px solid var(--border); color: #fff; padding: 0.7rem 0.9rem; border-radius: 6px; font-size: 0.9rem; outline: none; font-family: inherit; }
    input:focus, textarea:focus, select:focus { border-color: var(--primary); }
    button.btn-primary { background: var(--primary); color: #fff; border: none; padding: 0.7rem 1.4rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.9rem; transition: background 0.15s; white-space: nowrap; }
    button.btn-primary:hover { background: var(--primary-hover); }
    button.btn-secondary { background: #1f2937; color: #d1d5db; border: 1px solid #374151; padding: 0.7rem 1.2rem; border-radius: 6px; font-weight: 600; cursor: pointer; font-size: 0.85rem; transition: background 0.15s; }
    button.btn-secondary:hover { background: #374151; color: #fff; }

    .options-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.75rem; margin-bottom: 1rem; font-size: 0.85rem; color: var(--muted); }
    .options-grid label { display: flex; align-items: center; gap: 0.5rem; cursor: pointer; }

    /* Results Dashboard Grid */
    .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
    .score-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; text-align: center; }
    .score-card .title { font-size: 0.75rem; color: var(--muted); text-transform: uppercase; font-weight: 700; letter-spacing: 0.05em; }
    .score-card .value { font-size: 2.2rem; font-weight: 800; margin-top: 0.25rem; }

    /* Filter Bar */
    .filter-bar { display: flex; gap: 0.4rem; margin-bottom: 1rem; flex-wrap: wrap; }
    .filter-btn { padding: 0.35rem 0.75rem; border-radius: 6px; font-size: 0.75rem; font-weight: 600; background: #1f2937; color: var(--muted); border: 1px solid #374151; cursor: pointer; }
    .filter-btn.active { background: var(--primary); color: #fff; border-color: var(--primary); }

    /* Findings Items */
    .finding-item { background: #0c1220; border: 1px solid var(--border); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; transition: border-color 0.15s; }
    .finding-item:hover { border-color: #374151; }
    .badge { display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; text-transform: uppercase; margin-right: 0.5rem; }
    .badge-CRITICAL { background: rgba(239, 68, 68, 0.2); color: var(--red); border: 1px solid var(--red); }
    .badge-HIGH { background: rgba(245, 158, 11, 0.2); color: var(--yellow); border: 1px solid var(--yellow); }
    .badge-MEDIUM { background: rgba(168, 85, 247, 0.2); color: #c084fc; border: 1px solid #c084fc; }
    .badge-LOW { background: rgba(6, 182, 212, 0.2); color: #22d3ee; border: 1px solid #22d3ee; }
    .badge-PASS { background: rgba(16, 185, 129, 0.2); color: var(--green); border: 1px solid var(--green); }

    pre { background: #030712; padding: 1rem; border-radius: 6px; border: 1px solid var(--border); overflow-x: auto; font-family: monospace; font-size: 0.85rem; color: #7dd3fc; margin-top: 0.5rem; }
    .spinner { display: none; text-align: center; padding: 2rem; color: var(--muted); font-size: 1rem; }
    
    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }
    th { background: #070b14; color: #93c5fd; font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div>
          <h1>ClassiGuard CyFence</h1>
          <p>Enterprise Defensive Web Posture & Compliance Suite &bull; Zero External Dependencies</p>
        </div>
      </div>
      <div class="badges-row">
        <span class="badge-pill pill-green">● Local Loopback (127.0.0.1)</span>
        <span class="badge-pill pill-blue">CSRF Guard Active</span>
        <span class="badge-pill pill-green">Air-Gapped Ready</span>
      </div>
    </header>

    <!-- Top Navigation Bar -->
    <nav class="nav-bar">
      <button class="nav-btn active" onclick="switchView('view-single')">🚀 Single Audit</button>
      <button class="nav-btn" onclick="switchView('view-batch')">📋 Multi-Target Batch</button>
      <button class="nav-btn" onclick="switchView('view-diff')">⚖️ Drift & Diff</button>
      <button class="nav-btn" onclick="switchView('view-hardening')">🛡️ Blue Team Auto-Patch</button>
      <button class="nav-btn" onclick="switchView('view-ai')">🤖 AI Security Advisor</button>
      <button class="nav-btn" onclick="switchView('view-tour')">📖 Tour & Architecture</button>
    </nav>

    <!-- VIEW 1: SINGLE TARGET AUDIT -->
    <div id="view-single" class="view-section active">
      <div class="card">
        <div class="card-title">
          <span>Target Security Posture Audit</span>
          <div style="display: flex; gap: 0.5rem;">
            <button class="btn-secondary" onclick="exportReport('html')" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;">Export HTML</button>
            <button class="btn-secondary" onclick="exportReport('json')" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;">Export JSON</button>
            <button class="btn-secondary" onclick="exportReport('md')" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;">Export MD</button>
          </div>
        </div>
        <p class="card-subtitle">Performs comprehensive defensive verifications across OWASP ASVS v4.0, MITRE ATT&CK, D3FEND, and RFC 8725.</p>

        <div class="input-row">
          <input type="text" id="targetUrl" placeholder="Enter target URL (e.g. https://example.com or http://localhost:8080/insecure)" value="http://localhost:8080/insecure">
          <button class="btn-primary" id="scanBtn" onclick="runSingleAudit()">🚀 Launch Audit</button>
        </div>

        <div class="options-grid">
          <label><input type="checkbox" id="optRoutes" checked> Scan Sensitive Metadata (/.git, /.env)</label>
          <label><input type="checkbox" id="optAi"> Enable AI Security Advisor</label>
          <label><input type="checkbox" id="optCustomHeaders"> Send Custom Audit Headers</label>
          <label><input type="checkbox" id="optJwt"> Provide Target JWT for RFC 8725</label>
        </div>

        <div id="customHeadersBox" style="display: none; margin-bottom: 1rem;">
          <input type="text" id="customHeaderInput" placeholder="Custom headers in JSON format (e.g. {&quot;Authorization&quot;: &quot;Bearer token&quot;})">
        </div>

        <div id="jwtBox" style="display: none; margin-bottom: 1rem;">
          <input type="text" id="jwtInput" placeholder="Paste raw JWT (header.payload.signature) to audit for alg:none and expiration">
        </div>
      </div>

      <div id="singleSpinner" class="spinner">🔍 Executing security verifications across OWASP ASVS, ATT&CK, and D3FEND...</div>

      <div id="singleResults" style="display: none;">
        <div class="summary-grid">
          <div class="score-card">
            <div class="title">ASVS Compliance Score</div>
            <div class="value" id="scoreVal">--/100</div>
          </div>
          <div class="score-card">
            <div class="title">Security Grade</div>
            <div class="value" id="gradeVal">-</div>
          </div>
          <div class="score-card">
            <div class="title">Critical & High Defects</div>
            <div class="value" id="critHighVal" style="color: var(--red);">0</div>
          </div>
          <div class="score-card">
            <div class="title">Controls Verified</div>
            <div class="value" id="passVal" style="color: var(--green);">0</div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">
            <span>Defensive Audit Findings</span>
            <div class="filter-bar" style="margin-bottom: 0;">
              <button class="filter-btn active" onclick="filterFindings('ALL', this)">All</button>
              <button class="filter-btn" onclick="filterFindings('CRITICAL', this)">Critical</button>
              <button class="filter-btn" onclick="filterFindings('HIGH', this)">High</button>
              <button class="filter-btn" onclick="filterFindings('MEDIUM', this)">Medium</button>
              <button class="filter-btn" onclick="filterFindings('LOW', this)">Low</button>
              <button class="filter-btn" onclick="filterFindings('PASS', this)">Passed</button>
            </div>
          </div>
          <div id="findingsContainer"></div>
        </div>
      </div>
    </div>

    <!-- VIEW 2: MULTI-TARGET BATCH AUDIT -->
    <div id="view-batch" class="view-section">
      <div class="card">
        <div class="card-title">Multi-Target Batch Auditing Engine</div>
        <p class="card-subtitle">Execute audits across enterprise fleets or multiple internal microservices simultaneously.</p>

        <div style="margin-bottom: 1rem;">
          <label style="display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.4rem;">Target URLs (One per line):</label>
          <textarea id="batchUrls" rows="6" placeholder="https://app1.company.internal&#10;https://app2.company.internal/api&#10;http://localhost:8080/insecure">http://localhost:8080/insecure&#10;https://example.com</textarea>
        </div>

        <div style="display: flex; gap: 0.75rem; align-items: center;">
          <button class="btn-primary" onclick="runBatchAudit()">📋 Launch Fleet Batch Audit</button>
          <button class="btn-secondary" onclick="loadSampleTargets()">Load Sample Targets</button>
        </div>
      </div>

      <div id="batchSpinner" class="spinner">⏳ Processing multi-target batch audit...</div>

      <div id="batchResults" style="display: none;" class="card">
        <div class="card-title">
          <span>Fleet Assessment Summary Matrix</span>
          <span id="batchSummaryStats" style="font-size: 0.8rem; color: var(--muted);"></span>
        </div>
        <table>
          <thead>
            <tr>
              <th>Target URL</th>
              <th>Score</th>
              <th>Grade</th>
              <th>Critical</th>
              <th>High</th>
              <th>Medium</th>
              <th>Low</th>
              <th>Passed</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="batchTableBody"></tbody>
        </table>
      </div>
    </div>

    <!-- VIEW 3: POSTURE DRIFT & DIFF -->
    <div id="view-diff" class="view-section">
      <div class="card">
        <div class="card-title">Configuration Drift & Regression Analysis (Diff)</div>
        <p class="card-subtitle">Compare two audit runs across deployment cycles to track resolved issues and catch security regressions.</p>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem;">
          <div>
            <label style="display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.4rem;">Baseline Audit JSON:</label>
            <textarea id="diffBaseJson" rows="8" placeholder="Paste baseline JSON report..."></textarea>
          </div>
          <div>
            <label style="display: block; font-size: 0.8rem; color: var(--muted); margin-bottom: 0.4rem;">Current Audit JSON:</label>
            <textarea id="diffCurrentJson" rows="8" placeholder="Paste latest JSON report..."></textarea>
          </div>
        </div>

        <div style="display: flex; gap: 0.75rem;">
          <button class="btn-primary" onclick="runDiffAnalysis()">⚖️ Compare Audits</button>
          <button class="btn-secondary" onclick="loadDiffSamples()">Load Sample Baseline & Current</button>
        </div>
      </div>

      <div id="diffResults" style="display: none;" class="card">
        <div class="card-title">
          <span>Posture Drift Summary</span>
          <span id="diffStatusBadge" class="badge-pill pill-green">STATUS</span>
        </div>
        <div class="summary-grid" style="margin-top: 1rem;">
          <div class="score-card">
            <div class="title">Baseline Score</div>
            <div class="value" id="diffBaseScore">--</div>
          </div>
          <div class="score-card">
            <div class="title">Current Score</div>
            <div class="value" id="diffCurrentScore">--</div>
          </div>
          <div class="score-card">
            <div class="title">Score Delta</div>
            <div class="value" id="diffScoreDelta">--</div>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-top: 1rem;">
          <div style="background: rgba(239,68,68,0.05); border: 1px solid rgba(239,68,68,0.2); border-radius: 8px; padding: 1rem;">
            <h4 style="color: var(--red); font-size: 0.9rem; margin-bottom: 0.5rem;">🚨 New Vulnerabilities / Regressions</h4>
            <div id="diffNewDefectsList" style="font-size: 0.85rem;">None</div>
          </div>
          <div style="background: rgba(16,185,129,0.05); border: 1px solid rgba(16,185,129,0.2); border-radius: 8px; padding: 1rem;">
            <h4 style="color: var(--green); font-size: 0.9rem; margin-bottom: 0.5rem;">✅ Resolved Vulnerabilities</h4>
            <div id="diffResolvedDefectsList" style="font-size: 0.85rem;">None</div>
          </div>
        </div>
      </div>
    </div>

    <!-- VIEW 4: BLUE TEAM AUTO-REMEDIATION & SIEM -->
    <div id="view-hardening" class="view-section">
      <div class="card">
        <div class="card-title">
          <span>Blue Team: Auto-Remediation & SIEM Rules</span>
          <div style="display: flex; gap: 0.5rem;">
            <button class="btn-secondary" onclick="copyActiveCode()" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;">📋 Copy</button>
            <button class="btn-secondary" onclick="downloadActiveCode()" style="padding: 0.4rem 0.8rem; font-size: 0.75rem;">💾 Download</button>
          </div>
        </div>
        <p class="card-subtitle">Ready-to-deploy configuration snippets and SIEM rules generated directly from your audit results.</p>

        <div class="filter-bar">
          <button class="filter-btn active" onclick="switchHardeningTab('nginx', this)">Nginx Configuration</button>
          <button class="filter-btn" onclick="switchHardeningTab('apache', this)">Apache (.htaccess)</button>
          <button class="filter-btn" onclick="switchHardeningTab('caddy', this)">Caddyfile</button>
          <button class="filter-btn" onclick="switchHardeningTab('sigma', this)">Sigma Rule (YAML)</button>
          <button class="filter-btn" onclick="switchHardeningTab('elastic', this)">Elasticsearch Query DSL</button>
        </div>

        <pre><code id="activeCodeBlock">Run an audit first to generate targeted server remediation snippets.</code></pre>
      </div>
    </div>

    <!-- VIEW 5: AI SECURITY ADVISOR -->
    <div id="view-ai" class="view-section">
      <div class="card">
        <div class="card-title">AI Security Advisor & Synthesis</div>
        <p class="card-subtitle">Multi-provider synthesis with Ollama (Air-Gapped Local), Anthropic Claude, and OpenAI.</p>

        <div style="background: rgba(245,158,11,0.1); border: 1px solid var(--yellow); padding: 1rem; border-radius: 8px; margin-bottom: 1rem; color: #fbbf24; font-size: 0.85rem;">
          ⚠️ <strong>MANDATORY HUMAN APPROVAL ENFORCED</strong>: AI provides assistive proposals only. Explicit engineering approval and staging verification are required prior to applying changes.
        </div>

        <div class="options-grid">
          <div>
            <label style="display: block; margin-bottom: 0.3rem;">AI Provider:</label>
            <select id="aiProviderSelect" style="width: 100%;">
              <option value="ollama">Ollama (100% Offline / Air-Gapped Llama 3)</option>
              <option value="claude">Anthropic Claude (claude-3-5-sonnet)</option>
              <option value="openai">OpenAI (gpt-4o-mini)</option>
            </select>
          </div>
          <div>
            <label style="display: block; margin-bottom: 0.3rem;">API Key (If Cloud):</label>
            <input type="password" id="aiApiKeyInput" placeholder="Optional API Key">
          </div>
        </div>

        <button class="btn-primary" onclick="requestAiAdvisory()" style="margin-top: 0.5rem;">🤖 Synthesize AI Remediation Advisory</button>
      </div>

      <div id="aiAdvisoryCard" class="card" style="display: none;">
        <div class="card-title">
          <span>AI Remediation Proposal</span>
          <span id="aiModelBadge" class="badge-pill pill-blue">MODEL</span>
        </div>
        <div id="aiAdvisoryText" style="white-space: pre-wrap; font-size: 0.9rem; color: #e5e7eb; margin-bottom: 1rem; line-height: 1.6;"></div>

        <div style="border-top: 1px solid var(--border); padding-top: 1rem; display: flex; justify-content: space-between; align-items: center; flex-wrap: gap;">
          <span style="font-size: 0.8rem; color: var(--yellow);">🔒 Status: Awaiting Human Engineer Review</span>
          <div style="display: flex; gap: 0.5rem;">
            <button class="btn-secondary" onclick="logApproval(false)" style="color: var(--red);">✕ Reject Proposal</button>
            <button class="btn-primary" onclick="logApproval(true)">✓ Approve for Staging</button>
          </div>
        </div>
        <div id="approvalStatusLog" style="display: none; margin-top: 0.75rem; font-size: 0.8rem; font-family: monospace;"></div>
      </div>
    </div>

    <!-- VIEW 6: PRODUCT TOUR & DOCS -->
    <div id="view-tour" class="view-section">
      <div class="card">
        <div class="card-title">ClassiGuard CyFence: Architecture & Tour</div>
        <p class="card-subtitle">Zero-dependency security assessment engine aligned with OWASP ASVS v4.0 and MITRE ATT&CK.</p>

        <div class="summary-grid">
          <div class="score-card">
            <div class="title">Runtime Dependencies</div>
            <div class="value" style="color: var(--green);">0</div>
          </div>
          <div class="score-card">
            <div class="title">Scale Stress Test</div>
            <div class="value" style="color: var(--primary);">50,000</div>
          </div>
          <div class="score-card">
            <div class="title">Audit Throughput</div>
            <div class="value" style="color: var(--cyan);">149k/s</div>
          </div>
          <div class="score-card">
            <div class="title">VAPT Remediations</div>
            <div class="value" style="color: var(--green);">8 / 8</div>
          </div>
        </div>

        <div style="margin-top: 1rem;">
          <h3 style="font-size: 1rem; color: #fff; margin-bottom: 0.5rem;">Quick Start CLI & Shortcuts</h3>
          <pre><code># Run Single Audit via Standalone Binary
cyfence.exe https://example.com --html audit.html

# Run Multi-Target Fleet Audit
cyfence.exe --targets targets.txt --html batch-summary.html

# Compare Posture Drift
cyfence.exe diff baseline.json current.json

# Auto-Hardening Snippets Export
cyfence.exe https://example.com --remediation --export-configs reports/hardening/</code></pre>
        </div>
      </div>
    </div>
  </div>

  <script>
    const csrfToken = document.querySelector('meta[name="cyfence-token"]').getAttribute('content');
    let currentAuditData = null;
    let activeHardeningCode = '';

    function escapeHtml(str) {
      if (!str) return '';
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
    }

    function switchView(viewId) {
      document.querySelectorAll('.view-section').forEach(v => v.classList.remove('active'));
      document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
      document.getElementById(viewId).classList.add('active');
      event.target.classList.add('active');
    }

    document.getElementById('optCustomHeaders').addEventListener('change', (e) => {
      document.getElementById('customHeadersBox').style.display = e.target.checked ? 'block' : 'none';
    });

    document.getElementById('optJwt').addEventListener('change', (e) => {
      document.getElementById('jwtBox').style.display = e.target.checked ? 'block' : 'none';
    });

    // 1. Single Audit Execution
    async function runSingleAudit() {
      const url = document.getElementById('targetUrl').value.trim();
      if (!url) return alert('Please enter a target URL.');

      const skipRoutes = !document.getElementById('optRoutes').checked;
      const enableAi = document.getElementById('optAi').checked;
      let headers = {};
      if (document.getElementById('optCustomHeaders').checked) {
        try {
          headers = JSON.parse(document.getElementById('customHeaderInput').value || '{}');
        } catch {
          return alert('Invalid JSON in Custom Headers input.');
        }
      }
      const jwt = document.getElementById('optJwt').checked ? document.getElementById('jwtInput').value.trim() : null;

      document.getElementById('singleSpinner').style.display = 'block';
      document.getElementById('singleResults').style.display = 'none';

      try {
        const res = await fetch('/api/audit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CyFence-Token': csrfToken },
          body: JSON.stringify({ url, skipRoutes, enableAi, headers, jwt })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        currentAuditData = data;
        renderSingleResults(data);
      } catch (err) {
        alert('Audit execution failed: ' + err.message);
      } finally {
        document.getElementById('singleSpinner').style.display = 'none';
      }
    }

    function renderSingleResults(data) {
      document.getElementById('singleResults').style.display = 'block';
      const c = data.compliance;
      document.getElementById('scoreVal').innerText = c.score + '/100';
      document.getElementById('gradeVal').innerText = c.grade;
      document.getElementById('critHighVal').innerText = (c.counts.critical + c.counts.high);
      document.getElementById('passVal').innerText = c.counts.passed;

      filterFindings('ALL', document.querySelector('.filter-bar .filter-btn'));

      if (data.blueTeam) {
        switchHardeningTab('nginx');
      }
    }

    function filterFindings(sev, btn) {
      if (btn) {
        document.querySelectorAll('.filter-bar .filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      }
      if (!currentAuditData) return;

      const filtered = sev === 'ALL'
        ? currentAuditData.findings
        : currentAuditData.findings.filter(f => f.severity === sev);

      const container = document.getElementById('findingsContainer');
      container.innerHTML = filtered.map(f => {
        const safeSev = escapeHtml(f.severity);
        const safeTitle = escapeHtml(f.title);
        const safeStd = escapeHtml(f.standard);
        const safeCwe = f.cwe ? ' | CWE: ' + escapeHtml(f.cwe) : '';
        const safeAttack = f.attackId ? ' | ATT&CK: ' + escapeHtml(f.attackId) : '';
        const safeDetails = escapeHtml(f.details);
        const safeFix = f.remediation ? '<div style="margin-top: 0.5rem; font-size: 0.85rem; color: #6ee7b7;"><strong>Fix:</strong> ' + escapeHtml(f.remediation) + '</div>' : '';

        return \`
          <div class="finding-item">
            <div><span class="badge badge-\${safeSev}">\${safeSev}</span> <strong>\${safeTitle}</strong></div>
            <div style="font-size: 0.8rem; color: var(--muted); margin: 0.35rem 0;">Standard: \${safeStd}\${safeCwe}\${safeAttack}</div>
            <div style="font-size: 0.85rem; color: #d1d5db;">\${safeDetails}</div>
            \${safeFix}
          </div>
        \`;
      }).join('');
    }

    // 2. Batch Audit Execution
    async function runBatchAudit() {
      const raw = document.getElementById('batchUrls').value;
      const urls = raw.split('\\n').map(u => u.trim()).filter(u => u && !u.startsWith('#'));
      if (urls.length === 0) return alert('Please enter at least one target URL.');

      document.getElementById('batchSpinner').style.display = 'block';
      document.getElementById('batchResults').style.display = 'none';

      try {
        const res = await fetch('/api/batch', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CyFence-Token': csrfToken },
          body: JSON.stringify({ urls })
        });
        const data = await res.json();
        if (data.error) throw new Error(data.error);

        document.getElementById('batchResults').style.display = 'block';
        document.getElementById('batchSummaryStats').innerText = \`Evaluated \${data.count} target(s) &bull; Avg Score: \${data.avgScore}/100 &bull; Critical: \${data.totalCritical} &bull; High: \${data.totalHigh}\`;

        const tbody = document.getElementById('batchTableBody');
        tbody.innerHTML = data.results.map(r => \`
          <tr>
            <td><strong>\${escapeHtml(r.targetUrl)}</strong></td>
            <td><strong>\${r.compliance?.score || 0}/100</strong></td>
            <td><span class="badge badge-\${r.compliance?.grade || 'F'}">\${r.compliance?.grade || 'F'}</span></td>
            <td style="color: var(--red); font-weight: bold;">\${r.compliance?.counts?.critical || 0}</td>
            <td style="color: var(--yellow);">\${r.compliance?.counts?.high || 0}</td>
            <td>\${r.compliance?.counts?.medium || 0}</td>
            <td>\${r.compliance?.counts?.low || 0}</td>
            <td style="color: var(--green);">\${r.compliance?.counts?.passed || 0}</td>
            <td><button class="btn-secondary" style="padding: 0.2rem 0.5rem; font-size: 0.75rem;" onclick="loadBatchRowIntoSingle('\${encodeURIComponent(JSON.stringify(r))}')">Inspect</button></td>
          </tr>
        \`).join('');
      } catch (err) {
        alert('Batch audit failed: ' + err.message);
      } finally {
        document.getElementById('batchSpinner').style.display = 'none';
      }
    }

    function loadBatchRowIntoSingle(encoded) {
      const data = JSON.parse(decodeURIComponent(encoded));
      currentAuditData = data;
      document.getElementById('targetUrl').value = data.targetUrl;
      switchView('view-single');
      renderSingleResults(data);
    }

    function loadSampleTargets() {
      document.getElementById('batchUrls').value = "http://localhost:8080/insecure\\nhttps://example.com\\nhttps://httpbin.org/status/200";
    }

    // 3. Diff Analysis
    async function runDiffAnalysis() {
      let base, current;
      try {
        base = JSON.parse(document.getElementById('diffBaseJson').value);
        current = JSON.parse(document.getElementById('diffCurrentJson').value);
      } catch {
        return alert('Please enter valid JSON in both baseline and current boxes.');
      }

      try {
        const res = await fetch('/api/diff', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CyFence-Token': csrfToken },
          body: JSON.stringify({ base, current })
        });
        const diff = await res.json();
        if (diff.error) throw new Error(diff.error);

        document.getElementById('diffResults').style.display = 'block';
        document.getElementById('diffBaseScore').innerText = diff.baseScore + '/100';
        document.getElementById('diffCurrentScore').innerText = diff.currentScore + '/100';
        
        const delta = diff.scoreDelta;
        const deltaEl = document.getElementById('diffScoreDelta');
        deltaEl.innerText = (delta >= 0 ? '+' : '') + delta;
        deltaEl.style.color = delta >= 0 ? 'var(--green)' : 'var(--red)';

        const badge = document.getElementById('diffStatusBadge');
        badge.innerText = diff.status;
        badge.className = diff.status === 'IMPROVED' ? 'badge-pill pill-green' : (diff.status === 'DEGRADED' ? 'badge-pill' : 'badge-pill pill-blue');
        if (diff.status === 'DEGRADED') badge.style.cssText = 'background: rgba(239,68,68,0.2); color: var(--red); border: 1px solid var(--red);';

        // Lists
        const newBox = document.getElementById('diffNewDefectsList');
        newBox.innerHTML = diff.newDefects.length > 0
          ? diff.newDefects.map(d => \`<div style="margin-bottom: 0.35rem;">• [\${escapeHtml(d.severity)}] \${escapeHtml(d.title)}</div>\`).join('')
          : '<span style="color: var(--green);">✨ Zero new regressions detected.</span>';

        const resBox = document.getElementById('diffResolvedDefectsList');
        resBox.innerHTML = diff.resolvedDefects.length > 0
          ? diff.resolvedDefects.map(d => \`<div style="margin-bottom: 0.35rem;">• \${escapeHtml(d.title)}</div>\`).join('')
          : '<span style="color: var(--muted);">No defects resolved.</span>';

      } catch (err) {
        alert('Diff analysis failed: ' + err.message);
      }
    }

    function loadDiffSamples() {
      const sampleBase = {
        compliance: { score: 45, grade: 'D' },
        findings: [
          { id: 'SEC-HDR-01', severity: 'CRITICAL', title: 'Missing HSTS' },
          { id: 'SEC-HDR-02', severity: 'HIGH', title: 'Missing Content-Security-Policy' }
        ]
      };
      const sampleCurrent = {
        compliance: { score: 85, grade: 'B' },
        findings: [
          { id: 'SEC-HDR-01', severity: 'PASS', title: 'HSTS Present' },
          { id: 'SEC-HDR-02', severity: 'HIGH', title: 'Missing Content-Security-Policy' }
        ]
      };
      document.getElementById('diffBaseJson').value = JSON.stringify(sampleBase, null, 2);
      document.getElementById('diffCurrentJson').value = JSON.stringify(sampleCurrent, null, 2);
      runDiffAnalysis();
    }

    // 4. Blue Team Hardening Tab Controller
    function switchHardeningTab(type, btn) {
      if (btn) {
        document.querySelectorAll('#view-hardening .filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      }

      if (!currentAuditData || !currentAuditData.blueTeam) {
        document.getElementById('activeCodeBlock').innerText = 'Please run an audit on a target first.';
        return;
      }

      const bt = currentAuditData.blueTeam;
      if (type === 'nginx') activeHardeningCode = bt.hardeningConfigs.nginx;
      else if (type === 'apache') activeHardeningCode = bt.hardeningConfigs.apache;
      else if (type === 'caddy') activeHardeningCode = bt.hardeningConfigs.caddy;
      else if (type === 'sigma') activeHardeningCode = bt.detectionRules.sigmaYaml;
      else if (type === 'elastic') activeHardeningCode = bt.detectionRules.elasticQuery;

      document.getElementById('activeCodeBlock').innerText = activeHardeningCode;
    }

    function copyActiveCode() {
      if (!activeHardeningCode) return alert('No code to copy.');
      navigator.clipboard.writeText(activeHardeningCode);
      alert('Configuration copied to clipboard!');
    }

    function downloadActiveCode() {
      if (!activeHardeningCode) return alert('No code to download.');
      const blob = new Blob([activeHardeningCode], { type: 'text/plain' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'cyfence-remediation.conf';
      a.click();
    }

    // 5. AI Advisor Controller
    async function requestAiAdvisory() {
      if (!currentAuditData) return alert('Please run an audit first to generate context for the AI advisor.');

      const provider = document.getElementById('aiProviderSelect').value;
      const apiKey = document.getElementById('aiApiKeyInput').value.trim();

      document.getElementById('aiAdvisoryCard').style.display = 'block';
      document.getElementById('aiModelBadge').innerText = provider.toUpperCase();
      document.getElementById('aiAdvisoryText').innerText = '⏳ Synthesizing custom remediation advisory...';

      try {
        const res = await fetch('/api/ai/advise', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'X-CyFence-Token': csrfToken },
          body: JSON.stringify({ result: currentAuditData, provider, apiKey })
        });
        const data = await res.json();
        document.getElementById('aiAdvisoryText').innerText = data.advisory || 'No advisory generated.';
      } catch (err) {
        document.getElementById('aiAdvisoryText').innerText = 'AI request failed: ' + err.message;
      }
    }

    function logApproval(approved) {
      const log = document.getElementById('approvalStatusLog');
      log.style.display = 'block';
      if (approved) {
        log.style.color = 'var(--green)';
        log.innerText = \`✓ APPROVED BY OPERATOR: Staging patch execution authorized at \${new Date().toISOString()}\`;
      } else {
        log.style.color = 'var(--red)';
        log.innerText = \`✕ REJECTED: Changes cancelled and flagged for human architect review.\`;
      }
    }

    // Export helpers
    function exportReport(type) {
      if (!currentAuditData) return alert('Please execute an audit first.');
      let content = '', filename = '', mime = 'text/plain';

      if (type === 'json') {
        content = JSON.stringify(currentAuditData, null, 2);
        filename = 'audit-report.json';
        mime = 'application/json';
      } else if (type === 'md') {
        content = \`# ClassiGuard CyFence Report for \${currentAuditData.targetUrl}\\nScore: \${currentAuditData.compliance.score}/100 (Grade \${currentAuditData.compliance.grade})\\n\\n## Findings\\n\` +
          currentAuditData.findings.map(f => \`- [\${f.severity}] \${f.title}\\n  \${f.details}\`).join('\\n\\n');
        filename = 'audit-report.md';
      } else if (type === 'html') {
        content = \`<!DOCTYPE html><html><head><title>CyFence Report</title><style>body{background:#0b0f19;color:#fff;font-family:sans-serif;padding:2rem;}</style></head><body><h1>ClassiGuard CyFence: \${escapeHtml(currentAuditData.targetUrl)}</h1><h2>Score: \${currentAuditData.compliance.score}/100</h2><pre>\${escapeHtml(JSON.stringify(currentAuditData.findings, null, 2))}</pre></body></html>\`;
        filename = 'audit-report.html';
        mime = 'text/html';
      }

      const blob = new Blob([content], { type: mime });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = filename;
      a.click();
    }
  </script>
</body>
</html>`);
        return;
      }

      res.writeHead(404, { 'Content-Type': 'text/plain', ...DEFENSIVE_HEADERS });
      res.end('Not Found');
    });

    server.listen(port, host, () => {
      console.log(`\n================================================================================`);
      console.log(`  🛡️  ClassiGuard CyFence Enterprise Web GUI Suite Running`);
      console.log(`================================================================================`);
      console.log(`  Access URL:  http://${host}:${port}`);
      console.log(`  Mode:        100% Offline / Air-Gapped Ready (Zero external dependencies)`);
      console.log(`  Security:    CSRF Guard Active | Strict Loopback (${host}) | CSP Hardened`);
      console.log(`  Features:    Single Audit, Batch Fleet, Posture Drift Diff, Auto-Hardening, AI Advisor`);
      console.log(`  Press Ctrl+C to terminate dashboard server.`);
      console.log(`================================================================================\n`);

      if (options.autoOpen !== false) {
        openBrowser(`http://${host}:${port}`);
      }

      resolve(server);
    });

    server.on('error', reject);
  });
}

// --- End: src/server/guiServer.mjs ---


// --- Start: src/interactive/wizard.mjs ---
/**
 * Interactive Operator Wizard & Menu (TUI)
 * Pure Node.js readline implementation (Zero external dependencies)
 */







function askQuestion(rl, query) {
  return new Promise(resolve => rl.question(query, resolve));
}

/**
 * Launches the interactive text-based console menu
 */
async function launchWizard() {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  console.log(`\n================================================================================`);
  console.log(`  🛡️  CLASSIGUARD CYFENCE: INTERACTIVE OPERATOR WIZARD`);
  console.log(`  Defensive Web Security & Compliance Engine`);
  console.log(`================================================================================`);
  console.log(`  1. Audit Single Target URL`);
  console.log(`  2. Audit Multi-Target Batch List (from file)`);
  console.log(`  3. Launch Local Web GUI Dashboard (Browser mode)`);
  console.log(`  4. Configuration Drift & Regression Analysis (Diff)`);
  console.log(`  5. Exit`);
  console.log(`--------------------------------------------------------------------------------`);

  const choice = (await askQuestion(rl, 'Select an action [1-5]: ')).trim();

  if (choice === '1') {
    let target = (await askQuestion(rl, 'Enter Target URL (e.g. https://example.com or http://localhost:8080/insecure): ')).trim();
    if (!target) target = 'http://localhost:8080/insecure';
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      target = 'https://' + target;
    }

    const aiPrompt = (await askQuestion(rl, 'Enable AI-assisted remediation synthesis? [y/N]: ')).trim().toLowerCase();
    const enableAi = aiPrompt === 'y' || aiPrompt === 'yes';

    rl.close();
    console.log(`\n🔍 Initiating audit on ${target}...`);
    const result = await auditUrl(target, {
      ai: enableAi ? { provider: 'ollama' } : null
    });
    printTerminalReport(result, { showRemediation: true });

  } else if (choice === '2') {
    let filePath = (await askQuestion(rl, 'Enter path to targets file (default: targets.txt): ')).trim();
    if (!filePath) filePath = 'targets.txt';

    rl.close();
    try {
      const targets = await loadTargetsFromFile(filePath);
      const results = await auditBatch(targets);
      printBatchTerminal(results);
    } catch (err) {
      console.error(`Error processing batch: ${err.message}`);
    }

  } else if (choice === '3') {
    let port = (await askQuestion(rl, 'Enter Web GUI Port (default: 9090): ')).trim();
    const portNum = parseInt(port, 10) || 9090;
    rl.close();
    await startGuiServer(portNum, '127.0.0.1', { autoOpen: true });

  } else if (choice === '4') {
    const base = (await askQuestion(rl, 'Enter baseline JSON report path: ')).trim();
    const current = (await askQuestion(rl, 'Enter current JSON report path: ')).trim();
    rl.close();

    try {
      const diff = await diffReportFiles(base, current);
      console.log(formatDiffTerminal(diff));
    } catch (err) {
      console.error(`Error comparing files: ${err.message}`);
    }

  } else {
    rl.close();
    console.log('Exiting ClassiGuard CyFence. Stay secure!\n');
  }
}

// --- End: src/interactive/wizard.mjs ---


// --- Start: src/index.mjs ---
/**
 * ClassiGuard CyFence Core Orchestrator
 * High-level programmatic API for automated defensive security audits
 */
























/**
 * Runs a comprehensive defensive security audit against a target web URL
 * @param {string} targetUrl - Target URL to audit
 * @param {object} [options] - Optional configurations
 * @param {string} [options.jwt] - Explicit JWT string to audit
 * @param {object} [options.headers] - Custom request headers to send
 * @param {boolean} [options.skipRoutes=false] - Skip active sensitive route checks
 * @param {object} [options.ai] - AI advisor options
 * @returns {Promise<object>} Complete structured audit result
 */
async function auditUrl(targetUrl, options = {}) {
  const timestamp = new Date().toISOString();
  const requestHeaders = options.headers || {};

  // 1. Initial Probe
  const probe = await safeFetch(targetUrl, {
    method: 'GET',
    headers: requestHeaders
  });

  if (probe.error && probe.status === 0) {
    return {
      targetUrl,
      timestamp,
      error: probe.error,
      compliance: {
        score: 0,
        grade: 'F',
        counts: { total: 0, passed: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        totalDefects: 0
      },
      findings: [{
        id: 'SEC-CONN-ERR',
        title: 'Connection or Resolution Failure',
        standard: 'Network Infrastructure',
        severity: 'CRITICAL',
        details: `Failed to connect to target URL: ${probe.error}`,
        remediation: 'Verify host connectivity, DNS resolution, and firewall egress permissions.'
      }]
    };
  }

  const findings = [];

  // 2. Security Headers Audit (OWASP ASVS V14.4)
  const headerFindings = auditHeaders(targetUrl, probe.rawHeaders);
  findings.push(...headerFindings);

  // 3. Cookies Audit (OWASP ASVS V3.4)
  const cookieFindings = auditCookies(targetUrl, probe.cookies);
  findings.push(...cookieFindings);

  // 4. CORS Policy Audit (OWASP ASVS V14.4.7)
  const corsFindings = await auditCors(targetUrl, probe.rawHeaders);
  findings.push(...corsFindings);

  // 5. API Surface & Leakage Audit (OWASP ASVS V13.1)
  const apiSurfaceFindings = await auditApiSurface(targetUrl, probe.rawHeaders, probe.bodySnippet);
  findings.push(...apiSurfaceFindings);

  // 6. Perimeter WAF & CDN Fingerprinting (Red Team / Recon)
  const wafFindings = auditWaf(probe.rawHeaders, probe.cookies);
  findings.push(...wafFindings);

  // 7. Discovery Protocols & security.txt (Red Team / RFC 9116)
  const discoveryFindings = await auditDiscovery(targetUrl, { headers: requestHeaders });
  findings.push(...discoveryFindings);

  // 8. Sensitive Routes & File Exposure (Red Team / Recon)
  if (!options.skipRoutes) {
    const routeFindings = await auditSensitiveRoutes(targetUrl, { headers: requestHeaders });
    findings.push(...routeFindings);
  }

  // 9. JWT Security Audit (RFC 8725 / ASVS V8.3)
  let tokenToAudit = options.jwt;
  if (!tokenToAudit) {
    const authHdr = probe.rawHeaders['authorization'];
    if (authHdr && authHdr.toLowerCase().startsWith('bearer ')) {
      tokenToAudit = authHdr;
    } else {
      for (const c of probe.cookies) {
        const { value } = parseCookie(c);
        if (value.startsWith('ey') && value.split('.').length === 3) {
          tokenToAudit = value;
          break;
        }
      }
    }
  }

  if (tokenToAudit) {
    const jwtFindings = auditJwt(tokenToAudit, 'Target JWT Token');
    findings.push(...jwtFindings);
  }

  // 10. Compliance Calculation
  const compliance = calculateCompliance(findings);

  // 11. Blue Team Auto-Remediation & Sigma Generation
  const hardeningConfigs = generateHardeningConfigs(findings);
  const detectionRules = generateDetectionRules(findings, targetUrl);

  const result = {
    targetUrl,
    timestamp,
    httpStatus: probe.status,
    compliance,
    findings,
    blueTeam: {
      hardeningConfigs,
      detectionRules
    }
  };

  // 12. Optional AI Security Advisor
  if (options.ai) {
    const aiAdvisory = await getAiSecurityAdvisory(result, options.ai);
    result.aiAdvisory = aiAdvisory;
  }

  return result;
}

// --- End: src/index.mjs ---


// --- Start: bin/cli.mjs ---

/**
 * ClassiGuard CyFence CLI Tool
 * Command-line interface for OWASP ASVS defensive security assessments
 */









function printHelp() {
  console.log(`
ClassiGuard CyFence: Enterprise Defensive Web Security & Posture Auditor
Aligned with OWASP ASVS v4.0, MITRE ATT&CK & D3FEND, and RFC 8725

Usage:
  cyfence <target-url> [options]
  cyfence diff <baseline.json> <current.json>
  cyfence gui [port]
  cyfence menu

Primary Subcommands:
  gui, serve [port]       Launch the local Web GUI Dashboard (default port: 9090)
  diff <file1> <file2>    Compare two JSON audit runs to analyze posture drift
  menu, wizard            Launch the interactive terminal wizard

Core Options:
  --html <path>           Export a self-contained visual HTML report (air-gapped safe)
  --json <path>           Export a machine-readable JSON report for CI/CD
  --markdown <path>       Export a GitHub-flavored Markdown report
  --targets <file.txt>    Execute batch audit across all URLs listed in file
  --profile <mode>        Scan profile: 'fast', 'full' (default), 'red', 'blue'
  --config <file.json>    Load options from configuration file (default: cyfence.config.json)
  --jwt <token>           Explicitly audit a JWT for RFC 8725 compliance
  --header <key:value>    Custom HTTP header to send with requests (repeatable)
  --min-score <number>    Fail with exit code 1 if score is below threshold (default: 0)
  --no-routes             Skip scanning sensitive metadata routes (/.git, /.env, etc.)

Blue Team Auto-Remediation Options:
  --remediation           Display generated Nginx / Apache hardening configs
  --export-configs <dir>  Export ready-to-deploy Nginx, Apache, and Caddy configs to directory
  --sigma <path>          Save generated Sigma detection rule YAML to file
  --webhook <url>         Dispatch Slack/Discord/Teams alert webhook
  --watch <seconds>       Run audit continuously on a scheduled interval

AI Integration Options (Human-in-the-Loop Mandatory):
  --ai                    Enable AI-assisted remediation synthesis
  --ai-provider <name>    Provider: 'ollama' (default/offline), 'openai', 'claude', 'codex'
  --ai-model <model>      Specify model name (e.g., 'llama3', 'gpt-4o-mini', 'claude-3-5-sonnet')
  --ai-key <key>          API key for cloud AI providers (or use env variables)
  --ai-endpoint <url>     Custom API endpoint URL

General Options:
  --help, -h              Display this help message
`);
}

async function runSingleAudit(targetUrl, options) {
  console.log(`\n🔍 Initiating ClassiGuard CyFence audit against: ${targetUrl}...`);

  const result = await auditUrl(targetUrl, {
    jwt: options.jwtToken,
    headers: options.customHeaders,
    skipRoutes: options.skipRoutes || options.profile === 'fast' || options.profile === 'blue',
    ai: options.enableAi ? {
      provider: options.aiProvider,
      model: options.aiModel,
      apiKey: options.aiKey,
      endpoint: options.aiEndpoint
    } : null
  });

  // 1. Output terminal summary
  printTerminalReport(result, { showRemediation: options.showRemediation || options.profile === 'blue' });

  // 2. Export JSON if requested
  if (options.jsonPath) {
    await writeJsonReport(result, options.jsonPath);
    console.log(`📄 Machine-readable JSON report written to: ${options.jsonPath}`);
  }

  // 3. Export HTML if requested
  if (options.htmlPath) {
    await writeHtmlReport(result, options.htmlPath);
    console.log(`🌐 Visual HTML audit report written to: ${options.htmlPath}`);
  }

  // 4. Export Markdown if requested
  if (options.markdownPath) {
    await writeMarkdownReport(result, options.markdownPath);
    console.log(`📝 GitHub-flavored Markdown report written to: ${options.markdownPath}`);
  }

  // 5. Export Sigma rule if requested
  if (options.sigmaPath && result.blueTeam) {
    await fs.writeFile(options.sigmaPath, result.blueTeam.detectionRules.sigmaYaml, 'utf8');
    console.log(`🛡️  Sigma detection rule written to: ${options.sigmaPath}`);
  }

  // 6. Export ready-to-deploy Hardening Configs if requested
  if (options.exportConfigsDir) {
    const writtenFiles = await exportHardeningFiles(result.findings, options.exportConfigsDir);
    console.log(`📁 Auto-remediation configuration files exported to: ${options.exportConfigsDir}/`);
    for (const f of writtenFiles) {
      console.log(`   - ${f}`);
    }
  }

  // 7. Dispatch Webhook if configured
  if (options.webhookUrl) {
    console.log(`📡 Dispatching alert to webhook...`);
    const hookRes = await sendWebhookAlert(options.webhookUrl, result);
    if (hookRes.success) {
      console.log(`✅ Webhook alert dispatched successfully.`);
    } else {
      console.warn(`⚠️ Webhook alert failed: ${hookRes.error}`);
    }
  }

  // 8. Check CI/CD threshold
  if (result.compliance.score < options.minScore) {
    console.error(`\n❌ CI/CD Gate Failed: Security score (${result.compliance.score}) is below required minimum (${options.minScore}).`);
    return false;
  }

  return true;
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    const port = 9090;
    console.log(`\n================================================================================`);
    console.log(`  🛡️  ClassiGuard CyFence: Enterprise Web Security Suite`);
    console.log(`================================================================================`);
    console.log(`  No CLI arguments specified. Auto-launching the full Web GUI Dashboard...`);
    console.log(`  Target Interface: http://127.0.0.1:${port}`);
    console.log(`  Press Ctrl+C in this console window to exit.`);
    console.log(`================================================================================\n`);
    await startGuiServer(port, '127.0.0.1', { autoOpen: true });
    return;
  }

  if (args.includes('-h') || args.includes('--help')) {
    printHelp();
    process.exit(0);
  }

  // Subcommand: menu or wizard
  if (args[0] === 'menu' || args[0] === 'wizard') {
    await launchWizard();
    return;
  }

  // Subcommand: gui or serve
  if (args[0] === 'gui' || args[0] === 'serve') {
    const port = parseInt(args[1], 10) || 9090;
    await startGuiServer(port, '127.0.0.1', { autoOpen: true });
    return;
  }

  // Subcommand: diff <base.json> <current.json>
  if (args[0] === 'diff') {
    const baseFile = args[1];
    const currentFile = args[2];
    if (!baseFile || !currentFile) {
      console.error('Error: diff command requires two JSON files: `cyfence diff <base.json> <current.json>`\n');
      process.exit(1);
    }
    try {
      const diffResult = await diffReportFiles(baseFile, currentFile);
      console.log(formatDiffTerminal(diffResult));
      process.exit(diffResult.newDefects.length > 0 ? 1 : 0);
    } catch (err) {
      console.error(`Error comparing audit files: ${err.message}`);
      process.exit(1);
    }
  }

  // Check for config file flag
  let configFilePath = 'cyfence.config.json';
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--config') configFilePath = args[++i];
  }
  const fileConfig = await loadConfigFile(configFilePath);

  let targetUrl = null;
  let targetsFilePath = fileConfig.targetsFile || null;

  const options = {
    htmlPath: fileConfig.html || null,
    jsonPath: fileConfig.json || null,
    markdownPath: fileConfig.markdown || null,
    sigmaPath: fileConfig.sigma || null,
    webhookUrl: fileConfig.webhook || null,
    jwtToken: fileConfig.jwt || null,
    minScore: fileConfig.minScore || 0,
    profile: fileConfig.profile || 'full',
    skipRoutes: fileConfig.skipRoutes || false,
    showRemediation: fileConfig.remediation || false,
    exportConfigsDir: null,
    watchInterval: fileConfig.watch || 0,
    enableAi: fileConfig.ai || false,
    aiProvider: fileConfig.aiProvider || 'ollama',
    aiModel: fileConfig.aiModel || null,
    aiKey: fileConfig.aiKey || null,
    aiEndpoint: fileConfig.aiEndpoint || null,
    customHeaders: fileConfig.headers || {}
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (arg === '--html') options.htmlPath = args[++i];
    else if (arg === '--json') options.jsonPath = args[++i];
    else if (arg === '--markdown') options.markdownPath = args[++i];
    else if (arg === '--sigma') options.sigmaPath = args[++i];
    else if (arg === '--export-configs') options.exportConfigsDir = args[++i] || 'reports/hardening';
    else if (arg === '--webhook') options.webhookUrl = args[++i];
    else if (arg === '--jwt') options.jwtToken = args[++i];
    else if (arg === '--profile') options.profile = args[++i];
    else if (arg === '--targets') targetsFilePath = args[++i];
    else if (arg === '--min-score') options.minScore = parseInt(args[++i], 10) || 0;
    else if (arg === '--remediation' || arg === '--fix') options.showRemediation = true;
    else if (arg === '--no-routes') options.skipRoutes = true;
    else if (arg === '--watch') options.watchInterval = parseInt(args[++i], 10) || 60;
    else if (arg === '--ai') options.enableAi = true;
    else if (arg === '--ai-provider') { options.enableAi = true; options.aiProvider = args[++i]; }
    else if (arg === '--ai-model') options.aiModel = args[++i];
    else if (arg === '--ai-key') options.aiKey = args[++i];
    else if (arg === '--ai-endpoint') options.aiEndpoint = args[++i];
    else if (arg === '--header') {
      const headerStr = args[++i] || '';
      const splitIdx = headerStr.indexOf(':');
      if (splitIdx > -1) {
        const k = headerStr.slice(0, splitIdx).trim();
        const v = headerStr.slice(splitIdx + 1).trim();
        options.customHeaders[k] = v;
      }
    } else if (!arg.startsWith('-') && !targetUrl) {
      targetUrl = arg;
    }
  }

  // Batch Execution Mode
  if (targetsFilePath) {
    try {
      const targets = await loadTargetsFromFile(targetsFilePath);
      const batchResults = await auditBatch(targets, options);
      printBatchTerminal(batchResults);
      if (options.htmlPath) {
        await writeBatchHtmlReport(batchResults, options.htmlPath);
        console.log(`🌐 Aggregated batch HTML report written to: ${options.htmlPath}`);
      }
      process.exit(0);
    } catch (err) {
      console.error(`Failed to process targets file ${targetsFilePath}: ${err.message}`);
      process.exit(1);
    }
  }

  if (!targetUrl) {
    console.error('Error: Missing required <target-url> or --targets argument.\n');
    printHelp();
    process.exit(1);
  }

  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  if (options.watchInterval > 0) {
    console.log(`⏱️  ClassiGuard CyFence running in continuous watch mode (Interval: ${options.watchInterval}s). Press Ctrl+C to stop.`);
    const runLoop = async () => {
      await runSingleAudit(targetUrl, options);
      setTimeout(runLoop, options.watchInterval * 1000);
    };
    await runLoop();
  } else {
    const success = await runSingleAudit(targetUrl, options);
    process.exit(success ? 0 : 1);
  }
}

main().catch(err => {
  console.error(`Fatal error: ${err.message}`);
  process.exit(1);
});

// --- End: bin/cli.mjs ---
