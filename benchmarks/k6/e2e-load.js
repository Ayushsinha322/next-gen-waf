import { check, sleep } from 'k6';
import http from 'k6/http';
import { Counter, Trend, Rate } from 'k6/metrics';

// ---------------------------------------------------------------------------
// Sentinel WAF E2E Benchmark — realistic mixed-traffic load test
// ---------------------------------------------------------------------------
//
// Usage:
//   k6 run benchmarks/k6/e2e-load.js --duration 60s --vus 100 \
//     -e PROXY_URL=http://127.0.0.1:9080 -e HOST=dvwa.local
//
// The script sends a mix of clean traffic and attack payloads to a running
// Sentinel proxy. It measures:
//   - End-to-end latency (including WAF processing, rule evaluation, upstream round-trip)
//   - Throughput (req/s)
//   - Error rate (proxy crashes, timeouts, unexpected status codes)
//   - Block rate (403 responses for attack traffic)
//
// Traffic mix (configurable):
//   - 80% clean requests (various paths, query params)
//   - 15% SQLi / XSS / LFI attacks
//   -  5% scanner/suspicious traffic (nmap UA, backup file probing)

// --- Configuration ---------------------------------------------------------

const PROXY_URL = __ENV.PROXY_URL || 'http://127.0.0.1:9080';
const HOST_HEADER = __ENV.HOST || 'dvwa.local';
const TRAFFIC_MIX = [80, 15, 5]; // [clean%, attack%, scanner%]

// --- Custom metrics --------------------------------------------------------

const e2eLatency = new Trend('sentinel_e2e_latency_ms', true);
const blocks = new Counter('sentinel_blocks');
const errors = new Counter('sentinel_proxy_errors');
const attackStatus = new Rate('sentinel_attack_block_rate');

// --- Payload pools ---------------------------------------------------------

const CLEAN_PATHS = [
  '/',
  '/index.php',
  '/login.php',
  '/setup.php',
  '/security.php',
  '/vulnerabilities/csrf/',
  '/instructions.php',
  '/phpinfo.php',
  '/about.php',
  '/api/v1/health',
];

const CLEAN_QUERY_PARAMS = [
  '?page=1',
  '?test=hello+world',
  '?id=42',
  '?name=admin',
  '?action=list',
  '?lang=en',
  '',
];

const ATTACK_PAYLOADS = [
  // SQLi
  { path: '/vulnerabilities/sqli/', qs: "?id=1' OR 1=1--&Submit=Submit" },
  { path: '/vulnerabilities/sqli/', qs: "?id=1 UNION SELECT user,password FROM users--" },
  { path: '/vulnerabilities/sqli_blind/', qs: "?id=1' AND sleep(5)--" },
  // XSS
  { path: '/vulnerabilities/xss_r/', qs: "?name=<script>alert(1)</script>" },
  { path: '/vulnerabilities/xss_s/', qs: "?message=<img src=x onerror=alert(1)>" },
  // LFI
  { path: '/vulnerabilities/fi/', qs: "?page=../../etc/passwd" },
  { path: '/', qs: "?file=....//....//etc/passwd" },
  // RCE
  { path: '/vulnerabilities/exec/', qs: "?ip=127.0.0.1;cat /etc/passwd" },
  // CMDi
  { path: '/', qs: "?cmd=|cat /etc/passwd" },
];

const SCANNER_PATHS = [
  { path: '/.env', qs: '' },
  { path: '/wp-admin/', qs: '' },
  { path: '/backup.tar.gz', qs: '' },
  { path: '/.git/config', qs: '' },
  { path: '/.DS_Store', qs: '' },
];

const SCANNER_UA = [
  'nmap',
  'Nikto',
  'sqlmap',
  'WPScan',
  'dirbuster',
];

// --- Default headers ---

const BASE_HEADERS = {
  Host: HOST_HEADER,
  'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/125.0',
  Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
};

// --- Request builder ---

function makeRequest(url, headers) {
  const params = {
    headers: Object.assign({}, BASE_HEADERS, headers || {}),
    timeout: '10s',
  };
  const start = Date.now();
  const res = http.get(url, params);
  const elapsed = Date.now() - start;

  e2eLatency.add(elapsed);

  return res;
}

// --- Main test function ---

export default function () {
  const r = Math.random() * 100;
  let url, extraHeaders;
  let isAttack = false;

  if (r < TRAFFIC_MIX[0]) {
    // --- Clean traffic (80%) ---
    const path = CLEAN_PATHS[Math.floor(Math.random() * CLEAN_PATHS.length)];
    const qs = CLEAN_QUERY_PARAMS[Math.floor(Math.random() * CLEAN_QUERY_PARAMS.length)];
    url = `${PROXY_URL}${path}${qs}`;
    extraHeaders = {};
  } else if (r < TRAFFIC_MIX[0] + TRAFFIC_MIX[1]) {
    // --- Attack traffic (15%) ---
    const payload = ATTACK_PAYLOADS[Math.floor(Math.random() * ATTACK_PAYLOADS.length)];
    url = `${PROXY_URL}${payload.path}${payload.qs}`;
    extraHeaders = {};
    isAttack = true;
  } else {
    // --- Scanner traffic (5%) ---
    const scanner = SCANNER_PATHS[Math.floor(Math.random() * SCANNER_PATHS.length)];
    url = `${PROXY_URL}${scanner.path}${scanner.qs}`;
    const ua = SCANNER_UA[Math.floor(Math.random() * SCANNER_UA.length)];
    extraHeaders = { 'User-Agent': ua };
    isAttack = true;
  }

  const res = makeRequest(url, extraHeaders);

  const status = res.status;

  // Track blocks vs errors
  if (status === 403) {
    blocks.add(1);
    if (isAttack) {
      attackStatus.add(true);
    }
  } else if (status === 0 || status >= 500) {
    errors.add(1);
  } else if (status === 200) {
    if (isAttack) {
      attackStatus.add(false);
    }
  }

  // Verify proxy is reachable
  check(res, {
    'proxy reachable': (r) => r.status !== 0,
    'not timed out': (r) => r.timings.duration < 10000,
  });

  // Small think time to simulate real user patterns
  sleep(0.1 + Math.random() * 0.3);
}

// --- Default options ---

export const options = {
  scenarios: {
    smoke: {
      executor: 'constant-arrival-rate',
      rate: 100,        // 100 requests/second
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 20,
      maxVUs: 200,
    },
    moderate: {
      executor: 'ramping-arrival-rate',
      startRate: 50,
      timeUnit: '1s',
      stages: [
        { target: 200, duration: '30s' },   // ramp to 200 req/s
        { target: 200, duration: '30s' },   // steady at 200
        { target: 500, duration: '30s' },   // ramp to 500
        { target: 500, duration: '30s' },   // steady at 500
        { target: 50,  duration: '30s' },   // cool down
      ],
      preAllocatedVUs: 50,
      maxVUs: 500,
    },
    stress: {
      executor: 'ramping-arrival-rate',
      startRate: 100,
      timeUnit: '1s',
      stages: [
        { target: 500,  duration: '30s' },
        { target: 1000, duration: '30s' },
        { target: 2000, duration: '30s' },
        { target: 5000, duration: '30s' },
        { target: 100,  duration: '30s' },
      ],
      preAllocatedVUs: 100,
      maxVUs: 1000,
    },
  },
  thresholds: {
    'sentinel_e2e_latency_ms': ['p(50)<50', 'p(95)<200', 'p(99)<500'],
    'sentinel_attack_block_rate': ['rate>0.8'],
    'sentinel_proxy_errors': ['count<10'],
  },
};