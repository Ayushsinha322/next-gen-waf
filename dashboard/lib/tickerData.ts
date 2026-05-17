export const TICKER_ITEMS = [
  { sev: "tc", sl: "CRITICAL", msg: "SQLi attack blocked · 185.220.101.45 → /api/login · Rule CRS-942100 · Score: 24/50" },
  { sev: "th", sl: "HIGH", msg: "XSS attempt detected · 103.24.8.122 → /search?q= · Payload: <script>alert()" },
  { sev: "tc", sl: "CRITICAL", msg: "Log4Shell probe blocked · CVE-2021-44228 · Virtual patch applied · 198.235.24.130" },
  { sev: "th", sl: "HIGH", msg: "Path traversal blocked · 91.240.118.150 → /../../etc/passwd · Rule CRS-930100" },
  { sev: "tm", sl: "MEDIUM", msg: "Rate limit exceeded · 10.0.0.45 → 5,200 req/min · Auto-banned 300s" },
  { sev: "tl", sl: "INFO", msg: "New API endpoint discovered · /api/v2/users · ML profile updated · Learning mode" },
  { sev: "tc", sl: "CRITICAL", msg: "BotNet detected · JA4: t13d1516h2_8daaf615 · 450 IPs blocked · eBPF active" },
  { sev: "th", sl: "HIGH", msg: "Command injection blocked · 45.33.32.156 → /cmd?exec · Rule CRS-932100" },
  { sev: "tm", sl: "MEDIUM", msg: "Suspicious TLS fingerprint · JA3: 7dcce5b76c8b17472ef3... · Score +4" },
  { sev: "th", sl: "HIGH", msg: "Credential stuffing · 320 attempts in 60s · 45.142.212.100 · Blocked + reported" },
  { sev: "tl", sl: "INFO", msg: "GeoIP block enforced · CN → Blocked 1,247 requests today" },
  { sev: "tc", sl: "CRITICAL", msg: "SSRF attempt · 192.168.100.12 → /internal/metadata · Dropped · Alert raised" },
];
