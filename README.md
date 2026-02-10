# 🔍 IoC Quick Lookup

A lightweight, client-side web app for instant Indicator of Compromise (IoC) reputation lookups across multiple threat intelligence sources.

Built for DFIR and Threat Intelligence analysts who need fast, multi-source IoC enrichment without switching between tabs.

## 🚀 Live Demo

**[https://theclimbingcat.github.io/ioc-lookup/](https://theclimbingcat.github.io/ioc-lookup/)**

## Features

- **Auto-detect IoC type** — IPv4, IPv6, domains, URLs, MD5, SHA-1, SHA-256
- **Multi-source lookup** — Queries multiple threat intel sources in parallel
- **Visual threat scoring** — Aggregated risk score with color-coded indicators
- **Dark theme** — Professional UI designed for security analysts
- **Client-side only** — No backend, no tracking, your data stays in your browser
- **Mobile responsive** — Works on any device
- **Zero dependencies** — Vanilla HTML/CSS/JS, no frameworks

## Threat Intelligence Sources

### Free (no API key required)
| Source | Coverage |
|--------|----------|
| **Shodan InternetDB** | Open ports, vulnerabilities, tags |
| **ip-api.com** | Geolocation, ISP, proxy/VPN detection |
| **ThreatFox** (abuse.ch) | Malware-associated IoCs |
| **URLhaus** (abuse.ch) | Malicious URLs and domains |

### With free API key
| Source | Coverage | Get Key |
|--------|----------|---------|
| **AbuseIPDB** | IP abuse reports & confidence score | [abuseipdb.com](https://www.abuseipdb.com/account/api) |
| **VirusTotal** | Files, domains, IPs, URLs | [virustotal.com](https://www.virustotal.com/gui/my-apikey) |
| **IPQualityScore** | Fraud score, VPN/proxy/Tor detection | [ipqualityscore.com](https://www.ipqualityscore.com/create-account) |

## Setup

### Option 1: Use the live demo
Just visit the [GitHub Pages site](https://theclimbingcat.github.io/ioc-lookup/) — no setup needed.

### Option 2: Self-host
```bash
git clone https://github.com/TheClimbingCat/ioc-lookup.git
cd ioc-lookup
# Serve with any static file server:
python3 -m http.server 8080
# or
npx serve .
```

### Configure API Keys
1. Click the ⚙️ button in the top-right corner
2. Enter your free API keys
3. Keys are stored in your browser's localStorage only

## Architecture

```
Browser (100% client-side)
├── IoC Input → Auto-type detection (regex)
├── Parallel API queries → Fetch API
├── Results aggregation → Normalized scoring
└── Rendering → Vanilla DOM manipulation
```

- **No build step** — Just static HTML/CSS/JS
- **No frameworks** — Fast and lightweight (<50KB total)
- **No backend** — All API calls from the browser
- **No tracking** — Zero analytics or telemetry

## CORS Notes

Some APIs may block direct browser requests (CORS). In that case:
- **Shodan InternetDB, abuse.ch APIs** — CORS-friendly ✅
- **AbuseIPDB, VirusTotal** — Require API key in headers (CORS allowed with key)
- **ip-api.com** — HTTP only (works from non-HTTPS pages or localhost)

For production use behind HTTPS, consider a lightweight CORS proxy (e.g., Cloudflare Worker) for ip-api.com.

## Contributing

1. Fork the repo
2. Create a feature branch
3. Submit a pull request

## License

MIT License — See [LICENSE](LICENSE)
