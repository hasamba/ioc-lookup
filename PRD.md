# IoC Quick Lookup — Product Requirements Document

## 1. Overview

**Product Name:** IoC Quick Lookup  
**Version:** 1.0  
**Date:** 2026-02-10  
**Author:** TheClimbingCat  

### 1.1 Problem Statement
DFIR and Threat Intelligence analysts spend significant time manually checking Indicators of Compromise (IoCs) — IP addresses, domains, and file hashes — across multiple threat intelligence platforms. This context-switching slows incident response and reduces analyst efficiency.

### 1.2 Solution
A lightweight, single-page web application that provides instant IoC reputation lookup from multiple free threat intelligence sources in a unified interface. Client-side only, deployable via GitHub Pages with zero backend infrastructure.

### 1.3 Target Users
- DFIR (Digital Forensics & Incident Response) analysts
- Threat Intelligence analysts
- SOC (Security Operations Center) analysts
- Security researchers
- Penetration testers

---

## 2. Goals & Success Metrics

| Goal | Metric |
|------|--------|
| Reduce lookup time | < 5 seconds from input to results |
| Multi-source enrichment | ≥ 3 threat intel sources per lookup |
| Zero-cost operation | No paid API subscriptions required |
| Instant deployment | One-click deploy via GitHub Pages |
| Accessibility | Works on mobile and desktop |

---

## 3. Functional Requirements

### 3.1 IoC Input
- **FR-1:** Single input field accepting IP addresses (IPv4/IPv6), domain names, URLs, and file hashes (MD5, SHA-1, SHA-256)
- **FR-2:** Auto-detect IoC type from input (regex-based classification)
- **FR-3:** Input validation with clear error messages
- **FR-4:** Support paste from clipboard
- **FR-5:** Lookup history (session-only, stored in localStorage)

### 3.2 Threat Intelligence Sources
- **FR-6:** AbuseIPDB — IP reputation and abuse reports (free tier: 1000 checks/day)
- **FR-7:** VirusTotal — File hash, domain, and IP lookup (free tier: 4 req/min, 500/day)
- **FR-8:** IPQualityScore / ip-api.com — Geolocation and proxy/VPN detection (free tier)
- **FR-9:** ThreatFox (abuse.ch) — IoC database for malware-associated indicators
- **FR-10:** URLhaus (abuse.ch) — Malicious URL database
- **FR-11:** Shodan InternetDB — Open ports and vulns (free, no key required)

### 3.3 Results Display
- **FR-12:** Unified threat score (normalized 0-100 across sources)
- **FR-13:** Color-coded risk indicator (green/yellow/orange/red)
- **FR-14:** Per-source breakdown with individual scores and details
- **FR-15:** Geolocation data with country flag for IPs
- **FR-16:** WHOIS-style information where available
- **FR-17:** Related tags/labels (malware families, threat categories)
- **FR-18:** Direct links to full reports on source platforms

### 3.4 API Key Management
- **FR-19:** Settings panel for users to input their own API keys
- **FR-20:** Keys stored in browser localStorage (never transmitted to third parties)
- **FR-21:** Clear indication of which sources require API keys
- **FR-22:** Graceful degradation — sources without keys are skipped with notice

### 3.5 History & Export
- **FR-23:** Session lookup history with timestamps
- **FR-24:** Export results as JSON
- **FR-25:** Copy results summary to clipboard (for pasting into reports)

---

## 4. Non-Functional Requirements

### 4.1 Performance
- **NFR-1:** Initial page load < 1 second (no heavy frameworks)
- **NFR-2:** API queries fire in parallel for minimal wait time
- **NFR-3:** Total bundle size < 500 KB

### 4.2 Security
- **NFR-4:** All API calls over HTTPS
- **NFR-5:** API keys stored only in localStorage, never logged or transmitted elsewhere
- **NFR-6:** No tracking, analytics, or telemetry
- **NFR-7:** Content Security Policy headers where possible
- **NFR-8:** CORS-aware — use CORS proxies only for sources that block browser requests, with clear disclosure

### 4.3 Usability
- **NFR-9:** Dark theme by default (industry standard for security tools)
- **NFR-10:** Mobile-responsive (works on tablets during incident response)
- **NFR-11:** Keyboard-friendly (Enter to search, tab navigation)
- **NFR-12:** Accessible (ARIA labels, sufficient contrast ratios)

### 4.4 Deployment
- **NFR-13:** Static files only — deployable on GitHub Pages
- **NFR-14:** No build step required (vanilla HTML/CSS/JS)
- **NFR-15:** Works offline for UI (obviously APIs need connectivity)

---

## 5. Technical Architecture

```
┌──────────────────────────────┐
│     Browser (Client-Side)     │
│                               │
│  ┌─────────┐  ┌────────────┐ │
│  │  Input   │→ │ IoC Parser │ │
│  │  Field   │  │ (type det) │ │
│  └─────────┘  └─────┬──────┘ │
│                      │        │
│              ┌───────▼──────┐ │
│              │ Query Engine │ │
│              │  (parallel)  │ │
│              └───────┬──────┘ │
│                      │        │         External APIs
│    ┌─────────────────┼────────┼──────────────────┐
│    │  ┌──────┐ ┌─────┴┐ ┌────┴───┐ ┌──────────┐ │
│    │  │Abuse │ │ VT   │ │Shodan  │ │ThreatFox │ │
│    │  │IPDB  │ │      │ │InterDB │ │/URLhaus  │ │
│    │  └──┬───┘ └──┬───┘ └───┬────┘ └────┬─────┘ │
│    └─────┼────────┼─────────┼────────────┼───────┘
│          │        │         │            │        │
│    ┌─────▼────────▼─────────▼────────────▼─────┐ │
│    │          Results Aggregator                │ │
│    │     (normalize, score, render)             │ │
│    └───────────────────┬───────────────────────┘ │
│                        │                          │
│              ┌─────────▼──────────┐               │
│              │   Results Display  │               │
│              │  (cards, scores)   │               │
│              └────────────────────┘               │
└──────────────────────────────────────────────────┘
```

### 5.1 Technology Stack
- **HTML5 / CSS3 / Vanilla JavaScript** (ES modules)
- **No frameworks** — minimal dependencies for speed and security
- **CSS Custom Properties** for theming
- **Fetch API** for HTTP requests

### 5.2 CORS Considerations
Some APIs don't support browser CORS. Strategy:
1. **Direct call** for CORS-friendly APIs (Shodan InternetDB, abuse.ch)
2. **User's own keys** for APIs that allow browser access with auth
3. **Optional CORS proxy** with clear disclosure for restricted APIs

---

## 6. UI/UX Design

### 6.1 Layout
- Top: Logo + title + settings gear icon
- Center: Large search input with IoC type indicator badge
- Below: Results cards in a responsive grid
- Bottom: Lookup history accordion
- Floating: Settings modal for API keys

### 6.2 Color Scheme (Dark Theme)
- Background: `#0d1117` (GitHub dark)
- Surface: `#161b22`
- Border: `#30363d`
- Text: `#c9d1d9`
- Accent: `#58a6ff`
- Risk colors: `#3fb950` (clean) / `#d29922` (low) / `#db6d28` (medium) / `#f85149` (high)

---

## 7. Roadmap

### v1.0 (MVP — Current)
- Core lookup functionality
- 4-6 free threat intel sources
- Dark theme UI
- API key management
- GitHub Pages deployment

### v1.1 (Future)
- Bulk IoC lookup (paste list)
- CSV/STIX export
- Browser extension version
- Saved API key profiles
- Additional sources (AlienVault OTX, GreyNoise)

### v2.0 (Future)
- Optional lightweight backend (Cloudflare Workers) for CORS proxy
- Webhook/SIEM integration
- Team shared API keys
- IoC correlation graph

---

## 8. Risks & Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| API rate limits | Degraded results | Parallel queries with graceful fallback; cache results |
| CORS blocking | Some sources unavailable | Document CORS proxy setup; prioritize CORS-friendly APIs |
| API key exposure | Security concern | localStorage only; clear warnings; never log keys |
| Free tier changes | Source unavailability | Modular source architecture; easy to add/remove sources |

---

## 9. Acceptance Criteria

- [ ] User can enter an IP and see reputation data from ≥ 2 sources
- [ ] User can enter a domain and see reputation data
- [ ] User can enter a file hash and see reputation data
- [ ] IoC type is auto-detected
- [ ] Results display within 5 seconds
- [ ] Settings panel allows API key entry
- [ ] Works without any API keys (using keyless sources)
- [ ] Mobile-responsive layout
- [ ] Deployable on GitHub Pages with zero configuration
- [ ] Dark theme by default
