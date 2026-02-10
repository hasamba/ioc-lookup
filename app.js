// IoC Quick Lookup — Main Application
(function () {
  'use strict';

  // ── IoC Type Detection ──
  const patterns = {
    ipv4: /^(\d{1,3}\.){3}\d{1,3}$/,
    ipv6: /^([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}$/i,
    md5: /^[a-f0-9]{32}$/i,
    sha1: /^[a-f0-9]{40}$/i,
    sha256: /^[a-f0-9]{64}$/i,
    domain: /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i,
    url: /^https?:\/\/.+/i,
  };

  function detectType(input) {
    input = input.trim();
    if (patterns.ipv4.test(input)) return 'ipv4';
    if (patterns.ipv6.test(input)) return 'ipv6';
    if (patterns.sha256.test(input)) return 'sha256';
    if (patterns.sha1.test(input)) return 'sha1';
    if (patterns.md5.test(input)) return 'md5';
    if (patterns.url.test(input)) return 'url';
    if (patterns.domain.test(input)) return 'domain';
    return null;
  }

  function isIP(type) { return type === 'ipv4' || type === 'ipv6'; }
  function isHash(type) { return type === 'md5' || type === 'sha1' || type === 'sha256'; }
  function isDomain(type) { return type === 'domain'; }

  function extractDomain(input, type) {
    if (type === 'url') {
      try { return new URL(input).hostname; } catch { return input; }
    }
    return input;
  }

  // ── API Key Management ──
  function getKey(name) { return localStorage.getItem(`ioc_key_${name}`) || ''; }
  function setKey(name, val) { localStorage.setItem(`ioc_key_${name}`, val.trim()); }
  function clearAllKeys() {
    ['AbuseIPDB', 'VirusTotal', 'IPQS'].forEach(k => localStorage.removeItem(`ioc_key_${k}`));
  }

  // ── History ──
  function getHistory() {
    try { return JSON.parse(localStorage.getItem('ioc_history') || '[]'); } catch { return []; }
  }
  function addHistory(ioc, type) {
    const h = getHistory().filter(e => e.ioc !== ioc);
    h.unshift({ ioc, type, time: Date.now() });
    if (h.length > 50) h.length = 50;
    localStorage.setItem('ioc_history', JSON.stringify(h));
    renderHistory();
  }

  // ── Threat Intel Sources ──

  async function queryShodanInternetDB(ip) {
    const res = await fetch(`https://internetdb.shodan.io/${ip}`);
    if (!res.ok) return { source: 'Shodan InternetDB', error: res.status === 404 ? 'Not found in database' : `HTTP ${res.status}` };
    const d = await res.json();
    return {
      source: 'Shodan InternetDB',
      status: d.vulns?.length > 0 ? 'suspicious' : 'clean',
      data: {
        'Open Ports': d.ports?.join(', ') || 'None',
        'Hostnames': d.hostnames?.join(', ') || 'None',
        'Vulns': d.vulns?.join(', ') || 'None',
        'CPEs': d.cpes?.slice(0, 5).join(', ') || 'None',
      },
      tags: d.tags || [],
      score: d.vulns?.length > 0 ? Math.min(30 + d.vulns.length * 15, 90) : 5,
      link: `https://www.shodan.io/host/${ip}`,
    };
  }

  async function queryIPAPI(ip) {
    try {
      // Using ipapi.co - HTTPS, free tier 1000 req/day, no key required
      const res = await fetch(`https://ipapi.co/${ip}/json/`, {
        headers: { 'User-Agent': 'IoC-Quick-Lookup/1.0' },
        mode: 'cors',
      });
      if (!res.ok) return { source: 'IP Geolocation', error: `HTTP ${res.status}` };
      const d = await res.json();
      if (d.error) return { source: 'IP Geolocation', error: d.reason || d.error };
      const flag = d.country_code ? String.fromCodePoint(...[...d.country_code.toUpperCase()].map(c => 0x1F1E6 + c.charCodeAt(0) - 65)) : '';
      return {
        source: 'IP Geolocation',
        status: 'info',
        data: {
          'Location': `${flag} ${d.city || ''}, ${d.region || ''}, ${d.country_name || ''}`,
          'ISP': d.org || 'Unknown',
          'ASN': d.asn || 'Unknown',
          'Timezone': d.timezone || 'Unknown',
        },
        score: 0,
      };
    } catch (err) {
      return { source: 'IP Geolocation', error: err.message.includes('Failed to fetch') ? 'Network error' : err.message };
    }
  }

  async function queryGreyNoise(ip) {
    try {
      // GreyNoise Community API - free, no key required
      const res = await fetch(`https://api.greynoise.io/v3/community/${ip}`, {
        headers: { 'User-Agent': 'IoC-Quick-Lookup/1.0' },
        mode: 'cors',
      });
      if (!res.ok) {
        if (res.status === 404) return { source: 'GreyNoise', status: 'clean', data: { 'Result': 'Not found in GreyNoise' }, score: 0, link: 'https://www.greynoise.io/' };
        return { source: 'GreyNoise', error: `HTTP ${res.status}` };
      }
      const d = await res.json();
      const isNoise = d.noise === true;
      const isRiot = d.riot === true;
      const isMalicious = d.classification === 'malicious';
      
      let status = 'clean';
      let score = 0;
      if (isMalicious) { status = 'malicious'; score = 70; }
      else if (isNoise && !isRiot) { status = 'suspicious'; score = 40; }
      else if (isRiot) { status = 'clean'; score = 0; } // RIOT = known benign service
      
      return {
        source: 'GreyNoise',
        status,
        data: {
          'Classification': d.classification || 'Unknown',
          'Noise': isNoise ? '⚠️ Yes (mass-scanner)' : 'No',
          'RIOT': isRiot ? '✅ Known benign service' : 'No',
          'Last Seen': d.last_seen || 'Unknown',
          'Name': d.name || 'N/A',
        },
        tags: d.name ? [d.name] : [],
        score,
        link: `https://www.greynoise.io/viz/ip/${ip}`,
      };
    } catch (err) {
      return { source: 'GreyNoise', error: err.message.includes('Failed to fetch') ? 'Network error' : err.message };
    }
  }

  async function queryAbuseIPDB(ip) {
    const key = getKey('AbuseIPDB');
    if (!key) return { source: 'AbuseIPDB', nokey: true };
    const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`, {
      headers: { 'Key': key, 'Accept': 'application/json' }
    });
    if (!res.ok) return { source: 'AbuseIPDB', error: `HTTP ${res.status}` };
    const d = (await res.json()).data;
    const score = d.abuseConfidenceScore || 0;
    return {
      source: 'AbuseIPDB',
      status: score > 50 ? 'malicious' : score > 15 ? 'suspicious' : 'clean',
      data: {
        'Abuse Score': `${score}%`,
        'Total Reports': d.totalReports || 0,
        'ISP': d.isp || 'Unknown',
        'Domain': d.domain || 'N/A',
        'Country': d.countryCode || 'Unknown',
        'Usage Type': d.usageType || 'Unknown',
        'Whitelisted': d.isWhitelisted ? 'Yes' : 'No',
      },
      tags: d.reports?.slice(0, 5).map(r => r.categories?.map(c => abuseCategories[c]).join(', ')).filter(Boolean) || [],
      score: score,
      link: `https://www.abuseipdb.com/check/${ip}`,
    };
  }

  const abuseCategories = {
    1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Orders', 4: 'DDoS Attack',
    5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
    9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
    14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection', 17: 'Spoofing',
    18: 'Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host', 21: 'Web App Attack',
    22: 'SSH', 23: 'IoT Targeted',
  };

  async function queryVirusTotal(ioc, type) {
    const key = getKey('VirusTotal');
    if (!key) return { source: 'VirusTotal', nokey: true };
    let endpoint;
    if (isIP(type)) endpoint = `ip_addresses/${ioc}`;
    else if (isDomain(type)) endpoint = `domains/${ioc}`;
    else if (isHash(type)) endpoint = `files/${ioc}`;
    else if (type === 'url') {
      const id = btoa(ioc).replace(/=/g, '');
      endpoint = `urls/${id}`;
    } else return { source: 'VirusTotal', error: 'Unsupported type' };

    const res = await fetch(`https://www.virustotal.com/api/v3/${endpoint}`, {
      headers: { 'x-apikey': key }
    });
    if (!res.ok) return { source: 'VirusTotal', error: `HTTP ${res.status}` };
    const d = (await res.json()).data;
    const stats = d.attributes?.last_analysis_stats || {};
    const mal = stats.malicious || 0;
    const sus = stats.suspicious || 0;
    const total = (stats.harmless || 0) + (stats.undetected || 0) + mal + sus;
    const vtScore = total > 0 ? Math.round((mal + sus * 0.5) / total * 100) : 0;

    const data = { 'Malicious': `${mal}/${total}`, 'Suspicious': sus };
    if (d.attributes?.as_owner) data['AS Owner'] = d.attributes.as_owner;
    if (d.attributes?.reputation != null) data['VT Reputation'] = d.attributes.reputation;
    if (d.attributes?.meaningful_name) data['Name'] = d.attributes.meaningful_name;
    if (d.attributes?.type_description) data['Type'] = d.attributes.type_description;

    let link = `https://www.virustotal.com/gui/`;
    if (isIP(type)) link += `ip-address/${ioc}`;
    else if (isDomain(type)) link += `domain/${ioc}`;
    else if (isHash(type)) link += `file/${ioc}`;
    else link += `url/${btoa(ioc).replace(/=/g, '')}`;

    return {
      source: 'VirusTotal',
      status: mal > 3 ? 'malicious' : mal > 0 ? 'suspicious' : 'clean',
      data,
      tags: d.attributes?.tags?.slice(0, 8) || [],
      score: vtScore,
      link,
    };
  }

  async function queryThreatFox(ioc, type) {
    // ThreatFox API now requires authentication (changed policy)
    return { 
      source: 'ThreatFox', 
      error: 'API now requires authentication - service temporarily unavailable',
      link: 'https://threatfox.abuse.ch/'
    };
  }

  async function queryURLhaus(ioc) {
    // URLhaus API now requires authentication (changed policy)
    return { 
      source: 'URLhaus', 
      error: 'API now requires authentication - service temporarily unavailable',
      link: 'https://urlhaus.abuse.ch/'
    };
  }

  async function queryIPQS(ip) {
    const key = getKey('IPQS');
    if (!key) return { source: 'IPQualityScore', nokey: true };
    const res = await fetch(`https://ipqualityscore.com/api/json/ip/${key}/${ip}?strictness=1&allow_public_access_points=true`);
    if (!res.ok) return { source: 'IPQualityScore', error: `HTTP ${res.status}` };
    const d = await res.json();
    if (!d.success) return { source: 'IPQualityScore', error: d.message || 'Failed' };
    const score = d.fraud_score || 0;
    return {
      source: 'IPQualityScore',
      status: score > 75 ? 'malicious' : score > 30 ? 'suspicious' : 'clean',
      data: {
        'Fraud Score': `${score}/100`,
        'VPN': d.vpn ? '⚠️ Yes' : 'No',
        'Tor': d.tor ? '⚠️ Yes' : 'No',
        'Proxy': d.proxy ? '⚠️ Yes' : 'No',
        'Bot': d.bot_status ? '⚠️ Yes' : 'No',
        'ISP': d.ISP || 'Unknown',
        'City': d.city || 'Unknown',
        'Country': d.country_code || 'Unknown',
      },
      score,
      link: `https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/${ip}`,
    };
  }

  // ── Query Orchestrator ──
  async function lookup(ioc, type) {
    const queries = [];
    const value = type === 'url' ? extractDomain(ioc, type) : ioc;

    if (isIP(type)) {
      queries.push(queryShodanInternetDB(ioc));
      queries.push(queryIPAPI(ioc));
      queries.push(queryGreyNoise(ioc));
      queries.push(queryAbuseIPDB(ioc));
      queries.push(queryVirusTotal(ioc, type));
      queries.push(queryThreatFox(ioc, type));
      queries.push(queryIPQS(ioc));
    } else if (isDomain(type) || type === 'url') {
      queries.push(queryVirusTotal(value, type === 'url' ? type : 'domain'));
      queries.push(queryThreatFox(value, 'domain'));
      queries.push(queryURLhaus(type === 'url' ? ioc : value));
    } else if (isHash(type)) {
      queries.push(queryVirusTotal(ioc, type));
      queries.push(queryThreatFox(ioc, type));
    }

    const results = await Promise.allSettled(queries);
    return results.map(r => r.status === 'fulfilled' ? r.value : { source: 'Unknown', error: r.reason?.message || 'Failed' });
  }

  // ── UI Rendering ──
  function riskClass(score) {
    if (score == null) return 'risk-unknown';
    if (score <= 10) return 'risk-clean';
    if (score <= 35) return 'risk-low';
    if (score <= 65) return 'risk-medium';
    return 'risk-high';
  }
  function riskLabel(score) {
    if (score == null) return 'Unknown';
    if (score <= 10) return 'Clean';
    if (score <= 35) return 'Low Risk';
    if (score <= 65) return 'Medium Risk';
    return 'High Risk';
  }

  function renderSummary(ioc, type, results) {
    const el = document.getElementById('summary');
    const scored = results.filter(r => r.score != null && !r.nokey && !r.error);
    const avgScore = scored.length > 0 ? Math.round(scored.reduce((a, r) => a + r.score, 0) / scored.length) : null;
    const rc = riskClass(avgScore);
    const sourcesOk = results.filter(r => !r.nokey && !r.error).length;
    const sourcesTotal = results.length;

    el.innerHTML = `
      <div class="summary-header">
        <div>
          <div class="summary-type">${type.toUpperCase()}</div>
          <div class="summary-ioc">${escHtml(ioc)}</div>
        </div>
        <div class="threat-score">
          <div class="score-circle ${rc}">${avgScore != null ? avgScore : '?'}</div>
          <div>
            <div class="score-label ${rc}">${riskLabel(avgScore)}</div>
            <div class="score-sublabel">Aggregate Score</div>
          </div>
        </div>
      </div>
      <div class="summary-meta">
        <span>📡 ${sourcesOk}/${sourcesTotal} sources responded</span>
        <span>🕐 ${new Date().toLocaleTimeString()}</span>
      </div>
      <div class="summary-actions">
        <button class="text-btn" onclick="copyResults()">📋 Copy Summary</button>
        <button class="text-btn" onclick="exportJSON()">💾 Export JSON</button>
      </div>
    `;
    el.classList.remove('hidden');
  }

  function renderResults(results) {
    const grid = document.getElementById('results');
    grid.innerHTML = results.map(r => {
      if (r.nokey) {
        return `<div class="result-card nokey">
          <div class="card-header"><span class="card-source">${escHtml(r.source)}</span><span class="card-status status-nokey">No API Key</span></div>
          <div class="card-body"><p style="color:var(--text-dim)">Configure API key in ⚙️ Settings to enable this source.</p></div>
        </div>`;
      }
      if (r.error) {
        return `<div class="result-card error">
          <div class="card-header"><span class="card-source">${escHtml(r.source)}</span><span class="card-status status-error">Error</span></div>
          <div class="card-body"><p style="color:var(--text-dim)">${escHtml(r.error)}</p></div>
        </div>`;
      }
      const statusClass = r.status === 'malicious' ? 'status-malicious' : r.status === 'suspicious' ? 'status-suspicious' : 'status-clean';
      const cardClass = r.status === 'malicious' ? 'warning' : 'success';
      const dl = r.data ? Object.entries(r.data).map(([k, v]) => `<dt>${escHtml(k)}</dt><dd>${escHtml(String(v))}</dd>`).join('') : '';
      const tags = (r.tags || []).map(t => `<span class="tag">${escHtml(String(t))}</span>`).join('');
      const link = r.link ? `<a class="card-link" href="${escHtml(r.link)}" target="_blank" rel="noopener">View full report →</a>` : '';
      return `<div class="result-card ${cardClass}">
        <div class="card-header">
          <span class="card-source">${escHtml(r.source)}</span>
          <span class="card-status ${statusClass}">${r.status || 'info'}</span>
        </div>
        <div class="card-body">
          <dl>${dl}</dl>
          ${tags ? `<div class="tags">${tags}</div>` : ''}
          ${link}
        </div>
      </div>`;
    }).join('');
  }

  function renderHistory() {
    const section = document.getElementById('historySection');
    const list = document.getElementById('historyList');
    const h = getHistory();
    if (!h.length) { section.classList.add('hidden'); return; }
    section.classList.remove('hidden');
    list.innerHTML = h.slice(0, 20).map(e =>
      `<div class="history-item" onclick="document.getElementById('iocInput').value='${escHtml(e.ioc)}';doSearch()">
        <span class="history-ioc">${escHtml(e.ioc)}</span>
        <span class="history-time">${new Date(e.time).toLocaleString()}</span>
      </div>`
    ).join('');
  }

  function escHtml(s) {
    const d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  // ── Global state for export ──
  let lastResults = null;
  let lastIoC = '';
  let lastType = '';

  window.copyResults = function () {
    if (!lastResults) return;
    const lines = [`IoC: ${lastIoC} (${lastType})`, `Time: ${new Date().toISOString()}`, ''];
    lastResults.filter(r => !r.nokey && !r.error).forEach(r => {
      lines.push(`── ${r.source} [${r.status || 'info'}] ──`);
      if (r.data) Object.entries(r.data).forEach(([k, v]) => lines.push(`  ${k}: ${v}`));
      lines.push('');
    });
    navigator.clipboard.writeText(lines.join('\n')).then(() => {
      const btn = document.querySelector('.summary-actions .text-btn');
      if (btn) { const t = btn.textContent; btn.textContent = '✅ Copied!'; setTimeout(() => btn.textContent = t, 1500); }
    });
  };

  window.exportJSON = function () {
    if (!lastResults) return;
    const blob = new Blob([JSON.stringify({ ioc: lastIoC, type: lastType, time: new Date().toISOString(), results: lastResults }, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `ioc-${lastIoC.replace(/[^a-z0-9]/gi, '_')}.json`;
    a.click();
  };

  // ── Search Handler ──
  window.doSearch = async function () {
    const input = document.getElementById('iocInput').value.trim();
    if (!input) return;
    const type = detectType(input);
    if (!type) {
      alert('Could not identify IoC type. Please enter a valid IP, domain, URL, or file hash.');
      return;
    }

    const badge = document.getElementById('iocBadge');
    badge.textContent = type;
    badge.classList.remove('hidden');

    const loading = document.getElementById('loading');
    const searchBtn = document.getElementById('searchBtn');
    searchBtn.disabled = true;
    loading.classList.remove('hidden');
    document.getElementById('summary').classList.add('hidden');
    document.getElementById('results').innerHTML = '';

    try {
      const results = await lookup(input, type);
      lastResults = results;
      lastIoC = input;
      lastType = type;
      renderSummary(input, type, results);
      renderResults(results);
      addHistory(input, type);
    } catch (e) {
      document.getElementById('results').innerHTML = `<div class="result-card error"><div class="card-header"><span class="card-source">Error</span></div><div class="card-body">${escHtml(e.message)}</div></div>`;
    } finally {
      loading.classList.add('hidden');
      searchBtn.disabled = false;
    }
  };

  // ── Event Listeners ──
  document.getElementById('searchBtn').addEventListener('click', doSearch);
  document.getElementById('iocInput').addEventListener('keydown', e => { if (e.key === 'Enter') doSearch(); });
  document.getElementById('iocInput').addEventListener('input', e => {
    const type = detectType(e.target.value.trim());
    const badge = document.getElementById('iocBadge');
    if (type) { badge.textContent = type; badge.classList.remove('hidden'); }
    else badge.classList.add('hidden');
  });

  // Settings modal
  const modal = document.getElementById('settingsModal');
  document.getElementById('settingsBtn').addEventListener('click', () => {
    document.getElementById('keyAbuseIPDB').value = getKey('AbuseIPDB');
    document.getElementById('keyVirusTotal').value = getKey('VirusTotal');
    document.getElementById('keyIPQS').value = getKey('IPQS');
    modal.classList.remove('hidden');
  });
  document.getElementById('closeSettings').addEventListener('click', () => modal.classList.add('hidden'));
  modal.addEventListener('click', e => { if (e.target === modal) modal.classList.add('hidden'); });
  document.getElementById('saveKeys').addEventListener('click', () => {
    setKey('AbuseIPDB', document.getElementById('keyAbuseIPDB').value);
    setKey('VirusTotal', document.getElementById('keyVirusTotal').value);
    setKey('IPQS', document.getElementById('keyIPQS').value);
    modal.classList.add('hidden');
  });
  document.getElementById('clearKeys').addEventListener('click', () => {
    if (confirm('Clear all stored API keys?')) {
      clearAllKeys();
      document.getElementById('keyAbuseIPDB').value = '';
      document.getElementById('keyVirusTotal').value = '';
      document.getElementById('keyIPQS').value = '';
    }
  });
  document.getElementById('clearHistory').addEventListener('click', () => {
    localStorage.removeItem('ioc_history');
    renderHistory();
  });

  renderHistory();
})();
