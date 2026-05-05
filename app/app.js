/* ═══════════════════════════════════════════════════════════
   BUG-OVAWATCH DASHBOARD  ·  app.js
   Covers every output file from v2 recon pipeline.
   ═══════════════════════════════════════════════════════════ */

'use strict';

const BASE = '../output/';

/* ── State ──────────────────────────────────────────────── */
const S = {
  domains: [], currentDomain: null, activeTab: 'overview',
  data: {},     // keyed by domain name
  charts: [],   // Chart.js instances — destroyed before re-render
  filters: {
    subSearch:'', subStatus:'all', subTool:'all',
    nucleiSev:'all', nucleiSearch:'',
    urlSource:'all', urlSearch:'',
    httpSearch:'', httpStatus:'all',
    portSearch:'',
    dnsType:'all',
    techSearch:'',
  },
  sortCol: {}, sortDir: {},  // per-table sort state
  pages: {},                 // per-section page index
};

const PAGE_SIZE = 100;

/* ════════════════════════════════════════════════════════════
   INIT
   ════════════════════════════════════════════════════════════ */
document.addEventListener('DOMContentLoaded', async () => {
  renderShell();
  await loadDomains();
  setupModal();
});

/* ════════════════════════════════════════════════════════════
   SHELL RENDERING
   ════════════════════════════════════════════════════════════ */
function renderShell() {
  document.getElementById('app').innerHTML = `
    <!-- Topbar -->
    <header class="topbar">
      <div class="logo">
        <div class="logo-hex">⬡</div>
        <span>BUG<span class="logo-accent">OVAWATCH</span></span>
      </div>
      <div class="topbar-sep"></div>
      <div class="target-wrap">
        <span class="target-label">TARGET</span>
        <select id="domain-select" class="domain-select">
          <option value="">— select domain —</option>
        </select>
      </div>
      <div class="topbar-sep"></div>
      <div class="search-wrap">
        <span class="search-icon">⌕</span>
        <input id="global-search" class="search-input" type="text" placeholder="Search across all results…" />
      </div>
      <div class="topbar-actions">
        <button id="export-btn" class="btn btn-outline btn-sm" style="display:none">↓ Export JSON</button>
      </div>
    </header>

    <!-- Sidebar -->
    <nav class="sidebar">
      <div class="nav-section-label">Navigation</div>
      ${[
        ['overview',    '◈', 'Overview',     ''],
        ['subdomains',  '⊡', 'Subdomains',   'sub'],
        ['dns',         '⊞', 'DNS & Assets', ''],
        ['http',        '⊟', 'HTTP & Ports', 'http'],
        ['vulns',       '⚠', 'Vulnerabilities', 'vuln'],
        ['urls',        '⊙', 'URL Discovery','url'],
        ['techstack',   '⊛', 'Tech Stack',   ''],
        ['screenshots', '▦', 'Screenshots',  'ss'],
      ].map(([tab, icon, label, badgeKey]) => `
        <div class="nav-item${tab === 'overview' ? ' active' : ''}" data-tab="${tab}">
          <span class="nav-icon">${icon}</span>
          <span class="nav-label">${label}</span>
          ${badgeKey ? `<span class="nav-badge" id="badge-${badgeKey}">0</span>` : ''}
        </div>
      `).join('')}
    </nav>

    <!-- Main -->
    <main class="main" id="main">
      <div id="tab-content">${renderSplash()}</div>
    </main>
  `;

  // Nav clicks
  document.querySelectorAll('.nav-item').forEach(el =>
    el.addEventListener('click', () => {
      if (!S.currentDomain) return;
      setTab(el.dataset.tab);
    })
  );

  // Domain select
  document.getElementById('domain-select').addEventListener('change', e => {
    if (e.target.value) selectDomain(e.target.value);
  });

  // Global search — re-renders active tab
  document.getElementById('global-search').addEventListener('input', e => {
    S.filters.subSearch = e.target.value;
    S.filters.nucleiSearch = e.target.value;
    S.filters.urlSearch = e.target.value;
    S.filters.httpSearch = e.target.value;
    if (S.currentDomain) renderActiveTab();
  });

  // Export
  document.getElementById('export-btn').addEventListener('click', exportData);
}

function renderSplash() {
  return `
    <div class="splash">
      <div class="splash-hex">⬡</div>
      <h2>No Target Selected</h2>
      <p>Select a domain from the dropdown to load recon data.</p>
      <p>Make sure you're running from the project root: <code>python3 -m http.server 8000</code></p>
    </div>
  `;
}

/* ════════════════════════════════════════════════════════════
   DOMAIN LOADING
   ════════════════════════════════════════════════════════════ */
async function loadDomains() {
  const links = await listDir(BASE);
  S.domains = links
    .filter(h => h.endsWith('/'))
    .map(h => h.replace(/\/$/, ''))
    .filter(h => h && h !== '..');

  const sel = document.getElementById('domain-select');
  if (!sel) return;
  sel.innerHTML = '<option value="">— select domain —</option>' +
    S.domains.map(d => `<option value="${d}">${d}</option>`).join('');

  if (S.domains.length === 1) selectDomain(S.domains[0]);
}

async function selectDomain(domain) {
  S.currentDomain = domain;
  document.getElementById('domain-select').value = domain;
  document.getElementById('export-btn').style.display = '';
  setActiveNav('overview');
  showLoading();

  if (!S.data[domain]) {
    S.data[domain] = await loadDomainData(domain);
  }
  updateBadges(S.data[domain]);
  S.activeTab = 'overview';
  renderActiveTab();
}

/* ════════════════════════════════════════════════════════════
   DATA LOADING — every file from the v2 pipeline
   ════════════════════════════════════════════════════════════ */
async function loadDomainData(domain) {
  const base = `${BASE}${domain}/`;
  const raw  = `${base}raw/`;

  // Parallel fetch of all text/JSON files
  const [
    whoisTxt, asnTxt, dnsTxt, zoneTxt,
    crtshLines, afLines, sfLines, amassLines, sdnsLines,
    allSubLines, alterxLines, aliveLines, dnxsLines,
    aliveUrlLines, naabuLines,
    httpxRaw, whatwebRaw, nucleiRaw,
    amassRawLines,
  ] = await Promise.all([
    fetchText(`${base}whois.txt`),
    fetchText(`${base}asn_ranges.txt`),
    fetchText(`${base}dns_records.txt`),
    fetchText(`${base}zone_transfer.txt`),
    fetchLines(`${base}crt.sh.txt`),
    fetchLines(`${base}assetfinder.txt`),
    fetchLines(`${base}subfinder.txt`),
    fetchLines(`${base}amass.txt`),
    fetchLines(`${base}shuffledns.txt`),
    fetchLines(`${base}subdomains.txt`),
    fetchLines(`${base}alterx.txt`),
    fetchLines(`${base}alive_subdomains.txt`),
    fetchLines(`${base}dnsx_records.txt`),
    fetchLines(`${base}alive_urls.txt`),
    fetchLines(`${base}naabu.txt`),
    fetchText(`${base}httpx.jsonl`),
    fetchText(`${base}whatweb.jsonl`),
    fetchText(`${raw}nuclei_results.json`),
    fetchLines(`${raw}amass_raw.txt`),
  ]);

  // Async: directory-based URL sources
  const [waybackUrls, gauUrls, urlfinderUrls, katanaUrls, screenshots] = await Promise.all([
    loadDirFiles(domain, 'waybackurls', '_wayback.txt'),
    loadDirFiles(domain, 'gau', '_gau.txt'),
    loadDirFiles(domain, 'urlfinder', '_urlfinder.txt'),
    fetchLines(`${base}katana/katana.txt`),
    listImages(domain),
  ]);

  // ── Process ───────────────────────────────────────────────
  const httpxResults = parseJsonl(httpxRaw);
  const whatwebResults = parseWhatWeb(whatwebRaw);
  const nucleiFindings = parseNuclei(nucleiRaw);
  const naabuPorts = parseNaabu(naabuLines);
  const dnsRecords = parseDnsRecords(dnsTxt);

  // Build subdomain map: hostname → { tools, isAlive, httpxData }
  const aliveSet = new Set(aliveLines);
  const aliveUrlSet = new Set(aliveUrlLines.map(u => {
    try { return new URL(u).hostname; } catch { return u; }
  }));
  const httpxMap = {};
  httpxResults.forEach(r => {
    const host = extractHost(r.url || r.input || '');
    if (host) httpxMap[host] = r;
  });

  const toolFiles = { 'crt.sh': crtshLines, assetfinder: afLines, subfinder: sfLines, amass: amassLines, shuffledns: sdnsLines };
  const subMap = new Map();
  allSubLines.forEach(h => { if (h) subMap.set(h, { tools: new Set(), isAlive: false, httpxData: null }); });
  Object.entries(toolFiles).forEach(([tool, lines]) => {
    lines.forEach(h => {
      if (!h) return;
      if (!subMap.has(h)) subMap.set(h, { tools: new Set(), isAlive: false, httpxData: null });
      subMap.get(h).tools.add(tool);
    });
  });
  subMap.forEach((v, host) => {
    v.isAlive = aliveSet.has(host) || aliveUrlSet.has(host);
    v.httpxData = httpxMap[host] || null;
  });

  // Tech inventory from httpx + whatweb
  const techInventory = buildTechInventory(httpxResults, whatwebResults);

  // Severity counts
  const sevCounts = { critical:0, high:0, medium:0, low:0, info:0, unknown:0 };
  nucleiFindings.forEach(f => {
    const s = (f.info?.severity || f.severity || 'unknown').toLowerCase();
    sevCounts[s] = (sevCounts[s] || 0) + 1;
  });

  // Tool subdomain counts
  const toolCounts = {};
  Object.keys(toolFiles).forEach(t => { toolCounts[t] = toolFiles[t].length; });

  // Flatten URL sources
  const allUrls = flattenUrlSources({ wayback: waybackUrls, gau: gauUrls, urlfinder: urlfinderUrls, katana: katanaUrls.map(u => ({ source:'katana', url:u })) });

  return {
    domain,
    // Phase 1
    whois: whoisTxt, asnRanges: asnTxt.split('\n').filter(Boolean), dnsRecords, zoneTransfer: zoneTxt,
    // Phase 2/3
    subMap, allSubLines, aliveLines, dnxsLines, alterxLines,
    // Phase 4
    httpxResults, aliveUrlLines,
    // Phase 5
    naabuPorts,
    // Phase 6
    screenshots, whatwebResults,
    // Phase 7
    waybackUrls, gauUrls, urlfinderUrls, katanaUrls, allUrls,
    // Phase 8
    nucleiFindings,
    // Computed
    sevCounts, toolCounts, techInventory, amassRawLines,
    totalUrls: allUrls.length,
  };
}

/* ── Directory file loaders ─────────────────────────────── */
async function loadDirFiles(domain, subdir, suffix) {
  const dirUrl = `${BASE}${domain}/${subdir}/`;
  const links = await listDir(dirUrl);
  const txtFiles = links.filter(h => h.endsWith('.txt') && h !== '../');
  const results = [];
  await Promise.all(txtFiles.map(async fname => {
    const sub = fname.replace(suffix, '').replace(/_wayback$/, '').replace(/_gau$/, '').replace(/_urlfinder$/, '');
    const lines = await fetchLines(`${dirUrl}${fname}`);
    lines.forEach(url => results.push({ source: subdir.replace('urls','').replace('urlfinder','urlfinder'), sub, url }));
  }));
  return results;
}

async function listImages(domain) {
  const dirUrl = `${BASE}${domain}/screenshots/`;
  const links = await listDir(dirUrl);
  return links.filter(h => /\.(jpe?g|png|webp|gif)$/i.test(h) && h !== '../');
}

/* ════════════════════════════════════════════════════════════
   PARSERS
   ════════════════════════════════════════════════════════════ */
function parseJsonl(raw) {
  if (!raw) return [];
  // Try array first
  try { const a = JSON.parse(raw); if (Array.isArray(a)) return a; } catch {}
  // NDJSON
  return raw.split('\n').filter(l => l.trim()).map(l => {
    try { return JSON.parse(l); } catch { return null; }
  }).filter(Boolean);
}

function parseNuclei(raw) { return parseJsonl(raw); }

function parseNaabu(lines) {
  return lines.map(l => {
    const m = l.match(/^(.+):(\d+)$/);
    if (m) return { host: m[1], port: parseInt(m[2]) };
    return null;
  }).filter(Boolean);
}

function parseDnsRecords(raw) {
  if (!raw) return {};
  const records = {};
  let currentType = 'OTHER';
  raw.split('\n').forEach(line => {
    if (line.startsWith('## ')) { currentType = line.slice(3).trim(); }
    else if (line.trim() && !line.startsWith('#')) {
      if (!records[currentType]) records[currentType] = [];
      records[currentType].push(line.trim());
    }
  });
  return records;
}

function parseWhatWeb(raw) {
  if (!raw) return [];
  return raw.split('\n').filter(l => l.trim()).flatMap(l => {
    try {
      const parsed = JSON.parse(l);
      return Array.isArray(parsed) ? parsed : [parsed];
    } catch { return []; }
  });
}

function buildTechInventory(httpxResults, whatwebResults) {
  const inv = new Map(); // tech → Set of hosts
  httpxResults.forEach(r => {
    const host = extractHost(r.url || '');
    const techs = r.tech || r.technologies || r.technology || [];
    (Array.isArray(techs) ? techs : [techs]).filter(Boolean).forEach(t => {
      const tk = normalizeTech(t);
      if (!inv.has(tk)) inv.set(tk, new Set());
      if (host) inv.get(tk).add(host);
    });
  });
  whatwebResults.forEach(r => {
    const host = extractHost(r.target || r.uri || '');
    const plugins = r.plugins || {};
    Object.keys(plugins).forEach(t => {
      const tk = normalizeTech(t);
      if (!inv.has(tk)) inv.set(tk, new Set());
      if (host) inv.get(tk).add(host);
    });
  });
  return inv;
}

function flattenUrlSources(sources) {
  const result = [];
  Object.entries(sources).forEach(([src, items]) => {
    items.forEach(item => {
      if (typeof item === 'string') result.push({ source: src, url: item });
      else result.push({ ...item, source: item.source || src });
    });
  });
  return result;
}

/* ════════════════════════════════════════════════════════════
   TAB SYSTEM
   ════════════════════════════════════════════════════════════ */
function setTab(tab) {
  S.activeTab = tab;
  setActiveNav(tab);
  S.pages[tab] = 0;
  renderActiveTab();
}

function setActiveNav(tab) {
  document.querySelectorAll('.nav-item').forEach(el => {
    el.classList.toggle('active', el.dataset.tab === tab);
  });
}

function renderActiveTab() {
  destroyCharts();
  const d = S.data[S.currentDomain];
  if (!d) return;
  const fns = { overview: renderOverview, subdomains: renderSubdomains, dns: renderDns,
    http: renderHttp, vulns: renderVulns, urls: renderUrls, techstack: renderTechStack, screenshots: renderScreenshots };
  const el = document.getElementById('tab-content');
  if (!el) return;
  el.innerHTML = (fns[S.activeTab] || renderOverview)(d);
  attachTabEvents(S.activeTab, d);
}

function showLoading() {
  const el = document.getElementById('tab-content');
  if (el) el.innerHTML = `<div class="loading-wrap"><div class="spinner"></div><div class="loading-label">Loading recon data…</div></div>`;
}

function updateBadges(d) {
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  set('badge-sub', d.subMap.size);
  set('badge-http', d.httpxResults.length);
  set('badge-vuln', d.nucleiFindings.length);
  const b = document.getElementById('badge-vuln');
  if (b) { b.className = 'nav-badge' + (d.sevCounts.critical > 0 ? ' danger' : d.sevCounts.high > 0 ? ' warn' : ''); }
  set('badge-url', d.allUrls.length);
  set('badge-ss', d.screenshots.length);
}

/* ════════════════════════════════════════════════════════════
   TAB: OVERVIEW
   ════════════════════════════════════════════════════════════ */
function renderOverview(d) {
  const total = d.sevCounts.critical + d.sevCounts.high + d.sevCounts.medium + d.sevCounts.low + d.sevCounts.info;
  const aliveCount = [...d.subMap.values()].filter(v => v.isAlive).length;
  const topVulns = [...d.nucleiFindings]
    .sort((a,b) => sevOrder(a) - sevOrder(b)).slice(0,5);

  return `
    <div class="tab-intro">
      <div><h2>${d.domain}</h2><p>Recon summary — all phases</p></div>
      <button class="btn btn-outline btn-sm" onclick="copyToClip('${d.domain}')">Copy Target</button>
    </div>

    <div class="stat-grid">
      ${statCard('Subdomains', d.subMap.size, '', '')}
      ${statCard('Alive Hosts', aliveCount, `of ${d.subMap.size}`, 'accent')}
      ${statCard('Open Ports', d.naabuPorts.length, 'unique host:port', '')}
      ${statCard('Vulnerabilities', total, getCritHigh(d.sevCounts), total > 0 ? 'danger' : '')}
      ${statCard('Archived URLs', d.allUrls.length, 'wayback+gau+katana', '')}
      ${statCard('Screenshots', d.screenshots.length, 'captured', '')}
    </div>

    <div class="charts-row">
      <div class="chart-card">
        <div class="chart-title">Severity Distribution</div>
        <div class="chart-canvas-wrap"><canvas id="chart-sev"></canvas></div>
      </div>
      <div class="chart-card">
        <div class="chart-title">Subdomain Sources</div>
        <div class="chart-canvas-wrap"><canvas id="chart-sources"></canvas></div>
      </div>
    </div>

    <div class="overview-grid">
      <!-- Top vulnerabilities -->
      <div class="highlight-card">
        <div class="highlight-head">
          <span class="highlight-dot red"></span> Top Findings
        </div>
        <div class="highlight-list">
          ${topVulns.length ? topVulns.map(f => `
            <div class="highlight-item">
              ${sevBadge(f.info?.severity || f.severity)}
              <span class="hi-text">${esc(f.info?.name || f['template-id'] || 'Unknown')}</span>
              <span class="hi-meta">${esc(shortHost(f.host || f['matched-at'] || ''))}</span>
            </div>`).join('') : '<div class="highlight-item"><span class="hi-text" style="color:var(--accent)">No findings — clean!</span></div>'}
        </div>
      </div>

      <!-- Alive hosts sample -->
      <div class="highlight-card">
        <div class="highlight-head"><span class="highlight-dot green"></span> Alive Hosts</div>
        <div class="highlight-list">
          ${[...d.subMap.entries()].filter(([,v]) => v.isAlive).slice(0,6).map(([h,v]) => `
            <div class="highlight-item">
              <span class="hi-text"><a href="http://${esc(h)}" target="_blank">${esc(h)}</a></span>
              ${v.httpxData ? statusBadge(v.httpxData['status-code'] || v.httpxData.status_code) : ''}
            </div>`).join('') || '<div class="highlight-item"><span class="hi-text">No alive hosts found</span></div>'}
        </div>
      </div>

      <!-- Tech summary -->
      <div class="highlight-card">
        <div class="highlight-head"><span class="highlight-dot cyan"></span> Top Technologies</div>
        <div class="highlight-list">
          ${[...d.techInventory.entries()].sort((a,b) => b[1].size - a[1].size).slice(0,6).map(([tech,hosts]) => `
            <div class="highlight-item">
              <span class="hi-text">${esc(tech)}</span>
              <span class="hi-meta">${hosts.size} host${hosts.size !== 1 ? 's':''}</span>
            </div>`).join('') || '<div class="highlight-item"><span class="hi-text">No technology data</span></div>'}
        </div>
      </div>

      <!-- Severity bars -->
      <div class="highlight-card">
        <div class="highlight-head"><span class="highlight-dot red"></span> Vulnerability Breakdown</div>
        <div style="padding:14px 16px">
          <div class="sev-bar-wrap">
            ${Object.entries(d.sevCounts).map(([s,n]) => `
              <div class="sev-bar-row">
                <span class="sev-bar-label" style="color:var(--sev-${s})">${s}</span>
                <div class="sev-bar-track">
                  <div class="sev-bar-fill" style="width:${total ? Math.round(n/total*100) : 0}%;background:var(--sev-${s})"></div>
                </div>
                <span class="sev-bar-count">${n}</span>
              </div>`).join('')}
          </div>
        </div>
      </div>
    </div>
  `;
}

/* ════════════════════════════════════════════════════════════
   TAB: SUBDOMAINS
   ════════════════════════════════════════════════════════════ */
function renderSubdomains(d) {
  const allTools = ['crt.sh','assetfinder','subfinder','amass','shuffledns'];
  let rows = [...d.subMap.entries()].map(([host, v]) => ({ host, ...v, tools: [...v.tools] }));

  // Filters
  const q = S.filters.subSearch.toLowerCase();
  if (q) rows = rows.filter(r => r.host.toLowerCase().includes(q));
  if (S.filters.subStatus !== 'all') rows = rows.filter(r => S.filters.subStatus === 'alive' ? r.isAlive : !r.isAlive);
  if (S.filters.subTool !== 'all') rows = rows.filter(r => r.tools.includes(S.filters.subTool));

  // Sort
  rows = sortRows(rows, 'sub', 'host', 'asc', rows);

  const page = S.pages.subdomains || 0;
  const paged = rows.slice(page*PAGE_SIZE, (page+1)*PAGE_SIZE);

  return `
    <div class="tab-intro">
      <div><h2>Subdomains</h2><p>${d.subMap.size} discovered, ${[...d.subMap.values()].filter(v=>v.isAlive).length} alive</p></div>
    </div>
    <div class="filter-bar">
      <div class="filter-search">
        <span class="fi">⌕</span>
        <input id="sub-search" type="text" placeholder="Filter hostnames…" value="${esc(S.filters.subSearch)}" />
      </div>
      <select id="sub-status" class="filter-select">
        <option value="all"${S.filters.subStatus==='all'?' selected':''}>All Status</option>
        <option value="alive"${S.filters.subStatus==='alive'?' selected':''}>Alive Only</option>
        <option value="dead"${S.filters.subStatus==='dead'?' selected':''}>Dead Only</option>
      </select>
      <select id="sub-tool" class="filter-select">
        <option value="all">All Sources</option>
        ${allTools.map(t => `<option value="${t}"${S.filters.subTool===t?' selected':''}>${t}</option>`).join('')}
      </select>
      <span class="filter-count">${rows.length.toLocaleString()} results</span>
      <button class="btn btn-outline btn-sm" onclick="exportList(${JSON.stringify(rows.map(r=>r.host))}, 'subdomains.txt')">↓ Export</button>
    </div>
    <div class="panel" style="overflow:hidden">
      <div class="table-wrap">
        <table>
          <thead><tr>
            <th data-sort-table="sub" data-sort-key="host">Hostname <span class="sort-icon">⇅</span></th>
            <th>Sources</th>
            <th data-sort-table="sub" data-sort-key="isAlive">Status <span class="sort-icon">⇅</span></th>
            <th>Title</th>
            <th>Status Code</th>
            <th>Technologies</th>
            <th>Actions</th>
          </tr></thead>
          <tbody>
            ${paged.length ? paged.map(r => {
              const hx = r.httpxData || {};
              const techs = hx.tech || hx.technologies || hx.technology || [];
              const sc = hx['status-code'] || hx.status_code;
              return `<tr>
                <td class="td-mono">${esc(r.host)}</td>
                <td><div class="tools-wrap">${r.tools.map(t=>`<span class="badge badge-tool">${esc(t)}</span>`).join('')}</div></td>
                <td>${r.isAlive ? '<span class="badge badge-alive">Alive</span>' : '<span class="badge badge-dead">Unknown</span>'}</td>
                <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px">${esc(hx.title || '—')}</td>
                <td>${sc ? statusBadge(sc) : '—'}</td>
                <td><div class="tech-pills">${(Array.isArray(techs)?techs:[techs]).filter(Boolean).slice(0,3).map(t=>`<span class="tech-pill">${esc(normalizeTech(t))}</span>`).join('')}</div></td>
                <td>
                  <button class="btn btn-ghost btn-sm" onclick="window.open('http://${esc(r.host)}','_blank')">↗</button>
                  <button class="copy-btn" onclick="copyToClip('${esc(r.host)}')">copy</button>
                </td>
              </tr>`;
            }).join('') : `<tr class="empty-row"><td colspan="7">No subdomains match filters</td></tr>`}
          </tbody>
        </table>
      </div>
      ${paginator('subdomains', rows.length)}
    </div>
  `;
}

/* ════════════════════════════════════════════════════════════
   TAB: DNS & ASSETS
   ════════════════════════════════════════════════════════════ */
function renderDns(d) {
  const hasZone = d.zoneTransfer && d.zoneTransfer.includes('XFR size');

  return `
    <div class="tab-intro"><div><h2>DNS & Assets</h2><p>WHOIS, ASN, DNS records, zone transfer</p></div></div>

    ${hasZone ? `<div class="zone-alert vulnerable">⚠ ZONE TRANSFER SUCCESSFUL — internal DNS records exposed. Review zone_transfer.txt immediately.</div>` :
      `<div class="zone-alert secure">✓ Zone transfer refused by all nameservers (expected behaviour)</div>`}

    <div class="two-col" style="margin-bottom:16px">
      <!-- WHOIS -->
      <div class="panel">
        <div class="panel-header" onclick="togglePanel(this)">
          <span class="panel-title">WHOIS</span>
          <span class="panel-chevron">▼</span>
        </div>
        <div class="panel-body">
          <pre class="pre-block">${esc(d.whois || 'No WHOIS data available')}</pre>
        </div>
      </div>

      <!-- ASN Ranges -->
      <div class="panel">
        <div class="panel-header" onclick="togglePanel(this)">
          <span class="panel-title">ASN / IP Ranges</span>
          <span class="panel-count">${d.asnRanges.length}</span>
          <span class="panel-chevron">▼</span>
        </div>
        <div class="panel-body" style="padding:14px">
          ${d.asnRanges.length
            ? d.asnRanges.map(r=>`<span class="asn-chip">${esc(r)}</span>`).join('')
            : '<span style="color:var(--text-dim);font-size:12px;padding:8px">No ASN data (asnmap not installed or no results)</span>'}
        </div>
      </div>
    </div>

    <!-- DNS Records -->
    <div class="panel" style="margin-bottom:16px">
      <div class="panel-header" onclick="togglePanel(this)">
        <span class="panel-title">DNS Records</span>
        <span class="panel-count">${Object.keys(d.dnsRecords).length} types</span>
        <span class="panel-chevron">▼</span>
      </div>
      <div class="panel-body">
        <div style="padding:16px">
          ${Object.keys(d.dnsRecords).length
            ? Object.entries(d.dnsRecords).map(([type, recs]) => `
              <div style="margin-bottom:14px">
                <span class="dns-record-type">${esc(type)}</span>
                <div style="margin-top:6px">
                  ${recs.map(r=>`<div class="dns-record-val" style="padding:3px 0;border-bottom:1px solid var(--border)">${esc(r)}</div>`).join('')}
                </div>
              </div>`).join('')
            : '<span style="color:var(--text-dim);font-size:12px">No DNS records (dig not installed)</span>'}
        </div>
      </div>
    </div>

    <!-- dnsx full records -->
    <div class="panel" style="margin-bottom:16px">
      <div class="panel-header" onclick="togglePanel(this)">
        <span class="panel-title">dnsx Full Record Scan (alive subdomains)</span>
        <span class="panel-count">${d.dnxsLines.length}</span>
        <span class="panel-chevron">▼</span>
      </div>
      <div class="panel-body">
        <pre class="pre-block">${esc(d.dnxsLines.slice(0,200).join('\n') || 'No dnsx records')}</pre>
        ${d.dnxsLines.length > 200 ? `<div style="padding:8px 14px;font-size:11px;color:var(--text-dim)">Showing 200 of ${d.dnxsLines.length} — export for full data</div>` : ''}
      </div>
    </div>

    <!-- Zone transfer raw -->
    ${hasZone ? `
    <div class="panel">
      <div class="panel-header" onclick="togglePanel(this)">
        <span class="panel-title">Zone Transfer Data</span>
        <span class="panel-chevron">▼</span>
      </div>
      <div class="panel-body">
        <pre class="pre-block">${esc(d.zoneTransfer)}</pre>
      </div>
    </div>` : ''}
  `;
}

/* ════════════════════════════════════════════════════════════
   TAB: HTTP & PORTS
   ════════════════════════════════════════════════════════════ */
function renderHttp(d) {
  const q = S.filters.httpSearch.toLowerCase();
  let httpRows = d.httpxResults;
  if (q) httpRows = httpRows.filter(r => (r.url||'').toLowerCase().includes(q) || (r.title||'').toLowerCase().includes(q));
  if (S.filters.httpStatus !== 'all') {
    const range = S.filters.httpStatus;
    httpRows = httpRows.filter(r => {
      const sc = r['status-code'] || r.status_code || 0;
      if (range === '2xx') return sc >= 200 && sc < 300;
      if (range === '3xx') return sc >= 300 && sc < 400;
      if (range === '4xx') return sc >= 400 && sc < 500;
      if (range === '5xx') return sc >= 500;
      return true;
    });
  }
  httpRows = sortRows(httpRows, 'http', 'status-code', 'asc', httpRows);

  const page = S.pages.http || 0;
  const paged = httpRows.slice(page*PAGE_SIZE, (page+1)*PAGE_SIZE);

  // Port stats
  const portCounts = {};
  d.naabuPorts.forEach(p => { portCounts[p.port] = (portCounts[p.port]||0) + 1; });
  const sortedPorts = Object.entries(portCounts).sort((a,b)=>b[1]-a[1]);
  const COMMON = new Set([80,443,8080,8443,22,21,25,3389,3306,5432,6379,27017]);

  return `
    <div class="tab-intro"><div><h2>HTTP & Ports</h2><p>${d.httpxResults.length} HTTP services · ${d.naabuPorts.length} open ports</p></div></div>

    <!-- Port heatmap -->
    <div class="panel" style="margin-bottom:16px">
      <div class="panel-header" onclick="togglePanel(this)">
        <span class="panel-title">Open Ports (naabu)</span>
        <span class="panel-count">${d.naabuPorts.length} host:port pairs · ${sortedPorts.length} unique ports</span>
        <span class="panel-chevron">▼</span>
      </div>
      <div class="panel-body">
        ${d.naabuPorts.length ? `
          <div style="padding:12px 16px;border-bottom:1px solid var(--border)">
            <div style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim);margin-bottom:8px;text-transform:uppercase;letter-spacing:.08em">Port distribution</div>
            <div class="port-heat">
              ${sortedPorts.map(([p,c]) => `
                <span class="port-chip ${COMMON.has(parseInt(p))?'common':''}" title="${c} host(s)">
                  :${p} <span style="color:var(--text-dim);font-size:9px">${c}</span>
                </span>`).join('')}
            </div>
          </div>
          <div class="filter-bar" style="border-radius:0;border-left:none;border-right:none;border-bottom:none;margin-bottom:0">
            <div class="filter-search">
              <span class="fi">⌕</span>
              <input id="port-search" type="text" placeholder="Filter host or port…" value="${esc(S.filters.portSearch)}" />
            </div>
            <span class="filter-count">${d.naabuPorts.length} entries</span>
            <button class="btn btn-outline btn-sm" onclick="exportList(${JSON.stringify(d.naabuPorts.map(p=>p.host+':'+p.port))},'ports.txt')">↓ Export</button>
          </div>
          <div class="table-wrap">
            <table>
              <thead><tr><th>Host</th><th>Port</th><th>Common Service</th></tr></thead>
              <tbody>
                ${d.naabuPorts.filter(p => {
                  const q2 = S.filters.portSearch.toLowerCase();
                  return !q2 || p.host.includes(q2) || String(p.port).includes(q2);
                }).slice(0,200).map(p => `
                  <tr>
                    <td class="td-mono">${esc(p.host)}</td>
                    <td><span class="badge ${COMMON.has(p.port)?'badge-alive':'badge-dead'}">${p.port}</span></td>
                    <td style="color:var(--text-dim);font-size:11px">${portService(p.port)}</td>
                  </tr>`).join('')}
              </tbody>
            </table>
          </div>` : '<div style="padding:20px;color:var(--text-dim);font-size:12px">No naabu results (naabu not installed or no open ports found)</div>'}
      </div>
    </div>

    <!-- httpx results -->
    <div class="panel">
      <div class="panel-header" onclick="togglePanel(this)">
        <span class="panel-title">HTTP Responses (httpx)</span>
        <span class="panel-count">${d.httpxResults.length}</span>
        <span class="panel-chevron">▼</span>
      </div>
      <div class="panel-body">
        <div class="filter-bar" style="border-radius:0;border:none;border-bottom:1px solid var(--border);margin-bottom:0">
          <div class="filter-search">
            <span class="fi">⌕</span>
            <input id="http-search" type="text" placeholder="Filter URL or title…" value="${esc(S.filters.httpSearch)}" />
          </div>
          <select id="http-status" class="filter-select">
            <option value="all">All Status</option>
            <option value="2xx"${S.filters.httpStatus==='2xx'?' selected':''}>2xx OK</option>
            <option value="3xx"${S.filters.httpStatus==='3xx'?' selected':''}>3xx Redirect</option>
            <option value="4xx"${S.filters.httpStatus==='4xx'?' selected':''}>4xx Client Error</option>
            <option value="5xx"${S.filters.httpStatus==='5xx'?' selected':''}>5xx Server Error</option>
          </select>
          <span class="filter-count">${httpRows.length} results</span>
          <button class="btn btn-outline btn-sm" onclick="exportList(${JSON.stringify(httpRows.map(r=>r.url||''))},'alive_urls.txt')">↓ Export URLs</button>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr>
              <th data-sort-table="http" data-sort-key="url">URL <span class="sort-icon">⇅</span></th>
              <th data-sort-table="http" data-sort-key="status-code">Status <span class="sort-icon">⇅</span></th>
              <th>Title</th>
              <th>Technologies</th>
              <th>Server</th>
              <th>Actions</th>
            </tr></thead>
            <tbody>
              ${paged.length ? paged.map(r => {
                const sc = r['status-code'] || r.status_code;
                const techs = r.tech || r.technologies || r.technology || [];
                return `<tr>
                  <td class="td-url"><a href="${esc(r.url||'')}" target="_blank">${esc(r.url||'?')}</a></td>
                  <td>${sc ? statusBadge(sc) : '—'}</td>
                  <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px">${esc(r.title||'—')}</td>
                  <td><div class="tech-pills">${(Array.isArray(techs)?techs:[techs]).filter(Boolean).slice(0,3).map(t=>`<span class="tech-pill">${esc(normalizeTech(t))}</span>`).join('')}</div></td>
                  <td style="font-size:11px;color:var(--text-dim)">${esc(r.webserver||r['web-server']||'—')}</td>
                  <td>
                    <button class="btn btn-ghost btn-sm" onclick="window.open('${esc(r.url||'')}','_blank')">↗</button>
                    <button class="copy-btn" onclick="copyToClip('${esc(r.url||'')}')">copy</button>
                    <button class="btn btn-ghost btn-sm" onclick="showHttpxDetail(${JSON.stringify(r).replace(/'/g,'&#39;').replace(/</g,'&lt;')})">detail</button>
                  </td>
                </tr>`;
              }).join('') : `<tr class="empty-row"><td colspan="6">No HTTP results match filters</td></tr>`}
            </tbody>
          </table>
        </div>
        ${paginator('http', httpRows.length)}
      </div>
    </div>
  `;
}

/* ════════════════════════════════════════════════════════════
   TAB: VULNERABILITIES
   ════════════════════════════════════════════════════════════ */
function renderVulns(d) {
  const sevs = ['all','critical','high','medium','low','info','unknown'];
  let findings = d.nucleiFindings;
  const q = S.filters.nucleiSearch.toLowerCase();
  if (q) findings = findings.filter(f =>
    (f.info?.name||'').toLowerCase().includes(q) ||
    (f['template-id']||'').toLowerCase().includes(q) ||
    (f.host||'').toLowerCase().includes(q) ||
    (f['matched-at']||'').toLowerCase().includes(q));
  if (S.filters.nucleiSev !== 'all')
    findings = findings.filter(f => (f.info?.severity||f.severity||'unknown').toLowerCase() === S.filters.nucleiSev);
  findings = [...findings].sort((a,b) => sevOrder(a)-sevOrder(b));

  const page = S.pages.vulns || 0;
  const paged = findings.slice(page*50, (page+1)*50);

  return `
    <div class="tab-intro">
      <div><h2>Vulnerabilities</h2><p>${d.nucleiFindings.length} findings from nuclei scan</p></div>
    </div>
    <div class="filter-bar">
      <div class="filter-search">
        <span class="fi">⌕</span>
        <input id="vuln-search" type="text" placeholder="Search template, name, host…" value="${esc(S.filters.nucleiSearch)}" />
      </div>
      <div class="filter-pills">
        ${sevs.map(s => `
          <button class="filter-pill ${s} ${S.filters.nucleiSev===s?'active':''}" data-sev="${s}">
            ${s === 'all' ? 'All' : s.charAt(0).toUpperCase()+s.slice(1)}
            ${s !== 'all' && d.sevCounts[s] ? `(${d.sevCounts[s]})` : ''}
          </button>`).join('')}
      </div>
      <span class="filter-count">${findings.length} results</span>
    </div>

    ${findings.length === 0
      ? `<div class="card" style="text-align:center;padding:40px;color:var(--accent)">
           <div style="font-size:40px;margin-bottom:12px">✓</div>
           <h3 style="font-family:var(--font-head)">No vulnerabilities found${S.filters.nucleiSev!=='all'?' in this severity':''}</h3>
           <p style="color:var(--text-dim);font-size:12px;margin-top:6px">Either nuclei found nothing, or nuclei wasn't run. Use --skip-tools to check.</p>
         </div>`
      : `<div>
           ${paged.map((f,i) => renderVulnCard(f, page*50+i)).join('')}
           ${paginator('vulns', findings.length, 50)}
         </div>`}
  `;
}

function renderVulnCard(f, idx) {
  const sev = (f.info?.severity || f.severity || 'unknown').toLowerCase();
  const name = f.info?.name || f['template-id'] || 'Unknown';
  const host = f['matched-at'] || f.host || '—';
  const tid  = f['template-id'] || '—';
  const ts   = f.timestamp ? new Date(f.timestamp).toLocaleString() : '—';
  return `
    <div class="vuln-card ${sev}">
      <div class="vuln-head">
        ${sevBadge(sev)}
        <span class="vuln-name">${esc(name)}</span>
        <button class="btn btn-outline btn-sm" onclick="showVulnDetail(${idx})">Details</button>
      </div>
      <div class="vuln-meta">
        <span><span class="key">template:</span>${esc(tid)}</span>
        <span><span class="key">host:</span><a href="${esc(host)}" target="_blank">${esc(shortHost(host))}</a></span>
        <span><span class="key">time:</span>${ts}</span>
      </div>
      ${f.info?.description ? `<p style="margin-top:8px;font-size:12px;color:var(--text-dim)">${esc(f.info.description.slice(0,200))}${f.info.description.length>200?'…':''}</p>` : ''}
    </div>
  `;
}

/* ════════════════════════════════════════════════════════════
   TAB: URL DISCOVERY
   ════════════════════════════════════════════════════════════ */
function renderUrls(d) {
  const sources = ['all','waybackurls','gau','urlfinder','katana'];
  let urls = d.allUrls;
  const q = S.filters.urlSearch.toLowerCase();
  if (q) urls = urls.filter(u => (u.url||'').toLowerCase().includes(q));
  if (S.filters.urlSource !== 'all') urls = urls.filter(u => {
    const src = (u.source||'').replace('wayback','waybackurls').replace(/urls$/, 'urlfinder').toLowerCase();
    return src === S.filters.urlSource || (u.source||'').toLowerCase() === S.filters.urlSource;
  });

  const page = S.pages.urls || 0;
  const paged = urls.slice(page*PAGE_SIZE, (page+1)*PAGE_SIZE);

  const srcCounts = {};
  d.allUrls.forEach(u => { const s = u.source||'unknown'; srcCounts[s] = (srcCounts[s]||0)+1; });

  return `
    <div class="tab-intro">
      <div><h2>URL Discovery</h2><p>${d.allUrls.length.toLocaleString()} URLs from waybackurls, gau, katana, urlfinder</p></div>
    </div>

    <div class="stat-grid" style="margin-bottom:16px">
      ${Object.entries(srcCounts).map(([src,n]) => statCard(src, n, 'URLs', '')).join('')}
    </div>

    <div class="filter-bar">
      <div class="filter-search">
        <span class="fi">⌕</span>
        <input id="url-search" type="text" placeholder="Filter URLs…" value="${esc(S.filters.urlSearch)}" />
      </div>
      <div class="filter-pills">
        ${sources.map(s => `
          <button class="filter-pill ${S.filters.urlSource===s?'active':''}" data-url-src="${s}">
            ${s === 'all' ? 'All' : s}
            ${s !== 'all' && srcCounts[s] ? `(${srcCounts[s].toLocaleString()})` : ''}
          </button>`).join('')}
      </div>
      <span class="filter-count">${urls.length.toLocaleString()} results</span>
      <button class="btn btn-outline btn-sm" onclick="exportList(${JSON.stringify(urls.map(u=>u.url))},'urls.txt')">↓ Export</button>
    </div>

    <div class="panel">
      <div class="panel-body">
        ${paged.length
          ? paged.map(u => `
            <div class="url-item">
              <span class="badge badge-source">${esc((u.source||'?').slice(0,12))}</span>
              <span class="url-text"><a href="${esc(u.url)}" target="_blank" rel="noopener">${esc(u.url)}</a></span>
              <button class="copy-btn" onclick="copyToClip('${esc(u.url)}')">copy</button>
            </div>`).join('')
          : '<div style="padding:24px;text-align:center;color:var(--text-dim)">No URLs match filters</div>'}
        ${paginator('urls', urls.length)}
      </div>
    </div>
  `;
}

/* ════════════════════════════════════════════════════════════
   TAB: TECH STACK
   ════════════════════════════════════════════════════════════ */
function renderTechStack(d) {
  const q = S.filters.techSearch.toLowerCase();
  let tech = [...d.techInventory.entries()].sort((a,b) => b[1].size - a[1].size);
  if (q) tech = tech.filter(([t]) => t.toLowerCase().includes(q));
  const maxCount = tech[0]?.[1].size || 1;

  return `
    <div class="tab-intro">
      <div><h2>Tech Stack</h2><p>Aggregated from httpx tech-detect and whatweb</p></div>
    </div>
    <div class="filter-bar">
      <div class="filter-search">
        <span class="fi">⌕</span>
        <input id="tech-search" type="text" placeholder="Filter technologies…" value="${esc(S.filters.techSearch)}" />
      </div>
      <span class="filter-count">${tech.length} technologies detected</span>
    </div>
    ${tech.length
      ? `<div class="tech-inventory">
           ${tech.map(([t,hosts]) => `
             <div class="tech-card">
               <div class="tech-name">${esc(t)}</div>
               <div class="tech-count">${hosts.size} host${hosts.size!==1?'s':''}</div>
               <div class="tech-bar"><div class="tech-bar-fill" style="width:${Math.round(hosts.size/maxCount*100)}%"></div></div>
             </div>`).join('')}
         </div>`
      : `<div class="card" style="text-align:center;padding:32px;color:var(--text-dim)">
           No technology data.<br><span style="font-size:11px">Requires httpx with -tech-detect (included in v2) or whatweb.</span>
         </div>`}

    ${d.whatwebResults.length ? `
    <hr class="divider">
    <div class="section-head"><span class="section-title">WhatWeb Raw Results</span><span class="section-count">${d.whatwebResults.length}</span></div>
    <div class="panel">
      <div class="panel-body">
        ${d.whatwebResults.slice(0,50).map(r => `
          <div class="url-item">
            <span class="badge badge-tool">whatweb</span>
            <span class="url-text">${esc(r.target||r.uri||'?')}</span>
            <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-dim)">${Object.keys(r.plugins||{}).slice(0,5).join(', ')}</span>
          </div>`).join('')}
      </div>
    </div>` : ''}
  `;
}

/* ════════════════════════════════════════════════════════════
   TAB: SCREENSHOTS
   ════════════════════════════════════════════════════════════ */
function renderScreenshots(d) {
  return `
    <div class="tab-intro">
      <div><h2>Screenshots</h2><p>${d.screenshots.length} captured by gowitness</p></div>
    </div>
    ${d.screenshots.length
      ? `<div class="screenshots-grid">
           ${d.screenshots.map(fname => {
             const label = decodeScreenshotFilename(fname);
             const src = `${BASE}${d.domain}/screenshots/${fname}`;
             return `
               <div class="ss-card" onclick="showScreenshot('${esc(src)}','${esc(label)}')">
                 <img class="ss-img" src="${esc(src)}" alt="${esc(label)}" loading="lazy" onerror="this.style.display='none'" />
                 <div class="ss-label">${esc(label)}</div>
               </div>`;
           }).join('')}
         </div>`
      : `<div class="card" style="text-align:center;padding:40px;color:var(--text-dim)">
           <div style="font-size:32px;margin-bottom:12px">▦</div>
           <p>No screenshots found. Requires gowitness and alive URLs.</p>
         </div>`}
  `;
}

/* ════════════════════════════════════════════════════════════
   CHART RENDERING
   ════════════════════════════════════════════════════════════ */
function attachTabEvents(tab, d) {
  if (tab === 'overview') {
    requestAnimationFrame(() => {
      drawSeverityChart(d.sevCounts);
      drawSourcesChart(d.toolCounts);
    });
  }

  // Sort headers
  document.querySelectorAll('[data-sort-table]').forEach(th => {
    th.addEventListener('click', () => {
      const t = th.dataset.sortTable, k = th.dataset.sortKey;
      S.sortDir[t+k] = S.sortDir[t+k] === 'asc' ? 'desc' : 'asc';
      S.sortCol[t] = k;
      renderActiveTab();
    });
  });

  // Filter inputs
  const bind = (id, key, re) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', e => { S.filters[key]=e.target.value; S.pages[tab]=0; re(); });
  };
  const bindSelect = (id, key, re) => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('change', e => { S.filters[key]=e.target.value; S.pages[tab]=0; re(); });
  };

  if (tab === 'subdomains') {
    bind('sub-search', 'subSearch', renderActiveTab);
    bindSelect('sub-status', 'subStatus', renderActiveTab);
    bindSelect('sub-tool', 'subTool', renderActiveTab);
  }
  if (tab === 'http') {
    bind('http-search', 'httpSearch', renderActiveTab);
    bindSelect('http-status', 'httpStatus', renderActiveTab);
    bind('port-search', 'portSearch', renderActiveTab);
  }
  if (tab === 'vulns') {
    bind('vuln-search', 'nucleiSearch', renderActiveTab);
    document.querySelectorAll('[data-sev]').forEach(btn =>
      btn.addEventListener('click', () => { S.filters.nucleiSev = btn.dataset.sev; S.pages.vulns=0; renderActiveTab(); }));
  }
  if (tab === 'urls') {
    bind('url-search', 'urlSearch', renderActiveTab);
    document.querySelectorAll('[data-url-src]').forEach(btn =>
      btn.addEventListener('click', () => { S.filters.urlSource = btn.dataset.urlSrc; S.pages.urls=0; renderActiveTab(); }));
  }
  if (tab === 'techstack') {
    bind('tech-search', 'techSearch', renderActiveTab);
  }

  // Pagination
  document.querySelectorAll('[data-page-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.dataset.pageTab, dir = btn.dataset.dir;
      S.pages[t] = Math.max(0, (S.pages[t]||0) + (dir==='next'?1:-1));
      renderActiveTab();
    });
  });

  // Panel toggles
  document.querySelectorAll('.panel-header').forEach(el => {
    if (!el.getAttribute('onclick')) el.addEventListener('click', () => togglePanel(el));
  });

  // Collapsible via onclick="togglePanel(this)"
  window.togglePanel = (el) => el.closest('.panel').classList.toggle('collapsed');
}

function destroyCharts() {
  S.charts.forEach(c => { try { c.destroy(); } catch {} });
  S.charts = [];
}

function drawSeverityChart(counts) {
  const canvas = document.getElementById('chart-sev');
  if (!canvas) return;
  const labels = ['Critical','High','Medium','Low','Info','Unknown'];
  const data   = [counts.critical, counts.high, counts.medium, counts.low, counts.info, counts.unknown];
  const colors = ['#ff4757','#ff8c42','#ffc22a','#00bcd4','#78909c','#546e7a'];
  const chart = new Chart(canvas, {
    type: 'doughnut',
    data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: '#0b1628', borderWidth: 3 }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: { position: 'right', labels: { color: '#c4d4eb', font: { family: "'JetBrains Mono'", size: 11 }, padding: 14 } },
        tooltip: { callbacks: { label: ctx => ` ${ctx.label}: ${ctx.parsed}` } }
      },
      cutout: '62%',
    }
  });
  S.charts.push(chart);
}

function drawSourcesChart(toolCounts) {
  const canvas = document.getElementById('chart-sources');
  if (!canvas) return;
  const entries = Object.entries(toolCounts).filter(([,v])=>v>0).sort((a,b)=>b[1]-a[1]);
  if (!entries.length) return;
  const labels = entries.map(([k]) => k);
  const data   = entries.map(([,v]) => v);
  const chart = new Chart(canvas, {
    type: 'bar',
    data: { labels, datasets: [{ label: 'Subdomains', data, backgroundColor: 'rgba(0,232,122,.5)', borderColor: '#00e87a', borderWidth: 1, borderRadius: 4 }] },
    options: {
      indexAxis: 'y', responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: '#1a2e4a' }, ticks: { color: '#60789a', font: { family: "'JetBrains Mono'", size: 10 } } },
        y: { grid: { color: 'transparent' }, ticks: { color: '#c4d4eb', font: { family: "'JetBrains Mono'", size: 11 } } }
      }
    }
  });
  S.charts.push(chart);
}

/* ════════════════════════════════════════════════════════════
   MODAL
   ════════════════════════════════════════════════════════════ */
function setupModal() {
  document.getElementById('modal-close').addEventListener('click', closeModal);
  document.getElementById('modal-overlay').addEventListener('click', e => {
    if (e.target === document.getElementById('modal-overlay')) closeModal();
  });
  document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
}

function showModal(title, html) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').style.display = 'flex';
}
function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
}

window.showVulnDetail = (idx) => {
  const d = S.data[S.currentDomain];
  const allFindings = [...d.nucleiFindings].sort((a,b) => sevOrder(a)-sevOrder(b));
  const f = allFindings[idx];
  if (!f) return;
  const sev = (f.info?.severity || f.severity || 'unknown').toLowerCase();
  showModal(`${f.info?.name || f['template-id'] || 'Finding'}`, `
    <div class="modal-section">
      <div class="modal-section-label">Severity</div>
      ${sevBadge(sev)}
    </div>
    <div class="modal-section">
      <div class="modal-section-label">Template</div>
      <code>${esc(f['template-id']||'—')}</code>
    </div>
    ${f.info?.description ? `<div class="modal-section"><div class="modal-section-label">Description</div><p style="font-size:13px">${esc(f.info.description)}</p></div>` : ''}
    ${f.info?.tags ? `<div class="modal-section"><div class="modal-section-label">Tags</div>${f.info.tags.split(',').map(t=>`<span class="badge badge-tool">${esc(t.trim())}</span> `).join('')}</div>` : ''}
    <div class="modal-section">
      <div class="modal-section-label">Matched At</div>
      <code>${esc(f['matched-at']||f.host||'—')}</code>
    </div>
    ${f.request ? `<div class="modal-section"><div class="modal-section-label">Request</div><pre class="pre-block" style="max-height:180px">${esc(f.request.slice(0,1500))}</pre></div>` : ''}
    ${f.response ? `<div class="modal-section"><div class="modal-section-label">Response Snippet</div><pre class="pre-block" style="max-height:180px">${esc(f.response.slice(0,1500))}</pre></div>` : ''}
    ${f['curl-command'] ? `<div class="modal-section"><div class="modal-section-label">Curl</div><pre class="pre-block">${esc(f['curl-command'])}</pre></div>` : ''}
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="copyToClip(${JSON.stringify(JSON.stringify(f,null,2))})">Copy JSON</button>
      ${f['matched-at'] ? `<button class="btn btn-outline btn-sm" onclick="window.open('${esc(f['matched-at'])}','_blank')">Open URL ↗</button>` : ''}
    </div>
  `);
};

window.showHttpxDetail = (r) => {
  if (typeof r === 'string') { try { r = JSON.parse(r); } catch { return; } }
  const techs = r.tech || r.technologies || r.technology || [];
  const sc = r['status-code'] || r.status_code;
  showModal(`HTTP Detail: ${r.url||'?'}`, `
    <div class="modal-section"><div class="modal-section-label">URL</div><a href="${esc(r.url||'')}" target="_blank">${esc(r.url||'')}</a></div>
    <div class="two-col">
      <div class="modal-section"><div class="modal-section-label">Status</div>${sc ? statusBadge(sc) : '—'}</div>
      <div class="modal-section"><div class="modal-section-label">Title</div>${esc(r.title||'—')}</div>
    </div>
    <div class="two-col">
      <div class="modal-section"><div class="modal-section-label">Server</div><code>${esc(r.webserver||r['web-server']||'—')}</code></div>
      <div class="modal-section"><div class="modal-section-label">IP</div><code>${esc(r.host||r.ip||'—')}</code></div>
    </div>
    ${techs.length ? `<div class="modal-section"><div class="modal-section-label">Technologies</div><div class="tech-pills">${(Array.isArray(techs)?techs:[techs]).map(t=>`<span class="tech-pill">${esc(normalizeTech(t))}</span>`).join('')}</div></div>` : ''}
    <div class="modal-section"><div class="modal-section-label">Full JSON</div><pre class="pre-block">${esc(JSON.stringify(r,null,2))}</pre></div>
    <div class="modal-actions">
      <button class="btn btn-outline btn-sm" onclick="copyToClip('${esc(r.url||'')}')">Copy URL</button>
      <button class="btn btn-outline btn-sm" onclick="copyToClip(${JSON.stringify(JSON.stringify(r,null,2))})">Copy JSON</button>
    </div>
  `);
};

window.showScreenshot = (src, label) => {
  showModal(label, `
    <img class="lightbox-img" src="${esc(src)}" alt="${esc(label)}" />
    <div class="modal-actions">
      <a href="${esc(src)}" download="${esc(label)}.jpg" class="btn btn-outline btn-sm">↓ Download</a>
      <button class="btn btn-outline btn-sm" onclick="window.open('${esc(src)}','_blank')">Open Full ↗</button>
    </div>
  `);
};

/* ════════════════════════════════════════════════════════════
   UTILITIES
   ════════════════════════════════════════════════════════════ */
async function listDir(url) {
  try {
    const res = await fetch(url);
    if (!res.ok) return [];
    const html = await res.text();
    const d = document.createElement('div'); d.innerHTML = html;
    return [...d.querySelectorAll('a')].map(a => a.getAttribute('href'))
      .filter(h => h && !h.startsWith('?') && !h.startsWith('#') && h !== '../');
  } catch { return []; }
}

async function fetchText(url) {
  try { const r = await fetch(url); return r.ok ? await r.text() : ''; }
  catch { return ''; }
}

async function fetchLines(url) {
  const t = await fetchText(url);
  return t ? t.split('\n').map(l=>l.trim()).filter(Boolean) : [];
}

function extractHost(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

function normalizeTech(t) {
  if (!t) return '';
  if (typeof t === 'object') return t.name || JSON.stringify(t);
  return String(t).split(':')[0].trim();
}

function shortHost(url) {
  try { return new URL(url).hostname; } catch { return (url||'').slice(0,40); }
}

function decodeScreenshotFilename(fname) {
  return fname.replace(/^https---/, 'https://').replace(/^http---/, 'http://')
    .replace(/---(\d+)\.(jpe?g|png|webp)$/, ':$1').replace(/---/g, '/');
}

function sevOrder(f) {
  const m = { critical:0, high:1, medium:2, low:3, info:4, unknown:5 };
  return m[(f.info?.severity||f.severity||'unknown').toLowerCase()] ?? 5;
}

function getCritHigh(c) {
  const n = (c.critical||0) + (c.high||0);
  return n ? `${n} critical/high` : 'no high severity';
}

function portService(p) {
  const known = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',1433:'MSSQL',3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',27017:'MongoDB'};
  return known[p] || '—';
}

function sortRows(rows, table, defaultKey, defaultDir, fallback) {
  const key = S.sortCol[table] || defaultKey;
  const dir = S.sortDir[table + key] || defaultDir;
  return [...rows].sort((a,b) => {
    const av = a[key] ?? '', bv = b[key] ?? '';
    const cmp = typeof av === 'number' ? av - bv : String(av).localeCompare(String(bv));
    return dir === 'asc' ? cmp : -cmp;
  });
}

/* ── Components ─────────────────────────────────────────── */
function statCard(label, value, sub, cls) {
  return `<div class="stat-card ${cls||''}">
    <div class="stat-label">${esc(label)}</div>
    <div class="stat-value ${cls==='accent'?'green':cls==='danger'?'red':''}">${typeof value==='number'?value.toLocaleString():esc(value)}</div>
    ${sub ? `<div class="stat-sub">${esc(sub)}</div>` : ''}
  </div>`;
}

function sevBadge(sev) {
  const s = (sev||'unknown').toLowerCase();
  return `<span class="badge badge-${s}">${s}</span>`;
}

function statusBadge(code) {
  const c = parseInt(code);
  const cls = c >= 500 ? 'badge-5xx' : c >= 400 ? 'badge-4xx' : c >= 300 ? 'badge-3xx' : 'badge-2xx';
  return `<span class="badge ${cls}">${code}</span>`;
}

function paginator(tab, total, pageSize = PAGE_SIZE) {
  const pages = Math.ceil(total / pageSize);
  const page  = S.pages[tab] || 0;
  if (pages <= 1) return '';
  return `<div class="pagination">
    <button class="page-btn" data-page-tab="${tab}" data-dir="prev" ${page===0?'disabled':''}>‹ Prev</button>
    <span class="page-info">Page ${page+1} of ${pages} (${total.toLocaleString()} total)</span>
    <button class="page-btn" data-page-tab="${tab}" data-dir="next" ${page>=pages-1?'disabled':''}>Next ›</button>
  </div>`;
}

function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#039;');
}

/* ── Export ─────────────────────────────────────────────── */
function exportData() {
  const d = S.data[S.currentDomain];
  if (!d) return;
  const out = {
    domain: d.domain, generated: new Date().toISOString(),
    subdomains: [...d.subMap.entries()].map(([h,v]) => ({ host:h, tools:[...v.tools], alive:v.isAlive })),
    asnRanges: d.asnRanges,
    httpResults: d.httpxResults,
    naabuPorts: d.naabuPorts,
    nucleiFindings: d.nucleiFindings,
    techInventory: [...d.techInventory.entries()].map(([t,hosts]) => ({ tech:t, hosts:[...hosts] })),
    totalUrls: d.allUrls.length,
  };
  const blob = new Blob([JSON.stringify(out,null,2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = `${d.domain}-recon.json`;
  a.click(); URL.revokeObjectURL(a.href);
  toast('Exported!');
}

window.exportList = (lines, filename) => {
  const blob = new Blob([lines.filter(Boolean).join('\n')], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = filename || 'export.txt';
  a.click(); URL.revokeObjectURL(a.href);
  toast(`Exported ${lines.length} lines`);
};

window.copyToClip = (text) => {
  navigator.clipboard.writeText(text).then(() => toast('Copied!')).catch(() => {});
};

function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg; el.style.display = 'block';
  setTimeout(() => { el.style.display = 'none'; }, 2200);
}
