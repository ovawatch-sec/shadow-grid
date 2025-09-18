// Global state
const state = {
    domains: [],
    currentDomain: null,
    domainData: {},
    searchTerm: '',
    filters: {
        alive: 'all',
        tool: 'all'
    }
};

// Use relative path to output directory
const base_directory = '../output/';

// DOM Elements
const domainsListEl = document.getElementById('domains-list');
const domainDataEl = document.getElementById('domain-data');
const globalSearchEl = document.getElementById('global-search');
const nucleiModalEl = document.getElementById('nuclei-modal');
const screenshotModalEl = document.getElementById('screenshot-modal');

// Initialize the application
async function init() {
    try {
        await loadDomains();
        setupEventListeners();
    } catch (error) {
        console.warn('Failed to initialize app:', error);
        domainsListEl.innerHTML = '<div class="empty-state">Failed to load domains. Make sure you\'re serving from the parent directory of output/</div>';
    }
}

// Set up event listeners
function setupEventListeners() {
    globalSearchEl.addEventListener('input', (e) => {
        state.searchTerm = e.target.value.toLowerCase();
        if (state.currentDomain) {
            renderDomainData(state.currentDomain);
        }
    });
    
    // Close modals when clicking the close button
    document.querySelectorAll('.close').forEach(closeBtn => {
        closeBtn.addEventListener('click', () => {
            nucleiModalEl.style.display = 'none';
            screenshotModalEl.style.display = 'none';
        });
    });
    
    // Close modals when clicking outside
    window.addEventListener('click', (e) => {
        if (e.target === nucleiModalEl) {
            nucleiModalEl.style.display = 'none';
        }
        if (e.target === screenshotModalEl) {
            screenshotModalEl.style.display = 'none';
        }
    });
}

// Load domains from the output directory
async function loadDomains() {
    try {
        // Try to fetch the directory listing
        const dirs = await listDirectory(base_directory);
        
        const domains = dirs
            .filter(d => d.endsWith("/"))
            .map(d => d.replace(/\/$/, ""))
            .filter(domain => domain && domain !== "../");
        
        state.domains = domains;
        renderDomainsList();
    } catch (error) {
        console.log('Error loading domains:', error);
        // Fallback: try to load from a hardcoded list if directory listing fails
        state.domains = ['ovawatch.co.za', 'powerfleet.com'];
        renderDomainsList();
    }
}

// Parse http.server directory listing HTML
async function listDirectory(path) {
    try {
        const res = await fetch(path);
        if (!res.ok) return [];
        const html = await res.text();
        const div = document.createElement("div");
        div.innerHTML = html;
        const links = [...div.querySelectorAll("a")].map(a => a.getAttribute("href"));
        // Filter out parent link, query params, etc.
        return links.filter(href =>
            href &&
            href !== "../" &&
            !href.startsWith("?") &&
            !href.startsWith("#")
        );
    } catch {
        return [];
    }
}

// Render the domains list
function renderDomainsList() {
    if (state.domains.length === 0) {
        domainsListEl.innerHTML = '<div class="empty-state">No domains found</div>';
        return;
    }
    
    domainsListEl.innerHTML = state.domains.map(domain => `
        <div class="domain-item" data-domain="${domain}">${domain}</div>
    `).join('');
    
    // Add click event listeners to domain items
    document.querySelectorAll('.domain-item').forEach(item => {
        item.addEventListener('click', async () => {
            const domain = item.getAttribute('data-domain');
            document.querySelectorAll('.domain-item').forEach(i => i.classList.remove('active'));
            item.classList.add('active');
            await loadDomainData(domain);
        });
    });
}

// Load data for a specific domain
async function loadDomainData(domain) {
    state.currentDomain = domain;
    domainDataEl.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    
    try {
        // Reset filters
        state.searchTerm = '';
        globalSearchEl.value = '';
        state.filters.alive = 'all';
        
        // Load all data files in parallel
        const [
            amassData,
            assetfinderData,
            subfinderData,
            sublist3rData,
            crtshData,
            allSubsData,
            aliveSubsData,
            aliveUrlsData,
            amassRawData,
            nucleiData,
            waybackData,
            screenshots,
            fuzzingData
        ] = await Promise.allSettled([
            fetchTextFile(`${base_directory}${domain}/amass.txt`),
            fetchTextFile(`${base_directory}${domain}/assetfinder.txt`),
            fetchTextFile(`${base_directory}${domain}/subfinder.txt`),
            fetchTextFile(`${base_directory}${domain}/sublist3r.txt`),
            fetchTextFile(`${base_directory}${domain}/crt.sh.txt`),
            fetchTextFile(`${base_directory}${domain}/all_subs.txt`),
            fetchTextFile(`${base_directory}${domain}/alive_subs.txt`),
            fetchTextFile(`${base_directory}${domain}/alive_urls.txt`),
            fetchTextFile(`${base_directory}${domain}/raw/amass_raw.txt`),
            fetchNucleiData(`${base_directory}${domain}/raw/nuclei_results.json`),
            fetchWaybackData(domain),
            fetchScreenshots(domain),
            fetchFuzzingData(domain)
        ]);
        
        // Process the data
        const subdomains = processSubdomains(
            domain, amassData, assetfinderData, subfinderData, 
            sublist3rData, crtshData, allSubsData
        );
        
        const aliveHosts = processAliveHosts(aliveSubsData, aliveUrlsData);
        
        // Process amass raw data
        const amassRawRecords = amassRawData.status === 'fulfilled' ? 
            processAmassRawData(amassRawData.value, domain) : [];
        
        // Store the data in state
        state.domainData[domain] = {
            subdomains,
            aliveHosts,
            nucleiFindings: nucleiData.status === 'fulfilled' ? nucleiData.value : [],
            waybackUrls: waybackData.status === 'fulfilled' ? waybackData.value : {},
            screenshots: screenshots.status === 'fulfilled' ? screenshots.value : [],
            amassRawRecords,
            fuzzingResults: fuzzingData.status === 'fulfilled' ? fuzzingData.value : {}
        };
        
        renderDomainData(domain);
    } catch (error) {
        console.warn(`Error loading data for ${domain}:`, error);
        domainDataEl.innerHTML = `
            <div class="empty-state">
                Failed to load data for ${domain}.<br>
                Check the console for details.
            </div>
        `;
    }
}

// Fetch a text file and return lines as array
async function fetchTextFile(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) return [];
        const text = await response.text();
        return text.split('\n')
            .map(line => line.trim())
            .filter(line => line.length > 0);
    } catch (error) {
        console.warn(`Failed to fetch ${url}:`, error);
        return [];
    }
}

// Fetch and parse nuclei data (supports both JSON array and NDJSON)
async function fetchNucleiData(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) return [];
        const text = await response.text();
        
        // Try to parse as JSON array first
        try {
            return JSON.parse(text);
        } catch (e) {
            // If that fails, try to parse as NDJSON (newline-delimited JSON)
            return text.split('\n')
                .filter(line => line.trim().length > 0)
                .map(line => {
                    try {
                        return JSON.parse(line);
                    } catch (parseError) {
                        console.warn('Failed to parse nuclei line:', line, parseError);
                        return null;
                    }
                })
                .filter(item => item !== null);
        }
    } catch (error) {
        console.warn(`Failed to fetch nuclei data from ${url}:`, error);
        return [];
    }
}

// Fetch wayback data for a domain
async function fetchWaybackData(domain) {
    try {
        // Try to get list of wayback files
        const response = await fetch(`${base_directory}${domain}/waybackurls/`);
        if (!response.ok) return {};
        
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        const links = Array.from(doc.querySelectorAll('a'));
        const waybackFiles = links
            .map(link => link.href)
            .filter(href => href.endsWith('.txt') && !href.includes('../'))
            .map(href => href.replace(/.*\//, ''));
        
        // Fetch all wayback files
        const waybackData = {};
        for (const file of waybackFiles) {
            const subdomain = file.replace('_wayback_urls.txt', '');
            const urls = await fetchTextFile(`${base_directory}${domain}/waybackurls/${file}`);
            waybackData[subdomain] = urls;
        }
        
        return waybackData;
    } catch (error) {
        console.warn(`Failed to fetch wayback data for ${domain}:`, error);
        return {};
    }
}

// Fetch screenshots for a domain
async function fetchScreenshots(domain) {
    try {
        // Try to get list of screenshot files
        const response = await fetch(`${base_directory}${domain}/screenshots/`);
        if (!response.ok) return [];
        
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        const links = Array.from(doc.querySelectorAll('a'));
        return links
            .map(link => link.href)
            .filter(href => /\.(jpe?g|png|gif|webp)$/i.test(href) && !href.includes('../'))
            .map(href => href.replace(/.*\//, ''));
    } catch (error) {
        console.warn(`Failed to fetch screenshots for ${domain}:`, error);
        return [];
    }
}

// Fetch fuzzing data for a domain
async function fetchFuzzingData(domain) {
    try {
        // Try to get list of fuzzing files
        const response = await fetch(`${base_directory}${domain}/raw/`);
        if (!response.ok) return {};
        
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');
        
        const links = Array.from(doc.querySelectorAll('a'));
        const fuzzFiles = links
            .map(link => link.href)
            .filter(href => href.endsWith('_fuzz.json') && !href.includes('../'))
            .map(href => href.replace(/.*\//, ''));
        
        // Fetch all fuzzing files
        const fuzzingData = {};
        for (const file of fuzzFiles) {
            const subdomain = file.replace('_fuzz.json', '');
            const data = await fetchFuzzingFile(`${base_directory}${domain}/raw/${file}`);
            fuzzingData[subdomain] = data;
        }
        
        return fuzzingData;
    } catch (error) {
        console.warn(`Failed to fetch fuzzing data for ${domain}:`, error);
        return {};
    }
}

// Fetch and parse a fuzzing file
async function fetchFuzzingFile(url) {
    try {
        const response = await fetch(url);
        if (!response.ok) return [];
        const text = await response.text();
        
        // Parse NDJSON format
        return text.split('\n')
            .filter(line => line.trim().length > 0)
            .map(line => {
                try {
                    return JSON.parse(line);
                } catch (parseError) {
                    console.warn('Failed to parse fuzzing line:', line, parseError);
                    return null;
                }
            })
            .filter(item => item !== null && item.kind !== 'configuration');
    } catch (error) {
        console.warn(`Failed to fetch fuzzing file ${url}:`, error);
        return [];
    }
}

// Process subdomains from various sources
function processSubdomains(domain, amassData, assetfinderData, subfinderData, sublist3rData, crtshData, allSubsData) {
    const subdomains = new Map();
    
    // Process standard text files
    const processFile = (data, tool) => {
        if (data.status !== 'fulfilled') return;
        
        data.value.forEach(hostname => {
            if (!hostname || !isSubdomainOf(hostname, domain)) return;
            
            if (!subdomains.has(hostname)) {
                subdomains.set(hostname, {
                    hostname,
                    tools: new Set(),
                    isAlive: false
                });
            }
            
            subdomains.get(hostname).tools.add(tool);
        });
    };
    
    processFile(amassData, 'amass');
    processFile(assetfinderData, 'assetfinder');
    processFile(subfinderData, 'subfinder');
    processFile(sublist3rData, 'sublist3r');
    processFile(crtshData, 'crt.sh');
    processFile(allSubsData, 'all_subs');
    
    // Convert Map to Array and sort
    return Array.from(subdomains.values())
        .map(sub => ({
            ...sub,
            tools: Array.from(sub.tools),
            toolCount: sub.tools.size
        }))
        .sort((a, b) => a.hostname.localeCompare(b.hostname));
}

// Process amass raw data into structured records
function processAmassRawData(lines, domain) {
    const records = [];
    
    lines.forEach(line => {
        if (!line) return;
        
        // Parse the relationship format: source --> type --> target
        const parts = line.split('-->').map(part => part.trim());
        if (parts.length !== 3) return;
        
        const [source, type, target] = parts;
        
        // Extract clean values (remove metadata in parentheses)
        const cleanSource = source.replace(/\s*\(.*?\)\s*$/, '');
        const cleanTarget = target.replace(/\s*\(.*?\)\s*$/, '');
        const cleanType = type.replace(/\s*\(.*?\)\s*$/, '');
        
        records.push({
            source: cleanSource,
            type: cleanType,
            target: cleanTarget,
            fullLine: line
        });
    });
    
    return records;
}

// Check if a hostname is a subdomain of the given domain
function isSubdomainOf(hostname, domain) {
    if (hostname === domain) return true;
    return hostname.endsWith('.' + domain);
}

// Process alive hosts
function processAliveHosts(aliveSubsData, aliveUrlsData) {
    const aliveHosts = new Set();
    
    // Process alive_subs.txt
    if (aliveSubsData.status === 'fulfilled') {
        aliveSubsData.value.forEach(hostname => {
            if (hostname) aliveHosts.add(hostname);
        });
    }
    
    // Process alive_urls.txt - extract hostnames from URLs
    if (aliveUrlsData.status === 'fulfilled') {
        aliveUrlsData.value.forEach(url => {
            try {
                const hostname = new URL(url.startsWith('http') ? url : `http://${url}`).hostname;
                if (hostname) aliveHosts.add(hostname);
            } catch (e) {
                // If URL parsing fails, try to extract what looks like a hostname
                const match = url.match(/[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/);
                if (match) aliveHosts.add(match[0]);
            }
        });
    }
    
    return Array.from(aliveHosts);
}

// Render domain data
function renderDomainData(domain) {
    const data = state.domainData[domain];
    if (!data) return;
    
    // Mark alive subdomains
    const subdomains = data.subdomains.map(sub => ({
        ...sub,
        isAlive: data.aliveHosts.includes(sub.hostname)
    }));
    
    // Filter subdomains based on search term and status filter
    let filteredSubdomains = state.searchTerm 
        ? subdomains.filter(sub => sub.hostname.toLowerCase().includes(state.searchTerm))
        : subdomains;
    
    // Apply status filter
    if (state.filters.alive !== 'all') {
        filteredSubdomains = filteredSubdomains.filter(sub => 
            state.filters.alive === 'alive' ? sub.isAlive : !sub.isAlive
        );
    }
    
    // Filter nuclei findings based on search term
    const filteredNuclei = state.searchTerm
        ? data.nucleiFindings.filter(finding => 
            (finding['template-id'] || '').toLowerCase().includes(state.searchTerm) ||
            (finding.info?.name || '').toLowerCase().includes(state.searchTerm) ||
            (finding.host || '').toLowerCase().includes(state.searchTerm) ||
            (finding['matched-at'] || '').toLowerCase().includes(state.searchTerm))
        : data.nucleiFindings;
    
    // Count findings by severity
    const severityCounts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        unknown: 0
    };
    
    data.nucleiFindings.forEach(finding => {
        const severity = finding.severity || finding.info?.severity || 'unknown';
        severityCounts[severity] = (severityCounts[severity] || 0) + 1;
    });
    
    // Count wayback URLs
    let waybackUrlCount = 0;
    for (const sub in data.waybackUrls) {
        waybackUrlCount += data.waybackUrls[sub].length;
    }
    
    // Render the domain data
    domainDataEl.innerHTML = `
        <div class="domain-header">
            <h2>${domain}</h2>
            <button class="button" id="export-btn">Export Data</button>
        </div>
        
        <div class="summary-cards">
            <div class="card">
                <h3>Subdomains</h3>
                <div class="value">${subdomains.length}</div>
            </div>
            <div class="card">
                <h3>Alive Hosts</h3>
                <div class="value">${data.aliveHosts.length}</div>
            </div>
            <div class="card">
                <h3>Nuclei Findings</h3>
                <div class="value">${data.nucleiFindings.length}</div>
            </div>
            <div class="card">
                <h3>Screenshots</h3>
                <div class="value">${data.screenshots.length}</div>
            </div>
            <div class="card">
                <h3>Wayback URLs</h3>
                <div class="value">${waybackUrlCount}</div>
            </div>
            <div class="card">
                <h3>Amass Records</h3>
                <div class="value">${data.amassRawRecords.length}</div>
            </div>
            <div class="card">
                <h3>Fuzzing Results</h3>
                <div class="value">${Object.keys(data.fuzzingResults).length}</div>
            </div>
        </div>
        
        <div class="severity-cards">
            <div class="severity-card critical">
                <h3>Critical</h3>
                <div class="value">${severityCounts.critical}</div>
            </div>
            <div class="severity-card high">
                <h3>High</h3>
                <div class="value">${severityCounts.high}</div>
            </div>
            <div class="severity-card medium">
                <h3>Medium</h3>
                <div class="value">${severityCounts.medium}</div>
            </div>
            <div class="severity-card low">
                <h3>Low</h3>
                <div class="value">${severityCounts.low}</div>
            </div>
            <div class="severity-card info">
                <h3>Info</h3>
                <div class="value">${severityCounts.info}</div>
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header" id="subdomains-header">
                <h2>Subdomains (${filteredSubdomains.length})</h2>
                <div>
                    <select id="status-filter" class="filter-select">
                        <option value="all">All Status</option>
                        <option value="alive">Alive Only</option>
                        <option value="dead">Dead Only</option>
                    </select>
                    <span>▼</span>
                </div>
            </div>
            <div class="panel-content" id="subdomains-content">
                ${renderSubdomainsTable(filteredSubdomains, data)}
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header" id="amass-raw-header">
                <h2>Amass Raw Data (${data.amassRawRecords.length})</h2>
                <span>▼</span>
            </div>
            <div class="panel-content" id="amass-raw-content">
                ${renderAmassRawTable(data.amassRawRecords)}
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header" id="fuzzing-header">
                <h2>Fuzzing Results (${Object.keys(data.fuzzingResults).length})</h2>
                <span>▼</span>
            </div>
            <div class="panel-content" id="fuzzing-content">
                ${renderFuzzingResults(data.fuzzingResults)}
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header" id="nuclei-header">
                <h2>Nuclei Findings (${filteredNuclei.length})</h2>
                <span>▼</span>
            </div>
            <div class="panel-content" id="nuclei-content">
                ${renderNucleiFindings(filteredNuclei)}
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header" id="wayback-header">
                <h2>Wayback URLs</h2>
                <span>▼</span>
            </div>
            <div class="panel-content" id="wayback-content">
                ${renderWaybackUrls(data.waybackUrls)}
            </div>
        </div>
        
        <div class="panel">
            <div class="panel-header" id="screenshots-header">
                <h2>Screenshots (${data.screenshots.length})</h2>
                <span>▼</span>
            </div>
            <div class="panel-content" id="screenshots-content">
                ${renderScreenshots(data.screenshots, domain)}
            </div>
        </div>
    `;
    
    // Set the current filter value
    document.getElementById('status-filter').value = state.filters.alive;
    
    // Add event listeners for collapsible panels
    document.getElementById('subdomains-header').addEventListener('click', () => {
        togglePanel('subdomains-content');
    });
    
    document.getElementById('amass-raw-header').addEventListener('click', () => {
        togglePanel('amass-raw-content');
    });
    
    document.getElementById('fuzzing-header').addEventListener('click', () => {
        togglePanel('fuzzing-content');
    });
    
    document.getElementById('nuclei-header').addEventListener('click', () => {
        togglePanel('nuclei-content');
    });
    
    document.getElementById('wayback-header').addEventListener('click', () => {
        togglePanel('wayback-content');
    });
    
    document.getElementById('screenshots-header').addEventListener('click', () => {
        togglePanel('screenshots-content');
    });
    
    // Add event listener for status filter
    document.getElementById('status-filter').addEventListener('change', (e) => {
        state.filters.alive = e.target.value;
        renderDomainData(domain);
    });
    
    // Add event listener for export button
    document.getElementById('export-btn').addEventListener('click', () => {
        exportDomainData(domain, data);
    });
    
    // Add event listeners for nuclei findings
    document.querySelectorAll('.nuclei-detail-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const findingIndex = e.target.getAttribute('data-index');
            showNucleiDetail(data.nucleiFindings[findingIndex]);
        });
    });
    
    // Add event listeners for screenshot thumbnails
    document.querySelectorAll('.screenshot-thumbnail').forEach(img => {
        img.addEventListener('click', (e) => {
            const src = e.target.getAttribute('data-full-src');
            const hostname = e.target.getAttribute('data-hostname');
            showScreenshot(src, hostname);
        });
    });
}

// Toggle panel visibility
function togglePanel(panelId) {
    const panel = document.getElementById(panelId);
    panel.classList.toggle('collapsed');
}

// Render subdomains table
function renderSubdomainsTable(subdomains, data) {
    if (subdomains.length === 0) {
        return '<div class="empty-state">No subdomains found</div>';
    }
    
    return `
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Hostname</th>
                        <th>Discovered By</th>
                        <th>Status</th>
                        <th>Screenshot</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${subdomains.map((sub, index) => `
                        <tr>
                            <td>${sub.hostname}</td>
                            <td>${sub.tools.join(', ')}</td>
                            <td><span class="badge ${sub.isAlive ? 'alive' : 'dead'}">${sub.isAlive ? 'Alive' : 'Dead'}</span></td>
                            <td>
                                ${getScreenshotThumbnail(sub.hostname, data.screenshots, state.currentDomain)}
                            </td>
                            <td>
                                <button class="button" onclick="window.open('http://${sub.hostname}', '_blank')">Open</button>
                                <button class="button" data-hostname="${sub.hostname}" onclick="copyToClipboard('${sub.hostname}')">Copy</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Render amass raw data table (grouped by type)
function renderAmassRawTable(records) {
    if (records.length === 0) {
        return '<div class="empty-state">No amass raw data found</div>';
    }
    
    // Group records by type
    const groupedRecords = {};
    records.forEach(record => {
        if (!groupedRecords[record.type]) {
            groupedRecords[record.type] = [];
        }
        groupedRecords[record.type].push(record);
    });
    
    return Object.entries(groupedRecords).map(([type, typeRecords]) => `
        <h3>${type} Records (${typeRecords.length})</h3>
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Source</th>
                        <th>Target</th>
                    </tr>
                </thead>
                <tbody>
                    ${typeRecords.map(record => `
                        <tr>
                            <td>${record.source}</td>
                            <td>${record.target}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `).join('');
}

// Render fuzzing results
function renderFuzzingResults(fuzzingResults) {
    const subdomains = Object.keys(fuzzingResults);
    if (subdomains.length === 0) {
        return '<div class="empty-state">No fuzzing results found</div>';
    }
    
    return subdomains.map(subdomain => `
        <div class="fuzzing-group">
            <h3>${subdomain}</h3>
            <div class="table-container">
                <table>
                    <thead>
                        <tr>
                            <th>Status</th>
                            <th>Method</th>
                            <th>URL</th>
                            <th>Lines</th>
                            <th>Words</th>
                            <th>Chars</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${fuzzingResults[subdomain].map(result => `
                            <tr>
                                <td><span class="badge ${result.status >= 200 && result.status < 300 ? 'alive' : 'dead'}">${result.status}</span></td>
                                <td>${result.method || 'GET'}</td>
                                <td><a href="${result.url}" target="_blank">${result.url}</a></td>
                                <td>${result.lines || 'N/A'}</td>
                                <td>${result.words || 'N/A'}</td>
                                <td>${result.chars || 'N/A'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </div>
    `).join('');
}

// Get screenshot thumbnail for a hostname
function getScreenshotThumbnail(hostname, screenshots, domain) {
    // Try to find a matching screenshot
    const screenshotFile = screenshots.find(file => {
        // Convert filename to hostname format for comparison
        const fileHostname = file
            .replace(/^https---/, '')
            .replace(/^http---/, '')
            .replace(/-(\d+)\.(jpe?g|png|gif|webp)$/i, '')
            .replace(/-/g, '.');
        
        return fileHostname === hostname;
    });
    
    if (screenshotFile) {
        return `<img class="thumbnail screenshot-thumbnail" 
                    src="${base_directory}${domain}/screenshots/${screenshotFile}" 
                    data-full-src="${base_directory}${domain}/screenshots/${screenshotFile}"
                    data-hostname="${hostname}"
                    alt="${hostname}">`;
    }
    
    return '<span class="badge">No screenshot</span>';
}

// Render nuclei findings
function renderNucleiFindings(findings) {
    if (findings.length === 0) {
        return '<div class="empty-state">No nuclei findings</div>';
    }
    
    return `
        <div class="table-container">
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Template</th>
                        <th>Name</th>
                        <th>Host</th>
                        <th>Snippet</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    ${findings.map((finding, index) => {
                        const severity = finding.severity || finding.info?.severity || 'unknown';
                        const templateId = finding['template-id'] || 'N/A';
                        const name = finding.info?.name || 'N/A';
                        const host = finding.host || finding['matched-at'] || 'N/A';
                        const snippet = (finding.request || finding.response || '').substring(0, 200);
                        
                        return `
                            <tr>
                                <td><span class="badge ${severity}">${severity}</span></td>
                                <td>${templateId}</td>
                                <td>${name}</td>
                                <td>${host}</td>
                                <td>${snippet}...</td>
                                <td>
                                    <button class="button nuclei-detail-btn" data-index="${index}">Details</button>
                                </td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Render wayback URLs
function renderWaybackUrls(waybackData) {
    const subdomains = Object.keys(waybackData);
    if (subdomains.length === 0) {
        return '<div class="empty-state">No wayback URLs found</div>';
    }
    
    return `
        <div class="wayback-list">
            ${subdomains.map(sub => `
                <div class="wayback-group">
                    <h3>${sub}</h3>
                    ${waybackData[sub].map(url => `
                        <div class="wayback-url">
                            <a href="${url}" target="_blank">${url}</a>
                        </div>
                    `).join('')}
                </div>
            `).join('')}
        </div>
    `;
}

// Render screenshots
function renderScreenshots(screenshots, domain) {
    if (screenshots.length === 0) {
        return '<div class="empty-state">No screenshots found</div>';
    }
    
    return `
        <div class="screenshots-grid">
            ${screenshots.map(file => {
                // Extract hostname from filename
                const hostname = file
                    .replace(/^https---/, '')
                    .replace(/^http---/, '')
                    .replace(/-(\d+)\.(jpe?g|png|gif|webp)$/i, '')
                    .replace(/-/g, '.');
                
                return `
                    <div class="screenshot-item">
                        <img class="screenshot-thumbnail" 
                             src="${base_directory}${domain}/screenshots/${file}" 
                             data-full-src="${base_directory}${domain}/screenshots/${file}"
                             data-hostname="${hostname}"
                             alt="${hostname}">
                        <div class="hostname">${hostname}</div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
}

// Show nuclei finding detail
function showNucleiDetail(finding) {
    const contentEl = document.getElementById('nuclei-detail-content');
    
    contentEl.innerHTML = `
        <div class="severity-badge">
            <span class="badge ${finding.severity || finding.info?.severity || 'unknown'}">
                ${finding.severity || finding.info?.severity || 'unknown'}
            </span>
        </div>
        
        <h3>${finding.info?.name || 'No name'}</h3>
        <p><strong>Template ID:</strong> ${finding['template-id'] || 'N/A'}</p>
        <p><strong>Host:</strong> ${finding.host || 'N/A'}</p>
        <p><strong>Matched at:</strong> ${finding['matched-at'] || 'N/A'}</p>
        <p><strong>Timestamp:</strong> ${finding.timestamp || 'N/A'}</p>
        
        <h4>Request</h4>
        <div class="json-view">${escapeHtml(finding.request || 'No request data')}</div>
        
        <h4>Response</h4>
        <div class="json-view">${escapeHtml(finding.response || 'No response data')}</div>
        
        <h4>Notes</h4>
        <textarea class="textarea" placeholder="Add your notes here..."></textarea>
        
        <div style="margin-top: 1rem;">
            <button class="button" onclick="copyToClipboard('${escapeHtml(JSON.stringify(finding, null, 2))}')">Copy JSON</button>
            <button class="button" onclick="copyToClipboard('${escapeHtml(finding.request || '')}')">Copy Request</button>
            <button class="button" onclick="copyToClipboard('${escapeHtml(finding.response || '')}')">Copy Response</button>
        </div>
    `;
    
    nucleiModalEl.style.display = 'block';
}

// Show screenshot in lightbox
function showScreenshot(src, hostname) {
    const titleEl = document.getElementById('screenshot-title');
    const contentEl = document.getElementById('screenshot-content');
    
    titleEl.textContent = hostname;
    contentEl.innerHTML = `
        <img src="${src}" class="full-screenshot" alt="${hostname}">
        <div style="margin-top: 1rem; text-align: center;">
            <button class="button" onclick="downloadFile('${src}', '${hostname}.jpg')">Download</button>
        </div>
    `;
    
    screenshotModalEl.style.display = 'block';
}

// Export domain data as JSON
function exportDomainData(domain, data) {
    const exportData = {
        domain,
        timestamp: new Date().toISOString(),
        subdomains: data.subdomains,
        aliveHosts: data.aliveHosts,
        nucleiFindings: data.nucleiFindings,
        waybackUrls: data.waybackUrls,
        screenshots: data.screenshots,
        amassRawRecords: data.amassRawRecords,
        fuzzingResults: data.fuzzingResults
    };
    
    const jsonString = JSON.stringify(exportData, null, 2);
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    
    const a = document.createElement('a');
    a.href = url;
    a.download = `${domain}-recon-data.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

// Utility function to escape HTML
function escapeHtml(unsafe) {
    if (typeof unsafe !== 'string') return unsafe;
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Utility function to copy text to clipboard
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        // Show some feedback that text was copied
        console.log('Copied to clipboard:', text);
    }).catch(err => {
        console.warn('Failed to copy:', err);
    });
}

// Utility function to download a file
function downloadFile(url, filename) {
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
}

// Initialize the app when the DOM is loaded
document.addEventListener('DOMContentLoaded', init);