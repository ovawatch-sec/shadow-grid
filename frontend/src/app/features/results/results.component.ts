import { Component, OnDestroy, signal, computed, effect, inject, viewChild, type ElementRef } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { ThemeService } from '../../core/services/theme.service';
import { poll, type Poll } from '../../core/http/poll';
import { InventoryDelta, InventorySnapshot, Scan, ToolResult } from '../../core/models';
import { Chart } from 'chart.js';
import {
  chartPalette, registerCharts, severityChartConfig, toolChartConfig, SEVERITY_ORDER,
} from '../../core/charts/chart-theme';

/** Rows rendered per page in the large evidence tables. */
const ROWS_PER_PAGE = { subdomains: 100, http: 100, vulns: 50, urls: 200 } as const;

type TabId = 'overview'|'inventory'|'graph'|'changes'|'evidence'|'assessment'|'subdomains'|'dns'|'http'|'vulns'|'wordpress'|'urls'|'tech'|'emails'|'dorks'|'screenshots'|'ai';

@Component({
  selector: 'sg-results',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule],
  templateUrl: './results.component.html',
  styleUrls: ['./results.component.scss'],
})
export class ResultsComponent implements OnDestroy {
  scanId!: string;
  results = signal<ToolResult[]>([]);
  inventory = signal<InventorySnapshot | null>(null);
  inventoryDelta = signal<InventoryDelta | null>(null);
  attackGraph = signal<{nodes: any[]; edges: any[]} | null>(null);
  loading = signal(true);
  scanStatus = signal<string>('');
  artifactsDeletedAt = signal<string | null>(null);
  deletingArtifacts = signal(false);
  cleanupMessage = signal('');
  cleanupError = signal('');
  private readonly scanPoll: Poll<Scan>;
  private readonly resultsPoll: Poll<ToolResult[]>;
  activeTab = signal<TabId>('overview');
  lightbox: any = null;
  subQ = signal('');
  subStatus = signal('all');
  subPage = signal(0);
  httpQ = signal('');
  httpStatus = signal('all');
  httpPage = signal(0);
  vulnQ = signal('');
  vulnSev = signal('all');
  vulnPage = signal(0);
  urlQ = signal('');
  urlSrc = signal('all');
  urlPage = signal(0);

  tabs = [
    {id:'overview' as TabId, label:'Overview'},
    {id:'inventory' as TabId, label:'Assets'},
    {id:'graph' as TabId, label:'Graph'},
    {id:'vulns' as TabId, label:'Findings'},
    {id:'changes' as TabId, label:'Changes'},
    {id:'evidence' as TabId, label:'Evidence'},
    {id:'assessment' as TabId, label:'Assessment'},
  ];
  evidenceTabs: Array<{id: TabId; label: string}> = [
    {id:'subdomains',label:'Subdomains'}, {id:'dns',label:'DNS'}, {id:'http',label:'HTTP & Ports'},
    {id:'wordpress',label:'WordPress'}, {id:'urls',label:'URLs'}, {id:'tech',label:'Technology'},
    {id:'emails',label:'Emails'}, {id:'dorks',label:'Dorks'}, {id:'screenshots',label:'Screenshots'}, {id:'ai',label:'AI analysis'},
  ];
  severities = ['all','critical','high','medium','low','info'];
  COMMON_PORTS = new Set([80,443,8080,8443,22,21,25,3389,3306,5432,6379,27017]);

  private theme = inject(ThemeService);
  private sevCanvas = viewChild<ElementRef<HTMLCanvasElement>>('sevCanvas');
  private toolCanvas = viewChild<ElementRef<HTMLCanvasElement>>('toolCanvas');
  private sevChart?: Chart<'doughnut'>;
  private toolChart?: Chart<'bar'>;

  constructor(private route: ActivatedRoute, public api: ApiService) {
    registerCharts();
    this.scanId = this.route.snapshot.paramMap.get('scanId')!;

    // Results and status refresh in place while the assessment runs, so filters,
    // sorting and pagination survive the update. Polling stops on its own once
    // the scan reaches a terminal state, and pauses while the tab is hidden.
    this.scanPoll = poll({
      request: () => this.api.getScan(this.scanId),
      intervalMs: 5000,
      while: () => this.isLive(),
    });
    this.resultsPoll = poll({
      request: () => this.api.getResults(this.scanId),
      intervalMs: 5000,
      while: () => this.isLive(),
    });

    effect(() => {
      const scan = this.scanPoll.value();
      if (!scan) return;
      const wasLive = this.isLive();
      this.scanStatus.set(scan.status);
      this.artifactsDeletedAt.set(scan.artifacts_deleted_at || null);
      // Refresh the derived views once on the transition out of a live scan.
      if (wasLive && !this.isLive()) this.refreshInventory();
    }, { allowSignalWrites: true });

    effect(() => {
      const rows = this.resultsPoll.value();
      if (!rows) return;
      this.results.set(rows);
      this.loading.set(false);
    }, { allowSignalWrites: true });

    this.refreshInventory();
    // One effect owns the chart lifecycle. It re-runs when the canvases enter or
    // leave the DOM (tab switches), when the underlying data changes (results
    // stream in while a scan runs), and when the theme flips — which is what the
    // previous create-once-and-never-touch-again implementation could not do.
    effect(() => this.renderCharts());
  }

  ngOnDestroy() {
    // Chart.js keeps canvases in a global registry and attaches resize
    // observers; without an explicit destroy they leak on every navigation.
    this.sevChart?.destroy();
    this.toolChart?.destroy();
  }

  /** True while the underlying scan is still producing results. */
  isLive(): boolean {
    return this.scanStatus() === 'running' || this.scanStatus() === 'pending';
  }

  private refreshInventory() {
    this.api.getInventory(this.scanId).subscribe({
      next: snapshot => this.inventory.set(snapshot),
      error: () => {},
    });
    this.api.getInventoryDelta(this.scanId).subscribe({
      next: delta => this.inventoryDelta.set(delta),
      error: () => {},
    });
    this.api.getAttackGraph(this.scanId).subscribe({
      next: graph => this.attackGraph.set(graph),
      error: () => {},
    });
  }

  graphGroups = computed(() => {
    const grouped = new Map<string, any[]>();
    for (const node of this.attackGraph()?.nodes || []) {
      grouped.set(node.type, [...(grouped.get(node.type) || []), node]);
    }
    return [...grouped.entries()].map(([type, nodes]) => ({type, nodes}));
  });

  inventoryByType = computed(() => {
    const counts = new Map<string, number>();
    for (const asset of this.inventory()?.assets || []) {
      counts.set(asset.type, (counts.get(asset.type) || 0) + 1);
    }
    return [...counts.entries()].map(([type, count]) => ({type, count}));
  });

  setTab(t: TabId) {
    this.activeTab.set(t);
  }

  /** True while the user is browsing the evidence landing page or one of its sources. */
  isEvidenceView(): boolean {
    return this.activeTab() === 'evidence' || this.evidenceTabs.some(tab => tab.id === this.activeTab());
  }

  /** Keep Evidence highlighted while one of its tool-oriented result views is open. */
  isPrimaryTabActive(tab: TabId): boolean {
    return tab === 'evidence' ? this.isEvidenceView() : this.activeTab() === tab;
  }

  /** Permanently remove raw files after an explicit confirmation, preserving SQL evidence. */
  deleteRawOutputs(): void {
    if (this.isLive() || this.deletingArtifacts() || this.artifactsDeletedAt()) return;
    const confirmed = window.confirm(
      'Delete this assessment\'s raw output files?\n\n' +
      'Database records, findings, inventory, screenshots, and the assessment will be kept. ' +
      'Raw logs and original tool JSON/TXT files cannot be recovered.'
    );
    if (!confirmed) return;

    this.deletingArtifacts.set(true);
    this.cleanupMessage.set('');
    this.cleanupError.set('');
    this.api.deleteRawOutputs(this.scanId).subscribe({
      next: result => {
        this.deletingArtifacts.set(false);
        this.artifactsDeletedAt.set(new Date().toISOString());
        this.cleanupMessage.set(
          `Deleted ${result.files_deleted} transient file(s) and freed ${this.formatBytes(result.bytes_freed)}. Database records and screenshots were retained.`
        );
      },
      error: error => {
        this.deletingArtifacts.set(false);
        this.cleanupError.set(error?.error?.detail || 'Raw-output cleanup failed.');
      },
    });
  }

  formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB`;
  }

  // ── Data extractors ─────────────────────────────────────────────
  private byCategory(cat: string) { return this.results().filter(r => r.category === cat).flatMap(r => r.data); }
  private byTool(tool: string)    { return this.results().filter(r => r.tool === tool).flatMap(r => r.data); }

  subdomains = computed(() => {
    const all = this.byCategory('subdomain');
    const httpx = this.byTool('httpx');
    const httpxMap = new Map(httpx.map(h => [h['host'] || '', h]));
    const alive = new Set(this.byTool('dnsx').map((d: any) => (d['host'] || '').split(' ')[0]));
    const seen = new Map<string, any>();
    all.forEach((s: any) => {
      const h = s['host']; if (!h) return;
      if (!seen.has(h)) {
        const hx = httpxMap.get(h) || {};
        seen.set(h, { host:h, source:s['source'], alive:alive.has(h)||!!hx['url'],
          status:hx['status'], title:hx['title'], tech:hx['tech'] || [] });
      }
    });
    return [...seen.values()];
  });

  aliveCount   = computed(() => this.subdomains().filter((s: any) => s['alive']).length);
  ports        = computed(() => this.byTool('naabu'));
  vulns        = computed(() => [
    ...this.byCategory('vuln'),
    ...(this.inventory()?.findings || [])
      .filter(finding => finding.tool === 'shodan')
      .map(finding => ({
        ...finding.data,
        name: finding.title,
        severity: finding.severity,
        template_id: String(finding.data['cve'] || finding.id),
        matched_at: String(finding.data['cve'] || ''),
        source: 'shodan',
      })),
  ]);
  urls         = computed(() => this.results().filter(r => r.category === 'url').flatMap(r => r.data));
  screenshots  = computed(() => this.byTool('gowitness'));
  dorks        = computed(() => this.byTool('google_dorks'));
  emails       = computed(() => this.byTool('email_finder'));
  wpFindings   = computed(() => this.byTool('wpscan'));
  // One AI report per in-scope asset (each scanned domain produces its own row).
  aiReports    = computed(() => this.byTool('ai_analysis'));
  dnsRecords   = computed(() => this.byTool('dns_records'));
  zoneResults  = computed(() => this.byTool('zone_transfer'));
  whoisData    = computed(() => { const d = this.byTool('whois')[0]; return d ? d['whois'] : 'No WHOIS data'; });
  asnRanges    = computed(() => this.byTool('asnmap'));
  httpResults  = computed(() => this.byTool('httpx'));
  toolErrors = computed(() => this.results().filter(result => !!result.error).length);

  techInventory = computed(() => {
    const map = new Map<string, Set<string>>();
    this.httpResults().forEach((h: any) => {
      (h['tech'] || []).forEach((t: string) => {
        const k = t.split(':')[0].trim();
        if (!map.has(k)) map.set(k, new Set());
        if (h['host']) map.get(k)!.add(h['host']);
      });
    });
    return [...map.entries()].map(([name,hosts]) => ({name,count:hosts.size})).sort((a,b)=>b.count-a.count);
  });
  maxTech   = computed(() => this.techInventory()[0]?.count || 1);
  critHigh  = computed(() => this.vulns().filter((v: any) => ['critical','high'].includes(v['severity'])).length);
  topVulns  = computed(() => [...this.vulns()].sort((a: any,b: any) => this.sevRank(a)-this.sevRank(b)).slice(0,5));

  filteredSubs = computed(() => {
    let rows = this.subdomains();
    const q = this.subQ().trim().toLowerCase();
    const status = this.subStatus();

    if (q) rows = rows.filter((x: any) => (x['host'] || '').toLowerCase().includes(q));
    if (status === 'alive') rows = rows.filter((x: any) => x['alive']);
    if (status === 'dead') rows = rows.filter((x: any) => !x['alive']);

    return rows;
  });
  pagedSubs = computed(() => {
    const page = this.subPage();
    const size = ROWS_PER_PAGE.subdomains;
    return this.filteredSubs().slice(page * size, (page + 1) * size);
  });
  totalSubPages = computed(() => Math.ceil(this.filteredSubs().length / ROWS_PER_PAGE.subdomains));

  filteredHttp = computed(() => {
    let rows = this.httpResults();
    const q = this.httpQ().trim().toLowerCase();
    const status = this.httpStatus();

    if (q) {
      rows = rows.filter((x: any) =>
        (x['url'] || '').toLowerCase().includes(q) ||
        (x['title'] || '').toLowerCase().includes(q) ||
        (x['host'] || '').toLowerCase().includes(q));
    }

    if (status !== 'all') {
      rows = rows.filter((x: any) => {
        const sc = Number(x['status']);
        if (status === '2xx') return sc >= 200 && sc < 300;
        if (status === '3xx') return sc >= 300 && sc < 400;
        if (status === '4xx') return sc >= 400 && sc < 500;
        if (status === '5xx') return sc >= 500;
        return true;
      });
    }

    return rows;
  });

  filteredVulns = computed(() => {
    let rows = this.vulns();
    const sev = this.vulnSev();
    const q = this.vulnQ().trim().toLowerCase();

    if (sev !== 'all') rows = rows.filter((x: any) => (x['severity'] || '').toLowerCase() === sev);
    if (q) {
      rows = rows.filter((x: any) =>
        (x['name'] || '').toLowerCase().includes(q) ||
        (x['template_id'] || '').toLowerCase().includes(q) ||
        (x['matched_at'] || '').toLowerCase().includes(q) ||
        (x['host'] || '').toLowerCase().includes(q));
    }

    return [...rows].sort((a: any, b: any) => this.sevRank(a) - this.sevRank(b));
  });

  filteredUrls = computed(() => {
    let rows = this.urls();
    const source = this.urlSrc();
    const q = this.urlQ().trim().toLowerCase();

    if (source !== 'all') rows = rows.filter((x: any) => x['source'] === source);
    if (q) rows = rows.filter((x: any) => (x['url'] || '').toLowerCase().includes(q));

    return rows;
  });

  pagedHttp = computed(() => {
    const size = ROWS_PER_PAGE.http;
    const page = this.httpPage();
    return this.filteredHttp().slice(page * size, (page + 1) * size);
  });
  totalHttpPages = computed(() => Math.ceil(this.filteredHttp().length / ROWS_PER_PAGE.http));

  pagedVulns = computed(() => {
    const size = ROWS_PER_PAGE.vulns;
    const page = this.vulnPage();
    return this.filteredVulns().slice(page * size, (page + 1) * size);
  });
  totalVulnPages = computed(() => Math.ceil(this.filteredVulns().length / ROWS_PER_PAGE.vulns));

  /** Text equivalents of the two charts, exposed as the canvas aria-label. */
  severityChartSummary = computed(() => {
    const parts = SEVERITY_ORDER.map(level => `${this.sevCount(level)} ${level}`);
    return `Severity distribution: ${parts.join(', ')}.`;
  });
  toolChartSummary = computed(() => {
    const rows = this.chartToolRows();
    if (rows.length === 0) return 'Results by tool: no tools have reported yet.';
    return `Results by tool: ${rows.map(r => `${r.tool} ${r.count}`).join(', ')}.`;
  });
  private chartToolRows = computed(() =>
    [...this.results()].sort((a, b) => b.count - a.count).slice(0, 12));

  urlSources = computed(() => {
    const m = new Map<string, number>();
    this.urls().forEach((u: any) => { const s = u['source']||'unknown'; m.set(s,(m.get(s)||0)+1); });
    return [...m.entries()].map(([name,count])=>({name,count}));
  });

  portSummary = computed(() => {
    const m = new Map<number,number>();
    this.ports().forEach((p: any) => m.set(p['port'],(m.get(p['port'])||0)+1));
    return [...m.entries()].map(([port,count])=>({port,count})).sort((a,b)=>b.count-a.count);
  });

  sortedPorts = computed(() => [...this.ports()].sort((a: any, b: any) => {
    const hostOrder = String(a['host'] || '').localeCompare(String(b['host'] || ''));
    return hostOrder || Number(a['port'] || 0) - Number(b['port'] || 0);
  }));


  // ── Filter setters: reset pagination whenever a filter changes ─────────
  setSubQ(value: string) { this.subQ.set(value); this.subPage.set(0); }
  setSubStatus(value: string) { this.subStatus.set(value); this.subPage.set(0); }
  setHttpQ(value: string) { this.httpQ.set(value); this.httpPage.set(0); }
  setHttpStatus(value: string) { this.httpStatus.set(value); this.httpPage.set(0); }
  setVulnQ(value: string) { this.vulnQ.set(value); this.vulnPage.set(0); }
  setVulnSev(value: string) { this.vulnSev.set(value); this.vulnPage.set(0); }
  setUrlQ(value: string) { this.urlQ.set(value); this.urlPage.set(0); }
  setUrlSrc(value: string) { this.urlSrc.set(value); this.urlPage.set(0); }
  totalUrlPages(): number { return Math.ceil(this.filteredUrls().length / ROWS_PER_PAGE.urls); }

  // ── Helper methods ──────────────────────────────────────────────
  sevRank(f: any): number {
    const m: any = {critical:0,high:1,medium:2,low:3,info:4,unknown:5};
    return m[(f['severity']||'unknown').toLowerCase()] ?? 5;
  }
  sevCount(s: string): number {
    if (s === 'all') return 0;
    return this.vulns().filter((v: any) => v['severity'] === s).length;
  }
  tabCount(t: TabId): number {
    const m: Record<TabId,number> = {
      overview:0, inventory:this.inventory()?.assets.length || 0,
      graph:this.attackGraph()?.nodes.length || 0,
      changes:(this.inventoryDelta()?.added_assets.length || 0) + (this.inventoryDelta()?.new_findings.length || 0),
      evidence:this.results().reduce((sum,result)=>sum+result.count,0), assessment:this.results().length,
      subdomains:this.subdomains().length, dns:this.dnsRecords().length,
      http:this.httpResults().length, vulns:this.vulns().length, wordpress:this.wpFindings().length,
      urls:this.urls().length, tech:this.techInventory().length, emails:this.emails().length, dorks:this.dorks().length,
      screenshots:this.screenshots().length, ai:this.aiReports().length
    };
    return m[t] || 0;
  }
  wpSites(): number {
    return new Set(this.wpFindings().map((f: any) => f['url']).filter(Boolean)).size;
  }
  isCommonPort(p: number): boolean { return this.COMMON_PORTS.has(p); }
  portClass(p: number): string { return 'port-chip' + (this.isCommonPort(p) ? ' common' : ''); }
  statusBadge(code: number): string {
    if (code >= 500) return 'badge-5xx';
    if (code >= 400) return 'badge-4xx';
    if (code >= 300) return 'badge-3xx';
    return 'badge-2xx';
  }
  emailVerificationBadge(status: string): string {
    if (status === 'valid') return 'badge-alive';
    if (['invalid', 'disposable'].includes(status)) return 'badge-dead';
    return 'badge-tool';
  }

  // ── Export methods (no arrow functions in template) ─────────────
  exportSubdomains()  { this.exportTxt(this.filteredSubs().map((s: any) => s['host']), 'subdomains.txt'); }
  exportHttpUrls()    { this.exportTxt(this.filteredHttp().map((h: any) => h['url']), 'alive_urls.txt'); }
  exportAllUrls()     { this.exportTxt(this.filteredUrls().map((u: any) => u['url']), 'urls.txt'); }
  exportDorks()       { this.exportTxt(this.dorks().map((d: any) => d['dork']), 'google_dorks.txt'); }
  exportEmails()      { this.exportTxt(this.emails().map((e: any) => e['email']), 'emails.txt'); }
  exportAiReport(report: any) {
    const md = report?.['markdown'] || '';
    const name = (report?.['domain'] || 'asset').toString().replace(/[^a-z0-9.-]+/gi, '_');
    this.exportTxt([md], `ai_analysis_${name}.md`);
  }

  copy(text: string)  { navigator.clipboard.writeText(text).catch(() => {}); }
  copyItem(item: any, key: string) { this.copy(item[key] || ''); }

  artifactSrc(item: any): string {
    if (item?.['blob_id']) return this.api.evidenceBlobUrl(this.scanId, item['blob_id']);
    return item?.['path'] ? this.api.artifactUrl(this.scanId, item['path']) : '';
  }

  artifactPath(path: string | undefined): string {
    return path ? this.api.artifactUrl(this.scanId, path) : '#';
  }

  exportTxt(lines: string[], fname: string) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([lines.filter(Boolean).join('\n')], {type:'text/plain'}));
    a.download = fname; a.click();
  }
  exportJson() {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([JSON.stringify(this.results(),null,2)], {type:'application/json'}));
    a.download = `scan-${this.scanId.slice(0,8)}.json`; a.click();
  }

  techBarWidth(count: number): string { return ((count / this.maxTech()) * 100) + '%'; }

  /**
   * Create, update, or tear down the overview charts.
   *
   * Reading `theme.theme()` registers this effect as a dependency of the active
   * theme, so a light/dark switch rebuilds both charts with freshly resolved
   * token colours instead of leaving dark-only hex values on a light surface.
   */
  private renderCharts(): void {
    const themeKey = this.theme.theme();
    const sevEl = this.sevCanvas()?.nativeElement;
    const toolEl = this.toolCanvas()?.nativeElement;
    const palette = chartPalette();

    if (!sevEl) {
      this.sevChart?.destroy();
      this.sevChart = undefined;
    } else {
      const counts = SEVERITY_ORDER.map(level => this.sevCount(level));
      if (!this.sevChart || this.sevChart.canvas !== sevEl || this.sevThemeKey !== themeKey) {
        this.sevChart?.destroy();
        this.sevChart = new Chart(sevEl, severityChartConfig(counts, palette));
        this.sevThemeKey = themeKey;
      } else {
        this.sevChart.data.datasets[0].data = counts;
        this.sevChart.update('none');
      }
    }

    if (!toolEl) {
      this.toolChart?.destroy();
      this.toolChart = undefined;
    } else {
      const rows = this.chartToolRows();
      const labels = rows.map(r => r.tool);
      const values = rows.map(r => r.count);
      if (!this.toolChart || this.toolChart.canvas !== toolEl || this.toolThemeKey !== themeKey) {
        this.toolChart?.destroy();
        this.toolChart = new Chart(toolEl, toolChartConfig(labels, values, palette));
        this.toolThemeKey = themeKey;
      } else {
        this.toolChart.data.labels = labels;
        this.toolChart.data.datasets[0].data = values;
        this.toolChart.update('none');
      }
    }
  }

  private sevThemeKey = '';
  private toolThemeKey = '';
}
