import { Component, OnInit, signal, computed, AfterViewInit } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { ToolResult } from '../../core/models';

declare const Chart: any;

type TabId = 'overview'|'subdomains'|'dns'|'http'|'vulns'|'urls'|'tech'|'screenshots';

@Component({
  selector: 'sg-results',
  standalone: true,
  imports: [CommonModule, RouterLink, FormsModule],
  templateUrl: './results.component.html',
  styleUrls: ['./results.component.scss'],
})
export class ResultsComponent implements OnInit, AfterViewInit {
  scanId!: string;
  results = signal<ToolResult[]>([]);
  loading = signal(true);
  activeTab = signal<TabId>('overview');
  lightbox: any = null;
  subQ = ''; subStatus = 'all'; subPage = 0;
  httpQ = ''; httpStatus = 'all';
  vulnQ = ''; vulnSev = 'all';
  urlQ = ''; urlSrc = 'all'; urlPage = 0;

  tabs = [
    {id:'overview' as TabId, label:'Overview'},
    {id:'subdomains' as TabId, label:'Subdomains'},
    {id:'dns' as TabId, label:'DNS & Assets'},
    {id:'http' as TabId, label:'HTTP & Ports'},
    {id:'vulns' as TabId, label:'Vulns'},
    {id:'urls' as TabId, label:'URLs'},
    {id:'tech' as TabId, label:'Tech Stack'},
    {id:'screenshots' as TabId, label:'Screenshots'},
  ];
  severities = ['all','critical','high','medium','low','info'];
  COMMON_PORTS = new Set([80,443,8080,8443,22,21,25,3389,3306,5432,6379,27017]);

  constructor(private route: ActivatedRoute, private api: ApiService) {}

  ngOnInit() {
    this.scanId = this.route.snapshot.paramMap.get('scanId')!;
    this.api.getResults(this.scanId).subscribe({
      next: rs => { this.results.set(rs); this.loading.set(false); this.initCharts(); },
      error: () => this.loading.set(false),
    });
  }
  ngAfterViewInit() { setTimeout(() => this.initCharts(), 200); }

  setTab(t: TabId) {
    this.activeTab.set(t);
    setTimeout(() => this.initCharts(), 100);
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
  vulns        = computed(() => this.byTool('nuclei'));
  urls         = computed(() => this.results().filter(r => r.category === 'url').flatMap(r => r.data));
  screenshots  = computed(() => this.byTool('gowitness'));
  dnsRecords   = computed(() => this.byTool('dns_records'));
  zoneResults  = computed(() => this.byTool('zone_transfer'));
  whoisData    = computed(() => { const d = this.byTool('whois')[0]; return d ? d['whois'] : 'No WHOIS data'; });
  asnRanges    = computed(() => this.byTool('asnmap'));
  httpResults  = computed(() => this.byTool('httpx'));

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
    let s = this.subdomains();
    if (this.subQ) s = s.filter((x: any) => x['host']?.toLowerCase().includes(this.subQ.toLowerCase()));
    if (this.subStatus === 'alive') s = s.filter((x: any) => x['alive']);
    if (this.subStatus === 'dead')  s = s.filter((x: any) => !x['alive']);
    return s;
  });
  pagedSubs       = computed(() => this.filteredSubs().slice(this.subPage*100,(this.subPage+1)*100));
  totalSubPages   = computed(() => Math.ceil(this.filteredSubs().length / 100));

  filteredHttp = computed(() => {
    let h = this.httpResults();
    if (this.httpQ) h = h.filter((x: any) => (x['url']||'').toLowerCase().includes(this.httpQ.toLowerCase()) || (x['title']||'').toLowerCase().includes(this.httpQ.toLowerCase()));
    if (this.httpStatus !== 'all') h = h.filter((x: any) => {
      const sc = x['status'];
      if (this.httpStatus==='2xx') return sc>=200&&sc<300;
      if (this.httpStatus==='3xx') return sc>=300&&sc<400;
      if (this.httpStatus==='4xx') return sc>=400&&sc<500;
      if (this.httpStatus==='5xx') return sc>=500;
      return true;
    });
    return h;
  });

  filteredVulns = computed(() => {
    let v = this.vulns();
    if (this.vulnSev !== 'all') v = v.filter((x: any) => x['severity'] === this.vulnSev);
    if (this.vulnQ) v = v.filter((x: any) =>
      (x['name']||'').toLowerCase().includes(this.vulnQ.toLowerCase()) ||
      (x['template_id']||'').toLowerCase().includes(this.vulnQ.toLowerCase()) ||
      (x['matched_at']||'').toLowerCase().includes(this.vulnQ.toLowerCase()));
    return [...v].sort((a: any,b: any) => this.sevRank(a)-this.sevRank(b));
  });

  filteredUrls = computed(() => {
    let u = this.urls();
    if (this.urlSrc !== 'all') u = u.filter((x: any) => x['source'] === this.urlSrc);
    if (this.urlQ) u = u.filter((x: any) => x['url']?.toLowerCase().includes(this.urlQ.toLowerCase()));
    return u;
  });

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
      overview:0, subdomains:this.subdomains().length, dns:this.dnsRecords().length,
      http:this.httpResults().length, vulns:this.vulns().length, urls:this.urls().length,
      tech:this.techInventory().length, screenshots:this.screenshots().length
    };
    return m[t] || 0;
  }
  isCommonPort(p: number): boolean { return this.COMMON_PORTS.has(p); }
  portClass(p: number): string { return 'port-chip' + (this.isCommonPort(p) ? ' common' : ''); }
  statusBadge(code: number): string {
    if (code >= 500) return 'badge-5xx';
    if (code >= 400) return 'badge-4xx';
    if (code >= 300) return 'badge-3xx';
    return 'badge-2xx';
  }

  // ── Export methods (no arrow functions in template) ─────────────
  exportSubdomains()  { this.exportTxt(this.filteredSubs().map((s: any) => s['host']), 'subdomains.txt'); }
  exportHttpUrls()    { this.exportTxt(this.filteredHttp().map((h: any) => h['url']), 'alive_urls.txt'); }
  exportAllUrls()     { this.exportTxt(this.filteredUrls().map((u: any) => u['url']), 'urls.txt'); }

  copy(text: string)  { navigator.clipboard.writeText(text).catch(() => {}); }
  copyItem(item: any, key: string) { this.copy(item[key] || ''); }

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

  initCharts() {
    if (typeof Chart === 'undefined') return;
    const sevCanvas  = document.getElementById('chart-sev')  as HTMLCanvasElement;
    const toolCanvas = document.getElementById('chart-tools') as HTMLCanvasElement;
    if (sevCanvas && !(sevCanvas as any)._chartInstance) {
      const counts = this.severities.filter(s => s !== 'all').map(s => this.sevCount(s));
      const c = new Chart(sevCanvas, {
        type:'doughnut',
        data:{ labels:['Critical','High','Medium','Low','Info'],
          datasets:[{data:counts, backgroundColor:['#ff4757','#ff8c42','#ffc22a','#00bcd4','#78909c'],
          borderColor:'#0b1628', borderWidth:3}]},
        options:{responsive:true, maintainAspectRatio:false, cutout:'62%',
          plugins:{legend:{position:'right', labels:{color:'#c4d4eb', font:{size:11}}}}}
      });
      (sevCanvas as any)._chartInstance = c;
    }
    if (toolCanvas && !(toolCanvas as any)._chartInstance) {
      const r = this.results().slice(0,12);
      const c = new Chart(toolCanvas, {
        type:'bar',
        data:{ labels:r.map(x => x.tool),
          datasets:[{label:'Results', data:r.map(x => x.count),
          backgroundColor:'rgba(0,232,122,.5)', borderColor:'#00e87a', borderWidth:1, borderRadius:4}]},
        options:{indexAxis:'y', responsive:true, maintainAspectRatio:false,
          plugins:{legend:{display:false}},
          scales:{x:{grid:{color:'#1a2e4a'}, ticks:{color:'#60789a'}}, y:{ticks:{color:'#c4d4eb'}}}}
      });
      (toolCanvas as any)._chartInstance = c;
    }
  }
}
