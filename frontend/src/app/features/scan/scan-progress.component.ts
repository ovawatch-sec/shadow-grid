
import { Component, OnInit, OnDestroy, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { ApiService } from '../../core/services/api.service';
import { ScanProgressEvent } from '../../core/models';

@Component({
  selector: 'sg-scan-progress',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="page">
      <div class="breadcrumb">
        <a routerLink="/projects">Projects</a>
        <span class="sep">›</span>
        <span>Scan Progress</span>
      </div>

      <div class="progress-header">
        <h1 class="page-title">Scan Running</h1>
        <span class="mono text-dim">{{scanId.slice(0,8)}}…</span>
      </div>

      <!-- Phase indicator -->
      @if (currentPhase()) {
        <div class="phase-banner">
          <span class="spinner-sm"></span>
          <span>{{currentPhase()}}</span>
        </div>
      }

      <!-- Tool progress list -->
      <div class="progress-list">
        @for (ev of events(); track ev.tool) {
          <div class="progress-item" [class]="'pi-' + ev.status">
            <div class="pi-icon">
              @switch (ev.status) {
                @case ('running') { <span class="spinner-sm"></span> }
                @case ('done')    { <span class="pi-check">✓</span> }
                @case ('error')   { <span class="pi-x">✗</span> }
                @case ('skipped') { <span class="pi-skip">—</span> }
              }
            </div>
            <span class="pi-tool">{{ev.tool}}</span>
            <span class="pi-msg">{{ev.message}}</span>
            @if (ev.count) { <span class="pi-count">{{ev.count}} results</span> }
            <span class="badge badge-{{ev.status}}">{{ev.status}}</span>
          </div>
        }
      </div>

      <!-- Done -->
      @if (done()) {
        <div class="done-banner" [class.done-ok]="!failed()" [class.done-err]="failed()">
          <span>{{failed() ? '✗ Scan failed' : '✓ Scan completed'}}</span>
          <a class="btn btn-primary btn-sm" [routerLink]="['/scan', scanId, 'results']">View Results</a>
        </div>
      }
    </div>
  `,
  styles: [`
    .page { padding:32px; max-width:800px; margin:0 auto; }
    .breadcrumb { display:flex; align-items:center; gap:8px; font-size:13px; color:var(--text-dim); margin-bottom:20px; }
    .breadcrumb a { color:var(--accent); }
    .sep { color:var(--text-faint); }
    .progress-header { display:flex; align-items:center; gap:16px; margin-bottom:20px; }
    .page-title { font-family:var(--font-head); font-size:22px; font-weight:700; }
    .phase-banner { display:flex; align-items:center; gap:10px; background:rgba(0,232,122,.07); border:1px solid rgba(0,232,122,.2); border-radius:var(--radius-lg); padding:12px 16px; margin-bottom:16px; font-family:var(--font-head); font-size:13px; color:var(--accent); }
    .progress-list { display:flex; flex-direction:column; gap:6px; margin-bottom:20px; }
    .progress-item { display:flex; align-items:center; gap:10px; background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius); padding:10px 14px; transition:border-color 150ms; }
    .pi-running { border-color:rgba(255,147,64,.3); }
    .pi-done    { border-color:rgba(0,232,122,.25); }
    .pi-error   { border-color:rgba(255,71,87,.25); }
    .pi-icon { width:20px; text-align:center; flex-shrink:0; }
    .pi-check { color:var(--accent); font-weight:700; }
    .pi-x     { color:var(--sev-critical); font-weight:700; }
    .pi-skip  { color:var(--text-faint); }
    .pi-tool  { font-family:var(--font-mono); font-size:12px; width:120px; flex-shrink:0; }
    .pi-msg   { font-size:12px; color:var(--text-dim); flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .pi-count { font-family:var(--font-mono); font-size:11px; color:var(--cyan); }
    .done-banner { display:flex; align-items:center; justify-content:space-between; padding:14px 18px; border-radius:var(--radius-lg); border:1px solid; }
    .done-ok  { background:rgba(0,232,122,.08); border-color:rgba(0,232,122,.3); color:var(--accent); }
    .done-err { background:rgba(255,71,87,.08); border-color:rgba(255,71,87,.3); color:var(--sev-critical); }
  `]
})
export class ScanProgressComponent implements OnInit, OnDestroy {
  scanId!: string;
  events = signal<ScanProgressEvent[]>([]);
  currentPhase = signal('');
  done = signal(false);
  failed = signal(false);
  private es?: EventSource;

  constructor(private route: ActivatedRoute, private router: Router, private api: ApiService) {}

  ngOnInit() {
    this.scanId = this.route.snapshot.paramMap.get('id')!;
    this.es = new EventSource(`/api/scans/${this.scanId}/progress`);
    this.es.onmessage = (e) => {
      if (!e.data || e.data === '{}') return;
      try {
        const ev: ScanProgressEvent = JSON.parse(e.data);
        if (ev.tool === '__phase__') { this.currentPhase.set(ev.message); return; }
        if (ev.tool === '__domain__') return;
        if (ev.tool === '__scan__') {
          this.done.set(true);
          this.failed.set(ev.status as any === 'failed');
          this.es?.close();
          return;
        }
        this.events.update(evs => {
          const idx = evs.findIndex(x => x.tool === ev.tool);
          if (idx >= 0) { const copy = [...evs]; copy[idx] = ev; return copy; }
          return [...evs, ev];
        });
      } catch {}
    };
    this.es.onerror = () => { this.done.set(true); this.es?.close(); };
  }

  ngOnDestroy() { this.es?.close(); }
}
