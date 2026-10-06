import { Component, DestroyRef, OnInit, OnDestroy, NgZone, inject, signal, computed, effect } from '@angular/core';
import { CommonModule } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { ApiService } from '../../core/services/api.service';
import { poll } from '../../core/http/poll';
import { ScanProgressEvent } from '../../core/models';

type ProgressRow = ScanProgressEvent & { key: string };

/** A phase within one domain: its tools, and how far through them the scan is. */
interface PhaseGroup {
  index: number;
  name: string;
  rows: ProgressRow[];
  done: number;
  total: number;
  percent: number;
  running: boolean;
}

interface DomainGroup {
  domain: string;
  phases: PhaseGroup[];
  done: number;
  total: number;
  percent: number;
  running: boolean;
}

/** Declared by the engine for a phase it is about to run, or is skipping. */
interface PhaseMeta { domain: string; index: number; name: string; status: string; }

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
        <div>
          <h1 class="page-title">{{done() ? finalTitle() : 'Scan Running'}}</h1>
          <div class="mono text-dim">{{scanId.slice(0,8)}}…</div>
        </div>
        <div class="header-right">
          @if (!done()) {
            <a class="btn btn-outline btn-sm" [routerLink]="['/scan', scanId, 'results']">Results so far</a>
            <button class="btn btn-danger btn-sm" [disabled]="cancelling()" (click)="cancelScan()">
              @if (cancelling()) { <span class="spinner-sm"></span> } Cancel Scan
            </button>
          }
          <div class="overall-box">
            <span>{{overallPercent()}}%</span>
            <small>{{completedTools()}} / {{totalTools()}} tools finished</small>
          </div>
        </div>
      </div>

      <div class="overall-progress" role="progressbar" aria-label="Overall assessment progress"
        [attr.aria-valuenow]="overallPercent()" aria-valuemin="0" aria-valuemax="100">
        <div class="overall-fill" [style.width.%]="overallPercent()"></div>
      </div>
      <!-- Polite region so completion is announced without stealing focus. -->
      <p class="sr-only" aria-live="polite">{{liveSummary()}}</p>

      @if (currentPhase()) {
        <div class="phase-banner" [class.phase-done]="done()">
          @if (!done()) { <span class="spinner-sm"></span> }
          <div>
            <span>{{currentPhase()}}</span>
            @if (phaseToolTotal() > 0) {
              <small>{{phaseToolDone()}} / {{phaseToolTotal()}} in this phase</small>
            }
          </div>
        </div>
      }

      @for (g of domainGroups(); track g.domain) {
        <section class="domain-block" [class.db-active]="g.running && !done()">
          <header class="db-head">
            @if (g.running && !done()) { <span class="spinner-sm"></span> } @else { <span class="db-dot" aria-hidden="true">◆</span> }
            <h2 class="db-domain mono">{{g.domain}}</h2>
            <span class="db-count mono">{{g.done}}/{{g.total}} tools</span>
            <div class="db-bar" role="progressbar" [attr.aria-label]="g.domain + ' progress'"
              [attr.aria-valuenow]="g.percent" aria-valuemin="0" aria-valuemax="100">
              <div class="db-fill" [style.width.%]="g.percent"></div>
            </div>
          </header>

          <div class="phase-row">
            @for (p of g.phases; track p.index) {
              <article class="phase-card" [class.pc-running]="p.running && !done()" [class.pc-idle]="p.total === 0">
                <header class="pc-head">
                  <span class="pc-index mono">Phase {{p.index}}</span>
                  <span class="pc-count mono">{{p.done}}/{{p.total}}</span>
                </header>
                <h3 class="pc-name">{{p.name}}</h3>
                <div class="pc-bar"><div class="pc-fill" [style.width.%]="p.percent"></div></div>

                @if (p.rows.length === 0) {
                  <p class="pc-empty">No selected tools</p>
                } @else {
                  <ul class="pc-tools">
                    @for (ev of p.rows; track ev.key) {
                      <li class="progress-item" [class]="'pi-' + ev.status">
                        <span class="pi-icon">
                          @switch (ev.status) {
                            @case ('running') { <span class="spinner-sm"></span> }
                            @case ('done') { <span class="pi-check" aria-hidden="true">✓</span> }
                            @case ('completed') { <span class="pi-check" aria-hidden="true">✓</span> }
                            @case ('error') { <span class="pi-x" aria-hidden="true">✗</span> }
                            @case ('failed') { <span class="pi-x" aria-hidden="true">✗</span> }
                            @case ('skipped') { <span class="pi-skip" aria-hidden="true">—</span> }
                            @case ('cancelled') { <span class="pi-skip" aria-hidden="true">—</span> }
                          }
                        </span>
                        <span class="pi-main">
                          <span class="pi-line">
                            <span class="pi-tool">{{ev.tool}}</span>
                            @if (ev.count) { <span class="pi-count">{{ev.count}}</span> }
                          </span>
                          @if (ev.message) { <span class="pi-msg" [title]="ev.message">{{ev.message}}</span> }
                        </span>
                      </li>
                    }
                  </ul>
                }
              </article>
            }
          </div>
        </section>
      }

      @if (done()) {
        <div class="done-banner" [class.done-ok]="!failed()" [class.done-err]="failed()">
          <span>{{finalTitle()}}</span>
          @if (!failed()) {
            <a class="btn btn-primary btn-sm" [routerLink]="['/scan', scanId, 'results']">View Results</a>
          }
        </div>
      }
    </div>
  `,
  styles: [`
    /* One block per domain; its phases lay out as a wrapping row of cards.
       auto-fill with a min column width keeps the wrapped cards aligned to the
       same columns as the first row, rather than stretching to fill the gap. */
    .domain-block { margin-bottom:var(--space-6); }
    .db-head {
      display:flex; align-items:center; gap:10px; flex-wrap:wrap;
      padding-bottom:var(--space-2); margin-bottom:var(--space-3);
      border-bottom:1px solid var(--border);
    }
    .db-dot { color:var(--accent); font-size:12px; }
    .db-domain { font-size:var(--text-lg); font-weight:var(--weight-semibold); color:var(--text); min-width:0; overflow-wrap:anywhere; }
    .db-count { font-size:var(--text-sm); color:var(--text-dim); }
    .db-bar { flex:1 1 140px; min-width:120px; height:5px; background:var(--bg-elevated); border-radius:var(--radius-pill); overflow:hidden; }
    .db-fill { height:100%; background:linear-gradient(90deg,var(--accent),var(--cyan)); transition:width 250ms var(--ease); }
    .domain-block.db-active .db-domain { color:var(--text); }

    .phase-row { display:grid; grid-template-columns:repeat(auto-fill,minmax(250px,1fr)); gap:var(--space-3); align-items:start; }
    .phase-card {
      background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-lg);
      padding:var(--space-3) var(--space-4); box-shadow:var(--shadow);
      display:flex; flex-direction:column; gap:var(--space-2); min-width:0;
    }
    .phase-card.pc-running { border-color:var(--sev-high-border); }
    .phase-card.pc-idle { opacity:.6; }
    .pc-head { display:flex; align-items:center; justify-content:space-between; gap:var(--space-2); }
    .pc-index { font-size:var(--text-xs); letter-spacing:.08em; text-transform:uppercase; color:var(--text-dim); }
    .pc-count { font-size:var(--text-sm); color:var(--text-dim); }
    .pc-name { font-size:var(--text-base); font-weight:var(--weight-semibold); color:var(--text); line-height:1.3; overflow-wrap:anywhere; }
    .pc-bar { height:3px; background:var(--bg-elevated); border-radius:var(--radius-pill); overflow:hidden; }
    .pc-fill { height:100%; background:var(--accent); transition:width 250ms var(--ease); }
    .pc-empty { font-size:var(--text-sm); color:var(--text-faint); }
    .pc-tools { list-style:none; display:flex; flex-direction:column; gap:var(--space-1); margin:0; padding:0; }
    .progress-header { display:flex; align-items:center; justify-content:space-between; gap:16px; margin-bottom:12px; }
    .header-right { display:flex; align-items:center; gap:16px; }
    .page-title { font-family:var(--font-head); font-size:22px; font-weight:700; margin-bottom:4px; }
    .overall-box { display:flex; flex-direction:column; align-items:flex-end; gap:2px; font-family:var(--font-mono); }
    .overall-box span { color:var(--accent); font-size:20px; font-weight:700; }
    .overall-box small { color:var(--text-dim); font-size:11px; }
    .overall-progress { height:8px; background:var(--bg-elevated); border:1px solid var(--border); border-radius:999px; overflow:hidden; margin-bottom:16px; }
    .overall-fill { height:100%; background:linear-gradient(90deg,var(--accent),var(--cyan)); transition:width 250ms var(--ease); }
    .phase-banner { display:flex; align-items:center; gap:10px; background:var(--accent-glow); border:1px solid var(--accent-border); border-radius:var(--radius-lg); padding:var(--space-3) var(--space-4); margin-bottom:var(--space-4); font-family:var(--font-sans); font-size:var(--text-base); color:var(--accent); }
    .phase-banner small { display:block; margin-top:2px; font-family:var(--font-mono); color:var(--text-dim); font-size:10px; }
    .phase-done { opacity:.85; }
    /* Tool rows sit inside a phase card, so they drop the card chrome and the
       horizontal padding that would nest one box inside another. */
    .progress-item { display:flex; align-items:flex-start; gap:var(--space-2); padding:5px 0; border-top:1px solid var(--border); }
    .progress-item:first-child { border-top:none; }
    .pi-icon { width:16px; display:inline-flex; justify-content:center; flex-shrink:0; padding-top:2px; }
    .pi-check { color:var(--accent); font-weight:700; }
    .pi-x { color:var(--sev-critical); font-weight:700; }
    .pi-skip { color:var(--text-faint); }
    .pi-error .pi-tool, .pi-failed .pi-tool { color:var(--sev-critical); }
    .pi-skipped .pi-tool, .pi-cancelled .pi-tool { color:var(--text-dim); }
    .pi-main { flex:1; min-width:0; display:flex; flex-direction:column; }
    .pi-line { display:flex; align-items:baseline; gap:var(--space-2); min-width:0; }
    .pi-tool { font-family:var(--font-mono); font-size:12px; flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .pi-domain { font-family:var(--font-mono); font-size:10px; color:var(--text-faint); max-width:180px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .pi-msg { font-size:var(--text-sm); color:var(--text-dim); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .pi-count { font-family:var(--font-mono); font-size:var(--text-sm); color:var(--cyan); flex-shrink:0; }
    .done-banner { display:flex; align-items:center; justify-content:space-between; padding:14px 18px; border-radius:var(--radius-lg); border:1px solid; }
    .done-ok { background:var(--accent-glow); border-color:var(--accent-border); color:var(--accent); }
    .done-err { background:var(--sev-critical-surface); border-color:var(--sev-critical-border); color:var(--sev-critical); }
  `]
})
export class ScanProgressComponent implements OnInit, OnDestroy {
  scanId!: string;
  events = signal<ProgressRow[]>([]);
  currentPhase = signal('');
  done = signal(false);
  failed = signal(false);
  cancelling = signal(false);
  finalStatus = signal('');

  phaseToolDone = signal(0);
  phaseToolTotal = signal(0);
  totalTools = signal(0);
  completedTools = signal(0);

  /** Single sentence describing the current state, for the live region. */
  liveSummary = computed(() => {
    if (this.done()) return this.finalTitle();
    const phase = this.currentPhase();
    const base = `${this.completedTools()} of ${this.totalTools()} tools finished`;
    return phase ? `${phase}. ${base}.` : `${base}.`;
  });

  overallPercent = computed(() => {
    const total = this.totalTools();
    if (this.done()) return 100;
    if (!total) return 0;
    return Math.min(99, Math.round((this.completedTools() / total) * 100));
  });

  finalTitle = computed(() => {
    const s = this.finalStatus();
    if (s === 'failed') return '✗ Scan failed';
    if (s === 'cancelled') return '— Scan cancelled';
    return '✓ Scan completed';
  });

  /**
   * Group progress into one block per domain, and within it one card per phase.
   *
   * A scan runs the same ordered phases against every in-scope domain, so a flat
   * list per domain grew into a single tall column that pushed the later domains
   * off-screen and gave no sense of which stage the scan was at. Phases are the
   * natural unit here: each is a bounded set of tools with its own progress, so
   * they lay out as a wrapping row of cards the operator can scan across.
   *
   * Phases the engine announced but had no selected tools for are kept, greyed,
   * so the stages always read in the same order for every domain.
   */
  private static readonly TERMINAL = ['done', 'completed', 'error', 'failed', 'skipped', 'cancelled'];

  /** `__phase__` announcements, keyed by domain and phase index. */
  private phaseMeta = signal<PhaseMeta[]>([]);

  domainGroups = computed<DomainGroup[]>(() => {
    const rowsByDomain = new Map<string, ProgressRow[]>();
    for (const ev of this.events()) {
      const domain = ev.domain || 'general';
      if (!rowsByDomain.has(domain)) rowsByDomain.set(domain, []);
      rowsByDomain.get(domain)!.push(ev);
    }

    const metaByDomain = new Map<string, PhaseMeta[]>();
    for (const meta of this.phaseMeta()) {
      if (!metaByDomain.has(meta.domain)) metaByDomain.set(meta.domain, []);
      metaByDomain.get(meta.domain)!.push(meta);
    }

    const domains = new Set([...rowsByDomain.keys(), ...metaByDomain.keys()]);
    return [...domains].map(domain => {
      const rows = rowsByDomain.get(domain) || [];
      const announced = metaByDomain.get(domain) || [];

      // Every phase index seen for this domain, from announcements or tool rows.
      const indices = new Set<number>([
        ...announced.map(meta => meta.index),
        ...rows.map(row => row.phase_index ?? 0),
      ]);

      const phases: PhaseGroup[] = [...indices].sort((a, b) => a - b).map(index => {
        const phaseRows = rows.filter(row => (row.phase_index ?? 0) === index);
        // Prefer the engine's own announcement: handoff events carry a phase
        // label that does not always match the phase definition.
        const name = announced.find(meta => meta.index === index)?.name
          || phaseRows.find(row => !!row.phase)?.phase
          || `Phase ${index}`;
        const done = phaseRows.filter(row => ScanProgressComponent.TERMINAL.includes(row.status)).length;
        const total = phaseRows.length;
        return {
          index, name, rows: phaseRows, done, total,
          percent: total ? Math.round((done / total) * 100) : 0,
          running: phaseRows.some(row => row.status === 'running'),
        };
      });

      const done = phases.reduce((sum, phase) => sum + phase.done, 0);
      const total = phases.reduce((sum, phase) => sum + phase.total, 0);
      return {
        domain, phases, done, total,
        percent: total ? Math.round((done / total) * 100) : 0,
        running: phases.some(phase => phase.running),
      };
    });
  });

  private es?: EventSource;
  private readonly statusCheck: ReturnType<typeof poll<import('../../core/models').Scan>>;

  constructor(private route: ActivatedRoute, private api: ApiService, private zone: NgZone) {
    this.scanId = this.route.snapshot.paramMap.get('id')!;

    // SSE carries the live detail; this poll is the safety net for a dropped or
    // proxied-away stream. It stops once the scan is terminal and never runs
    // while the tab is hidden.
    this.statusCheck = poll({
      request: () => this.api.getScan(this.scanId),
      intervalMs: 5000,
      while: () => !this.done(),
    });
    effect(() => {
      const scan = this.statusCheck.value();
      if (!scan) return;
      this.totalTools.update(current => Math.max(current, scan.tools?.length || 0));
      if (['completed', 'failed', 'cancelled'].includes(scan.status)) this.markDone(scan.status);
    }, { allowSignalWrites: true });

    // Close the stream with the component even if the scan never terminates.
    inject(DestroyRef).onDestroy(() => this.es?.close());
  }

  ngOnInit() {
    this.openStream();
  }

  ngOnDestroy() {
    this.es?.close();
  }

  cancelScan() {
    if (this.done() || this.cancelling()) return;
    if (!confirm('Cancel this scan? Running tools will be stopped.')) return;
    this.cancelling.set(true);
    this.api.cancelScan(this.scanId).subscribe({
      next: () => { this.cancelling.set(false); this.markDone('cancelled'); },
      error: () => { this.cancelling.set(false); },
    });
  }

  private openStream() {
    this.es?.close();
    this.es = new EventSource(this.api.progressStreamUrl(this.scanId));

    // EventSource is not patched by zone.js, so its callbacks fire outside the
    // Angular zone and signal writes would not trigger change detection — the
    // progress UI would only repaint on some other zone event (or at scan end).
    // Re-enter the zone so every streamed event renders live.
    this.es.onmessage = (e) => {
      if (!e.data || e.data === '{}') return;
      this.zone.run(() => {
        try {
          const raw = JSON.parse(e.data);
          if (raw.heartbeat) return;
          this.applyEvent(raw as ScanProgressEvent);
        } catch {}
      });
    };

    // Never mark the scan complete just because SSE had a network/proxy hiccup;
    // the status poll above is the authority on whether the scan actually ended.
    this.es.onerror = () => this.zone.run(() => this.statusCheck.refresh());
  }

  private applyEvent(ev: ScanProgressEvent) {
    if (ev.overall_total_tools) {
      this.completedTools.set(ev.overall_completed_tools || 0);
      this.totalTools.set(ev.overall_total_tools);
    }

    if (ev.tool === '__phase__') {
      if (ev.status === 'running' || ev.status === 'done') this.currentPhase.set(ev.message);
      this.phaseToolDone.set(ev.completed_tools || 0);
      this.phaseToolTotal.set(ev.total_tools || this.phaseToolTotal());
      this.recordPhase(ev);
      return;
    }

    if (ev.total_tools) {
      this.phaseToolDone.set(ev.completed_tools || 0);
      this.phaseToolTotal.set(ev.total_tools);
    }

    if (ev.tool === '__domain__') return;

    if (ev.tool === '__scan__') {
      if (['completed', 'failed', 'cancelled'].includes(ev.status)) {
        this.markDone(ev.status);
      }
      return;
    }

    this.upsertEvent(ev);
    if (!ev.overall_total_tools) this.recalculateFinishedTools();
  }

  /** Remember a phase the engine announced, so its card renders in order even
   *  when no tool in it was selected. */
  private recordPhase(ev: ScanProgressEvent): void {
    const domain = ev.domain || 'general';
    const index = ev.phase_index ?? 0;
    const name = ev.phase || ev.message || `Phase ${index}`;
    this.phaseMeta.update(all => {
      const at = all.findIndex(meta => meta.domain === domain && meta.index === index);
      const next = { domain, index, name, status: ev.status };
      if (at < 0) return [...all, next];
      const copy = [...all];
      copy[at] = next;
      return copy;
    });
  }

  private upsertEvent(ev: ScanProgressEvent) {
    const row = { ...ev, key: this.eventKey(ev) } as ProgressRow;
    this.events.update(evs => {
      const idx = evs.findIndex(x => x.key === row.key);
      if (idx >= 0) {
        const copy = [...evs];
        copy[idx] = row;
        return copy;
      }
      return [...evs, row];
    });
  }

  private eventKey(ev: ScanProgressEvent): string {
    return `${ev.domain || ''}:${ev.phase_index || 0}:${ev.tool}`;
  }

  private recalculateFinishedTools() {
    const terminal = new Set(['done', 'error', 'skipped', 'completed', 'failed', 'cancelled']);
    const handoff = new Set(['subdomain-merge', 'alive-subdomains', 'alive-urls']);
    const rows = this.events().filter(e => !e.tool.startsWith('__') && !handoff.has(e.tool));
    const finished = rows.filter(e => terminal.has(e.status)).length;
    this.completedTools.set(finished);
    this.totalTools.set(Math.max(this.totalTools(), rows.length));
  }

  private markDone(status: string) {
    if (this.done()) return;
    this.finalStatus.set(status);
    this.done.set(true);
    this.failed.set(status === 'failed' || status === 'cancelled');
    this.es?.close();
    this.recalculateFinishedTools();
  }
}
