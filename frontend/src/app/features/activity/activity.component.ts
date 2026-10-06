import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ScanActivityService, ActivityEntry } from '../../core/services/scan-activity.service';
import { poll } from '../../core/http/poll';

/**
 * Cross-program scan activity board. Concurrent assessments render as discrete
 * status cards — active ones grouped and highlighted, recent ones below — so
 * scanning many domains at once stays legible instead of stacking into a wall
 * of rows. Polls while mounted to reflect completions live.
 */
@Component({
  selector: 'sg-activity',
  standalone: true,
  imports: [CommonModule, RouterLink],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1 class="page-title">Assessments</h1>
          <p class="page-sub">Live and recent security assessments across every program</p>
        </div>
        <button class="btn btn-outline btn-sm" (click)="load()">
          <span [class.spin]="loading()" aria-hidden="true">⟳</span> Refresh
        </button>
      </div>

      @if (loading() && entries().length === 0) {
        <div class="empty-state"><div class="spinner-sm"></div><span>Loading activity…</span></div>
      } @else if (entries().length === 0) {
        <div class="card"><div class="empty-state">
          <div class="empty-icon">📡</div>
          <h3>No scan activity</h3>
          <p>Launch an assessment from any program to see it tracked here in real time.</p>
          <a class="btn btn-primary" routerLink="/projects">Go to programs</a>
        </div></div>
      } @else {
        @if (activeEntries().length > 0) {
          <div class="section-head">
            <span class="pulse-dot"></span>
            <span class="section-title">Running now</span>
            <span class="section-count">{{activeEntries().length}}</span>
          </div>
          <div class="scan-grid">
            @for (e of activeEntries(); track e.scan.id) {
              <div class="scan-card active">
                <div class="sc-top">
                  <span class="badge badge-{{e.scan.status}}">{{e.scan.status}}</span>
                  <span class="sc-id mono">{{e.scan.id.slice(0,8)}}</span>
                </div>
                <a class="sc-project" [routerLink]="['/projects', e.project.id]">{{e.project.name}}</a>
                <div class="sc-meta mono">{{e.scan.tools.length}} tools · started {{e.scan.started_at || e.scan.created_at | date:'HH:mm'}}</div>
                <div class="sc-actions">
                  <a class="btn btn-primary btn-sm" [routerLink]="['/scan', e.scan.id, 'progress']">Live progress</a>
                  <a class="btn btn-outline btn-sm" [routerLink]="['/scan', e.scan.id, 'results']">Results so far</a>
                </div>
              </div>
            }
          </div>
        }

        <div class="section-head section-head--spaced">
          <span class="section-title">Recent</span>
          <span class="section-count">{{recentEntries().length}}</span>
        </div>
        @if (recentEntries().length === 0) {
          <div class="card"><div class="empty-state empty-state--sm"><p>No completed assessments yet.</p></div></div>
        } @else {
          <div class="scan-grid">
            @for (e of recentEntries(); track e.scan.id) {
              <div class="scan-card">
                <div class="sc-top">
                  <span class="badge badge-{{e.scan.status}}">{{e.scan.status}}</span>
                  <span class="sc-id mono">{{e.scan.id.slice(0,8)}}</span>
                </div>
                <a class="sc-project" [routerLink]="['/projects', e.project.id]">{{e.project.name}}</a>
                <div class="sc-meta mono">{{e.scan.tools.length}} tools · {{e.scan.completed_at || e.scan.created_at | date:'MMM d, HH:mm'}}</div>
                <div class="sc-actions">
                  @if (e.scan.status === 'completed') {
                    <a class="btn btn-primary btn-sm" [routerLink]="['/scan', e.scan.id, 'results']">View results</a>
                  } @else {
                    <a class="btn btn-outline btn-sm" [routerLink]="['/projects', e.project.id]">Open program</a>
                  }
                </div>
              </div>
            }
          </div>
        }
      }
    </div>
  `,
  styles: [`
    .scan-grid { display:grid; grid-template-columns:repeat(auto-fill,minmax(280px,1fr)); gap:14px; }
    .scan-card { background:var(--bg-card); border:1px solid var(--border); border-radius:var(--radius-lg); padding:16px 18px; display:flex; flex-direction:column; gap:9px; box-shadow:var(--shadow); transition:border-color 140ms, transform 140ms; }
    .scan-card:hover { border-color:var(--border-bright); transform:translateY(-1px); }
    .scan-card.active { border-color:var(--sev-high-border); }
    .section-head--spaced { margin-top:26px; }
    .empty-state--sm { padding:28px; }
    .sc-top { display:flex; align-items:center; justify-content:space-between; }
    .sc-top .badge { text-transform:capitalize; }
    .sc-id { font-size:11px; color:var(--text-faint); }
    .sc-project { font-family:var(--font-sans); font-size:var(--text-lg); font-weight:var(--weight-semibold); color:var(--text); overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .sc-project:hover { color:var(--accent); }
    .sc-meta { font-size:11.5px; color:var(--text-dim); }
    .sc-actions { display:flex; gap:8px; margin-top:4px; flex-wrap:wrap; }
    .spin { display:inline-block; animation:spin .7s linear infinite; }
  `]
})
export class ActivityComponent {
  private activityService = inject(ScanActivityService);
  private feed = poll({ request: () => this.activityService.activity(), intervalMs: 6000 });

  entries = computed<ActivityEntry[]>(() => this.feed.value() ?? []);
  loading = this.feed.loading;

  activeEntries = computed(() => this.entries().filter(e => ScanActivityService.isActive(e.scan)));
  recentEntries = computed(() => this.entries().filter(e => !ScanActivityService.isActive(e.scan)).slice(0, 24));

  load(): void { this.feed.refresh(); }
}
