import { Component, computed, inject } from '@angular/core';
import { CommonModule } from '@angular/common';
import { RouterLink } from '@angular/router';
import { ScanActivityService, ActivityEntry } from '../../core/services/scan-activity.service';
import { ApiService } from '../../core/services/api.service';
import { poll } from '../../core/http/poll';
import { EmptyStateComponent, StatCardComponent } from '../../shared/ui';

/**
 * Security-posture overview. Aggregates programs and their assessments into a
 * single dashboard so the product reads as an AppSec platform rather than a
 * one-off recon tool. Polls while mounted so active assessments stay current.
 */
@Component({
  selector: 'sg-dashboard',
  standalone: true,
  imports: [CommonModule, RouterLink, StatCardComponent, EmptyStateComponent],
  template: `
    <div class="page">
      <div class="page-header">
        <div>
          <h1 class="page-title">Security Posture</h1>
          <p class="page-sub">Application-security assessments across all of your programs</p>
        </div>
        <a class="btn btn-primary" routerLink="/projects">Manage programs →</a>
      </div>

      @if (loading()) {
        <sg-empty-state loading message="Loading posture…" />
      } @else {
        <div class="stat-grid">
          <sg-stat-card label="Programs" [value]="programs()" tone="green" accent
            sub="application scopes under management" />
          <sg-stat-card label="Active assessments" [value]="active()"
            [tone]="active() > 0 ? 'orange' : 'default'" [danger]="active() > 0"
            [sub]="active() > 0 ? 'scanning now' : 'idle'" />
          <sg-stat-card label="Completed" [value]="completed()" tone="cyan" sub="finished assessments" />
          <sg-stat-card label="Known assets" [value]="portfolio()?.summary?.assets || 0">
            <div class="stat-sub"><a routerLink="/assets">open inventory</a></div>
          </sg-stat-card>
          <sg-stat-card label="Critical / high" [value]="portfolio()?.summary?.critical_high || 0"
            [tone]="(portfolio()?.summary?.critical_high || 0) > 0 ? 'red' : 'default'"
            [danger]="(portfolio()?.summary?.critical_high || 0) > 0">
            <div class="stat-sub"><a routerLink="/findings">review findings</a></div>
          </sg-stat-card>
        </div>

        <div class="section-head">
          <span class="section-title">Recent assessment activity</span>
          @if (active() > 0) { <span class="pulse-dot"></span> }
          <span class="section-count">{{entries().length}}</span>
          <div class="section-actions"><a class="btn btn-outline btn-sm" routerLink="/activity">View all</a></div>
        </div>

        @if (entries().length === 0) {
          <div class="card">
            <sg-empty-state icon="🛡️" heading="No assessments yet"
              message="Create a program, add in-scope applications, and launch your first security assessment.">
              <a class="btn btn-primary" routerLink="/projects">Create a program</a>
            </sg-empty-state>
          </div>
        } @else {
          <div class="card feed-card">
            @for (e of recent(); track e.scan.id) {
              <a class="feed-row" [routerLink]="rowLink(e)">
                <span class="badge badge-{{e.scan.status}} feed-status">{{e.scan.status}}</span>
                <span class="feed-project">{{e.project.name}}</span>
                <span class="feed-meta mono">{{e.scan.tools.length}} tools</span>
                <span class="feed-meta mono">{{e.scan.created_at | date:'MMM d, HH:mm'}}</span>
                <span class="feed-go">→</span>
              </a>
            }
          </div>
        }
      }
    </div>
  `,
  styles: [`
    .feed-card { padding:var(--space-2) 0; }
    .feed-row { display:flex; align-items:center; gap:14px; padding:11px 20px; border-bottom:1px solid var(--border); transition:background 120ms; }
    .feed-row:last-child { border-bottom:none; }
    .feed-row:hover { background:var(--bg-hover); }
    .feed-status { text-transform:capitalize; min-width:88px; justify-content:center; }
    .feed-project { font-weight:600; color:var(--text); flex:1; min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
    .feed-meta { font-size:11.5px; color:var(--text-dim); }
    .feed-go { color:var(--text-faint); }
    @media (max-width:640px){ .feed-meta { display:none; } }
  `]
})
export class DashboardComponent {
  private activityService = inject(ScanActivityService);
  private api = inject(ApiService);

  private activityPoll = poll({ request: () => this.activityService.activity(), intervalMs: 8000 });
  private portfolioPoll = poll({ request: () => this.api.getPortfolio(), intervalMs: 8000 });

  entries = computed<ActivityEntry[]>(() => this.activityPoll.value() ?? []);
  portfolio = computed(() => this.portfolioPoll.value() ?? null);
  loading = computed(() => this.activityPoll.value() === undefined && !this.activityPoll.error());

  programs = computed(() => new Set(this.entries().map(e => e.project.id)).size);
  active = computed(() => this.entries().filter(e => ScanActivityService.isActive(e.scan)).length);
  completed = computed(() => this.entries().filter(e => e.scan.status === 'completed').length);
  recent = computed(() => this.entries().slice(0, 8));

  rowLink(e: ActivityEntry): any[] {
    if (ScanActivityService.isActive(e.scan)) return ['/scan', e.scan.id, 'progress'];
    if (e.scan.status === 'completed') return ['/scan', e.scan.id, 'results'];
    return ['/projects', e.project.id];
  }
}
