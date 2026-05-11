
import { Component, OnInit, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { ApiService } from '../../core/services/api.service';
import { StorageConfig } from '../../core/models';

@Component({
  selector: 'sg-settings',
  standalone: true,
  imports: [CommonModule, FormsModule],
  template: `
    <div class="page">
      <h1 class="page-title">Settings</h1>
      <p class="page-sub" style="margin-bottom:28px">Configure storage and framework options</p>

      <div class="card" style="max-width:640px">
        <h3 style="font-family:var(--font-head);font-weight:600;margin-bottom:4px">Azure Table Storage</h3>
        <p style="font-size:12px;color:var(--text-dim);margin-bottom:20px">Optional — results are always saved to disk. Enable Azure for additional cloud backup and multi-instance sync.</p>

        <label class="toggle-row" style="margin-bottom:20px">
          <span>Enable Azure Table Storage</span>
          <input type="checkbox" [(ngModel)]="cfg.azure_enabled" />
        </label>

        @if (cfg.azure_enabled) {
          <div class="form-group">
            <label class="form-label">Connection String (preferred)</label>
            <input class="form-input" [(ngModel)]="cfg.connection_string" placeholder="DefaultEndpointsProtocol=https;AccountName=…" />
          </div>
          <p style="font-size:11px;color:var(--text-faint);margin:-12px 0 16px;text-align:center">— OR use account name + key —</p>
          <div class="form-group">
            <label class="form-label">Account Name</label>
            <input class="form-input" [(ngModel)]="cfg.account_name" placeholder="mystorageaccount" />
          </div>
          <div class="form-group">
            <label class="form-label">Account Key</label>
            <input class="form-input" type="password" [(ngModel)]="cfg.account_key" placeholder="••••••••" />
          </div>
          <div class="form-group">
            <label class="form-label">Table Prefix</label>
            <input class="form-input" [(ngModel)]="cfg.table_prefix" placeholder="shadowgrid" />
            <span style="font-size:11px;color:var(--text-dim)">Tables: {{cfg.table_prefix}}Projects, {{cfg.table_prefix}}Targets, {{cfg.table_prefix}}Scans, {{cfg.table_prefix}}Results</span>
          </div>
        }

        @if (saved()) {
          <div class="alert alert-success" style="margin-bottom:16px">✓ Configuration saved</div>
        }
        @if (error()) {
          <div class="alert alert-danger" style="margin-bottom:16px">✗ {{error()}}</div>
        }

        <button class="btn btn-primary" (click)="save()" [disabled]="saving()">
          @if (saving()) { <span class="spinner-sm"></span> }
          Save Configuration
        </button>
      </div>

      <div class="card" style="max-width:640px;margin-top:16px">
        <h3 style="font-family:var(--font-head);font-weight:600;margin-bottom:16px">About</h3>
        <div class="about-row"><span>Version</span><span class="mono">3.0.0</span></div>
        <div class="about-row"><span>Storage</span><span class="mono">File (always) + Azure (optional)</span></div>
        <div class="about-row"><span>Output Directory</span><span class="mono">/app/output</span></div>
        <div class="about-row"><span>Data Directory</span><span class="mono">/app/data</span></div>
      </div>
    </div>
  `,
  styles: [`
    .page { padding:32px; max-width:1200px; margin:0 auto; }
    .page-title { font-family:var(--font-head); font-size:24px; font-weight:700; }
    .toggle-row { display:flex; align-items:center; justify-content:space-between; cursor:pointer; }
    input[type=checkbox] { width:18px; height:18px; accent-color:var(--accent); }
    .about-row { display:flex; justify-content:space-between; padding:8px 0; border-bottom:1px solid var(--border); font-size:13px; }
    .about-row:last-child { border-bottom:none; }
  `]
})
export class SettingsComponent implements OnInit {
  cfg: StorageConfig = { azure_enabled:false, connection_string:'', account_name:'', account_key:'', table_prefix:'shadowgrid' };
  saving = signal(false);
  saved = signal(false);
  error = signal('');

  constructor(private api: ApiService) {}

  ngOnInit() {
    this.api.getStorageConfig().subscribe(c => { this.cfg = { ...c, account_key: '' }; });
  }

  save() {
    this.saving.set(true); this.saved.set(false); this.error.set('');
    this.api.saveStorageConfig(this.cfg).subscribe({
      next: () => { this.saving.set(false); this.saved.set(true); setTimeout(() => this.saved.set(false), 3000); },
      error: e => { this.saving.set(false); this.error.set(e.message || 'Save failed'); },
    });
  }
}
