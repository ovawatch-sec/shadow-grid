
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { Project, Target, Scan, ToolResult, ToolInfo, StorageConfig, ToolApiKeysConfig } from '../models';

@Injectable({ providedIn: 'root' })
export class ApiService {
  private base = '/api';

  constructor(private http: HttpClient) {}

  // ── Projects ──────────────────────────────────────────────────
  getProjects(): Observable<Project[]> {
    return this.http.get<Project[]>(`${this.base}/projects/`);
  }
  getProject(id: string): Observable<Project> {
    return this.http.get<Project>(`${this.base}/projects/${id}`);
  }
  createProject(name: string, description: string): Observable<Project> {
    return this.http.post<Project>(`${this.base}/projects/`, { name, description });
  }
  deleteProject(id: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/projects/${id}`);
  }

  // ── Targets ───────────────────────────────────────────────────
  getTargets(projectId: string): Observable<Target[]> {
    return this.http.get<Target[]>(`${this.base}/projects/${projectId}/targets`);
  }
  addTarget(projectId: string, domain: string, isOos = false): Observable<Target> {
    return this.http.post<Target>(`${this.base}/projects/${projectId}/targets`, { domain, is_oos: isOos });
  }
  deleteTarget(projectId: string, targetId: string): Observable<void> {
    return this.http.delete<void>(`${this.base}/projects/${projectId}/targets/${targetId}`);
  }

  // ── Scans ─────────────────────────────────────────────────────
  startScan(projectId: string, tools: string[], wordlist?: string): Observable<Scan> {
    return this.http.post<Scan>(`${this.base}/scans/`, { project_id: projectId, tools, wordlist });
  }
  getScans(projectId: string): Observable<Scan[]> {
    return this.http.get<Scan[]>(`${this.base}/scans/${projectId}/list`);
  }
  getScan(scanId: string): Observable<Scan> {
    return this.http.get<Scan>(`${this.base}/scans/${scanId}`);
  }

  // ── Results ───────────────────────────────────────────────────
  getResults(scanId: string): Observable<ToolResult[]> {
    return this.http.get<ToolResult[]>(`${this.base}/results/${scanId}`);
  }
  getResultsSummary(scanId: string): Observable<any> {
    return this.http.get<any>(`${this.base}/results/${scanId}/summary`);
  }

  // ── Tools ─────────────────────────────────────────────────────
  getTools(): Observable<ToolInfo[]> {
    return this.http.get<ToolInfo[]>(`${this.base}/tools/`);
  }

  // ── Settings ──────────────────────────────────────────────────
  getStorageConfig(): Observable<StorageConfig> {
    return this.http.get<StorageConfig>(`${this.base}/settings/storage`);
  }
  saveStorageConfig(cfg: StorageConfig): Observable<any> {
    return this.http.post<any>(`${this.base}/settings/storage`, cfg);
  }
  getToolApiKeys(): Observable<ToolApiKeysConfig> {
    return this.http.get<ToolApiKeysConfig>(`${this.base}/settings/api-keys`);
  }
  saveToolApiKeys(cfg: ToolApiKeysConfig): Observable<any> {
    return this.http.post<any>(`${this.base}/settings/api-keys`, cfg);
  }
}
