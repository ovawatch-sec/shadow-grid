import { Injectable, inject } from '@angular/core';
import { Observable, forkJoin } from 'rxjs';
import { map } from 'rxjs/operators';
import { ApiService } from './api.service';
import { Project, Scan } from '../models';

/** A scan paired with the program it belongs to, for cross-project views. */
export interface ActivityEntry {
  project: Project;
  scan: Scan;
}

const RUNNING = new Set(['running', 'pending']);

/**
 * Cross-program activity feed.
 *
 * This used to list the programs and then request each program's scans, so a
 * poll cost 1+N requests and grew with the install. It is now two parallel
 * requests regardless of how many programs exist; the join happens here.
 */
@Injectable({ providedIn: 'root' })
export class ScanActivityService {
  private api = inject(ApiService);

  /** All scans across all programs, newest first, each tagged with its program. */
  activity(): Observable<ActivityEntry[]> {
    return forkJoin({
      projects: this.api.getProjects(),
      scans: this.api.getAllScans(),
    }).pipe(
      map(({ projects, scans }) => {
        const byId = new Map(projects.map(project => [project.id, project]));
        return scans
          .filter(scan => byId.has(scan.project_id))
          .map(scan => ({ project: byId.get(scan.project_id)!, scan }))
          .sort((a, b) => b.scan.created_at.localeCompare(a.scan.created_at));
      }),
    );
  }

  static isActive(scan: Scan): boolean {
    return RUNNING.has(scan.status);
  }
}
