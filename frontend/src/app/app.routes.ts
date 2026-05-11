
import { Routes } from '@angular/router';

export const routes: Routes = [
  { path: '', redirectTo: 'projects', pathMatch: 'full' },
  {
    path: 'projects',
    loadComponent: () => import('./features/projects/projects.component').then(m => m.ProjectsComponent),
  },
  {
    path: 'projects/:id',
    loadComponent: () => import('./features/projects/project-detail.component').then(m => m.ProjectDetailComponent),
  },
  {
    path: 'scan/:id/progress',
    loadComponent: () => import('./features/scan/scan-progress.component').then(m => m.ScanProgressComponent),
  },
  {
    path: 'scan/:scanId/results',
    loadComponent: () => import('./features/results/results.component').then(m => m.ResultsComponent),
  },
  {
    path: 'settings',
    loadComponent: () => import('./features/settings/settings.component').then(m => m.SettingsComponent),
  },
  { path: '**', redirectTo: 'projects' }
];
