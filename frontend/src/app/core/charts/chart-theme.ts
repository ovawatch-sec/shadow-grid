import {
  ArcElement, BarController, BarElement, CategoryScale, Chart, DoughnutController,
  Legend, LinearScale, Tooltip, type ChartConfiguration,
} from 'chart.js';

/**
 * Chart.js is registered explicitly rather than via `chart.js/auto`, which pulls
 * in every controller, scale and element the library ships. Only the doughnut
 * and horizontal bar used by the results view are registered here.
 */
let registered = false;
export function registerCharts(): void {
  if (registered) return;
  Chart.register(
    DoughnutController, ArcElement,
    BarController, BarElement,
    CategoryScale, LinearScale,
    Tooltip, Legend,
  );
  registered = true;
}

/**
 * Resolve a design token to its current computed value.
 *
 * Charts render to a canvas, so they cannot inherit CSS custom properties the
 * way the rest of the UI does — the values have to be read out and handed to
 * Chart.js. Reading them at render time (instead of hard-coding hex literals)
 * is what makes the charts follow the active theme.
 */
function token(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback;
  const value = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  return value || fallback;
}

export interface ChartPalette {
  severity: Record<'critical' | 'high' | 'medium' | 'low' | 'info', string>;
  accent: string;
  series: string;
  surface: string;
  text: string;
  textDim: string;
  grid: string;
}

/** Snapshot of the themed palette. Re-read whenever the theme changes. */
export function chartPalette(): ChartPalette {
  return {
    severity: {
      critical: token('--sev-critical', '#ff6b78'),
      high: token('--sev-high', '#ff9f5a'),
      medium: token('--sev-medium', '#f0c94a'),
      low: token('--sev-low', '#4cccdd'),
      info: token('--sev-info', '#9fb0c6'),
    },
    accent: token('--accent', '#00e884'),
    series: token('--chart-series', '#00c06e'),
    surface: token('--bg-card', '#0d1524'),
    text: token('--text', '#dbe6f5'),
    textDim: token('--text-dim', '#8496b0'),
    grid: token('--border', '#1d2b44'),
  };
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'] as const;
const SEVERITY_LABELS = ['Critical', 'High', 'Medium', 'Low', 'Info'];

export function severityChartConfig(counts: number[], palette: ChartPalette): ChartConfiguration<'doughnut'> {
  return {
    type: 'doughnut',
    data: {
      labels: SEVERITY_LABELS,
      datasets: [{
        data: counts,
        backgroundColor: SEVERITY_ORDER.map(level => palette.severity[level]),
        borderColor: palette.surface,
        borderWidth: 3,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '62%',
      // The canvas carries an aria-label summarising the same numbers, so the
      // chart is not the only way to reach them.
      plugins: {
        legend: { position: 'right', labels: { color: palette.text, font: { size: 11 } } },
      },
    },
  };
}

export function toolChartConfig(
  labels: string[], values: number[], palette: ChartPalette,
): ChartConfiguration<'bar'> {
  return {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Results',
        data: values,
        backgroundColor: palette.series,
        borderColor: palette.series,
        borderWidth: 1,
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { grid: { color: palette.grid }, ticks: { color: palette.textDim } },
        y: { grid: { display: false }, ticks: { color: palette.text } },
      },
    },
  };
}
