import { Signal, computed, signal } from '@angular/core';

export type SortDirection = 'asc' | 'desc';
export interface SortState<K extends string> { key: K | null; direction: SortDirection; }

/**
 * Column sorting for the evidence tables.
 *
 * The global stylesheet used to put `cursor:pointer` on every `th` while
 * nothing in the app was actually sortable. This supplies the behaviour the
 * affordance was promising; `th.th-sortable` is now applied only to headers
 * wired through here.
 */
export function createSort<K extends string, T>(
  accessors: Record<K, (row: T) => string | number | null | undefined>,
  initial: SortState<K> = { key: null, direction: 'asc' },
) {
  const state = signal<SortState<K>>(initial);

  /** Cycle a column: ascending, then descending, then back to source order. */
  function toggle(key: K): void {
    state.update(current => {
      if (current.key !== key) return { key, direction: 'asc' };
      if (current.direction === 'asc') return { key, direction: 'desc' };
      return { key: null, direction: 'asc' };
    });
  }

  function indicator(key: K): string {
    const current = state();
    if (current.key !== key) return '';
    return current.direction === 'asc' ? '▲' : '▼';
  }

  /** aria-sort value for the header cell. */
  function ariaSort(key: K): 'ascending' | 'descending' | 'none' {
    const current = state();
    if (current.key !== key) return 'none';
    return current.direction === 'asc' ? 'ascending' : 'descending';
  }

  function apply(rows: readonly T[]): T[] {
    const { key, direction } = state();
    if (!key) return [...rows];
    const read = accessors[key];
    const sign = direction === 'asc' ? 1 : -1;
    // Stable: equal values keep their incoming order, so sorting a live table
    // does not reshuffle rows on every refresh.
    return rows
      .map((row, index) => ({ row, index }))
      .sort((a, b) => compare(read(a.row), read(b.row)) * sign || a.index - b.index)
      .map(entry => entry.row);
  }

  function sorted(source: Signal<readonly T[]>) {
    return computed(() => apply(source()));
  }

  return { state: state.asReadonly(), toggle, indicator, ariaSort, apply, sorted };
}

function compare(a: string | number | null | undefined, b: string | number | null | undefined): number {
  const aMissing = a === null || a === undefined || a === '';
  const bMissing = b === null || b === undefined || b === '';
  if (aMissing && bMissing) return 0;
  // Blanks sort last in both directions so they never crowd out real values.
  if (aMissing) return 1;
  if (bMissing) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}
