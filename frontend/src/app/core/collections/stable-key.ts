/** The synthetic identity attached by {@link withStableKeys}. */
export const ROW_KEY = '_key';

export type Keyed<T> = T & { [ROW_KEY]: string };

/**
 * Attach a stable, collision-free identity to rows that arrive without one.
 *
 * Tool output is raw JSON with no server-assigned ids, so the result views
 * tracked rows by `$index`. That makes a row's identity its position: when a
 * live scan prepends new evidence, every row below it is treated as changed and
 * Angular rebuilds the whole list — losing text selection and scroll position
 * on a table the analyst is reading.
 *
 * Tracking by a natural key alone is not an option either, because duplicates
 * are legitimate (the same URL seen by two sources) and a repeated track key is
 * a hard error in Angular's `@for`. So duplicates get an occurrence suffix:
 * unique within the list, and stable across refreshes as long as the backend's
 * ordering is deterministic, which it is.
 */
export function withStableKeys<T extends object>(
  rows: readonly T[], natural: (row: T) => string,
): Keyed<T>[] {
  const seen = new Map<string, number>();
  return rows.map(row => {
    const base = natural(row) || 'row';
    const occurrence = seen.get(base) ?? 0;
    seen.set(base, occurrence + 1);
    return {
      ...row,
      [ROW_KEY]: occurrence === 0 ? base : `${base}#${occurrence}`,
    } as Keyed<T>;
  });
}

/** Join the parts of a composite natural key, skipping blanks. */
export function keyOf(...parts: unknown[]): string {
  return parts.map(part => (part === null || part === undefined ? '' : String(part))).join('|');
}
