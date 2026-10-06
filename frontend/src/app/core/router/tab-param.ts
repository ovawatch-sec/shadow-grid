import { Signal, computed, inject } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router } from '@angular/router';
import { map } from 'rxjs/operators';

export interface TabParam<T extends string> {
  /** The active tab, derived from the URL. */
  readonly active: Signal<T>;
  /** Navigate to a tab. The URL is the single source of truth, so this is the only setter. */
  select(tab: T): void;
}

/**
 * Keep tab state in a query parameter.
 *
 * Holding it in a component signal meant a view could not be linked to, the
 * back button skipped past every tab change in one jump, and a reload always
 * dropped the user back on the first tab. Deriving the active tab from the URL
 * makes the address bar the single source of truth, so all three fall out for
 * free. An unknown or absent value resolves to the fallback, so a hand-edited
 * link cannot render an empty view.
 */
export function tabParam<T extends string>(
  valid: readonly T[], fallback: T, param = 'tab',
): TabParam<T> {
  const route = inject(ActivatedRoute);
  const router = inject(Router);
  const allowed = new Set<string>(valid);

  const raw = toSignal(route.queryParamMap.pipe(map(params => params.get(param))), {
    initialValue: route.snapshot.queryParamMap.get(param),
  });

  return {
    active: computed(() => {
      const value = raw();
      return value && allowed.has(value) ? (value as T) : fallback;
    }),
    select(tab: T): void {
      router.navigate([], {
        relativeTo: route,
        // Other query params (the portfolio's `project` filter, for instance)
        // have to survive a tab change.
        queryParams: { [param]: tab === fallback ? null : tab },
        queryParamsHandling: 'merge',
      });
    },
  };
}
