import { DestroyRef, inject, signal, type Signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { EMPTY, Observable, Subject, fromEvent, merge, timer } from 'rxjs';
import { catchError, exhaustMap, filter, map } from 'rxjs/operators';

export interface PollConfig<T> {
  /** Builds a fresh request. Called once per tick. */
  request: () => Observable<T>;
  intervalMs: number;
  /**
   * Gates *repeat* ticks only. The first fetch always runs, because the
   * predicate usually depends on data that first fetch is what supplies — a
   * view that polls `while: () => isLive()` cannot know whether the scan is
   * live until it has loaded it once.
   */
  while?: () => boolean;
}

export interface Poll<T> {
  value: Signal<T | undefined>;
  error: Signal<unknown>;
  loading: Signal<boolean>;
  /** Fetch now, regardless of the interval or the `while` predicate. */
  refresh(): void;
}

/**
 * Interval polling that does not pile up, leak, or run in the background.
 *
 * Three properties the hand-rolled `setInterval` loops did not have:
 *
 * - **No overlap.** `exhaustMap` drops a tick that lands while a request is
 *   still in flight, so a slow backend cannot accumulate a queue of requests
 *   that all resolve at once and fight over the same signal.
 * - **Cancellation.** `takeUntilDestroyed` unsubscribes with the component.
 *   The previous `clearInterval` in `ngOnDestroy` stopped new requests but left
 *   any in-flight response to resolve against a dead view.
 * - **No work while hidden.** Ticks are suppressed while the tab is in the
 *   background and a fetch runs immediately on return, so a dashboard left open
 *   in a spare tab stops hammering the API.
 */
export function poll<T>(config: PollConfig<T>): Poll<T> {
  const destroyRef = inject(DestroyRef);
  const value = signal<T | undefined>(undefined);
  const error = signal<unknown>(null);
  const loading = signal(true);
  const manual = new Subject<void>();

  const visible = () => typeof document === 'undefined' || !document.hidden;
  const due = () => visible() && (config.while?.() ?? true);

  const ticks = timer(0, config.intervalMs).pipe(
    filter((tick, index) => index === 0 || due()),
    map(() => undefined),
  );
  const resumed = typeof document === 'undefined'
    ? EMPTY
    : fromEvent(document, 'visibilitychange').pipe(filter(due), map(() => undefined));

  merge(ticks, resumed, manual)
    .pipe(
      exhaustMap(() => {
        loading.set(true);
        return config.request().pipe(catchError(cause => {
          error.set(cause);
          loading.set(false);
          return EMPTY;
        }));
      }),
      takeUntilDestroyed(destroyRef),
    )
    .subscribe(next => {
      value.set(next);
      error.set(null);
      loading.set(false);
    });

  return {
    value: value.asReadonly(),
    error: error.asReadonly(),
    loading: loading.asReadonly(),
    refresh: () => manual.next(),
  };
}
