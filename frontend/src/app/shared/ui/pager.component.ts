import { ChangeDetectionStrategy, Component, computed, input, output } from '@angular/core';

/** Page control for the large evidence tables. */
@Component({
  selector: 'sg-pager',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    @if (totalPages() > 1) {
      <div class="pagination">
        <button class="page-btn" type="button" (click)="go(page() - 1)"
          [disabled]="page() === 0" aria-label="Previous page">‹</button>
        <span aria-live="polite">{{page() + 1}} / {{totalPages()}}</span>
        <button class="page-btn" type="button" (click)="go(page() + 1)"
          [disabled]="page() >= totalPages() - 1" aria-label="Next page">›</button>
      </div>
    }
  `,
})
export class PagerComponent {
  /** Zero-based. */
  page = input.required<number>();
  totalPages = input.required<number>();
  pageChange = output<number>();

  go(next: number): void {
    const clamped = Math.max(0, Math.min(next, this.totalPages() - 1));
    if (clamped !== this.page()) this.pageChange.emit(clamped);
  }
}
