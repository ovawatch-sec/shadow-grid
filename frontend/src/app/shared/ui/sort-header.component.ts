import { ChangeDetectionStrategy, Component, input, output } from '@angular/core';

/**
 * A sortable column header.
 *
 * The control is a real button rather than a click handler on the `th`, so the
 * column can be sorted from the keyboard and is announced as actionable;
 * `aria-sort` reports the current direction on the header cell itself.
 */
@Component({
  selector: 'th[sgSort]',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  host: {
    class: 'th-sortable',
    scope: 'col',
    '[attr.aria-sort]': 'ariaSort()',
  },
  template: `
    <button type="button" class="th-sort-btn" (click)="sort.emit()">
      <ng-content />
      <span class="sort-ind" aria-hidden="true">{{indicator()}}</span>
    </button>
  `,
})
export class SortHeaderComponent {
  indicator = input('');
  ariaSort = input<'ascending' | 'descending' | 'none'>('none');
  sort = output<void>();
}
