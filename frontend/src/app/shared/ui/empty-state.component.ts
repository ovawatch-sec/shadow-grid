import { ChangeDetectionStrategy, Component, booleanAttribute, input } from '@angular/core';

/** Empty, loading, and all-clear states, which were nine near-copies before. */
@Component({
  selector: 'sg-empty-state',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="empty-state" [class.empty-ok]="tone() === 'ok'" [class.empty-state--sm]="compact()">
      @if (loading()) {
        <div class="spinner-sm"></div>
      } @else if (icon()) {
        <div class="empty-icon" [class.empty-ok-glyph]="tone() === 'ok'" aria-hidden="true">{{icon()}}</div>
      }
      @if (heading()) { <h3>{{heading()}}</h3> }
      @if (message()) { <p>{{message()}}</p> }
      <ng-content />
    </div>
  `,
})
export class EmptyStateComponent {
  icon = input('');
  heading = input('');
  message = input('');
  loading = input(false, { transform: booleanAttribute });
  compact = input(false, { transform: booleanAttribute });
  /** 'ok' renders the accent treatment used for "nothing found, and that's good". */
  tone = input<'muted' | 'ok'>('muted');
}
