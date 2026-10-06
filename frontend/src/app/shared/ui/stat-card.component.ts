import { ChangeDetectionStrategy, Component, booleanAttribute, input } from '@angular/core';

export type StatTone = 'default' | 'green' | 'red' | 'cyan' | 'orange';

/**
 * A single headline figure.
 *
 * The same markup was hand-written in five views, which is why the accent and
 * danger treatments had drifted apart between them.
 */
@Component({
  selector: 'sg-stat-card',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="stat-card" [class.accent]="accent()" [class.danger]="danger()">
      <div class="stat-label">{{label()}}</div>
      <div class="stat-value" [class]="tone() === 'default' ? '' : tone()">{{value()}}</div>
      @if (sub()) { <div class="stat-sub">{{sub()}}</div> }
      <ng-content />
    </div>
  `,
})
export class StatCardComponent {
  label = input.required<string>();
  value = input.required<string | number>();
  tone = input<StatTone>('default');
  sub = input('');
  // booleanAttribute lets these be written as bare attributes (`accent`) as
  // well as bindings (`[accent]="expr"`).
  accent = input(false, { transform: booleanAttribute });
  danger = input(false, { transform: booleanAttribute });
}
