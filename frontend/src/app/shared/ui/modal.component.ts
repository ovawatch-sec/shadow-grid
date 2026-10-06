import {
  AfterViewInit, ChangeDetectionStrategy, Component, ElementRef, HostListener,
  OnDestroy, inject, input, output, viewChild,
} from '@angular/core';

const FOCUSABLE = [
  'a[href]', 'button:not([disabled])', 'input:not([disabled])',
  'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
].join(',');

let dialogSeq = 0;

/**
 * Modal dialog with the behaviour the hand-rolled backdrops were missing:
 * Escape to dismiss, focus moved in on open and restored on close, and Tab
 * cycling kept inside the dialog so a keyboard user cannot land on the page
 * behind it while it is still covering the screen.
 */
@Component({
  selector: 'sg-modal',
  standalone: true,
  changeDetection: ChangeDetectionStrategy.OnPush,
  template: `
    <div class="modal-backdrop" (click)="dismiss()">
      <div #card class="modal-card" (click)="$event.stopPropagation()"
        role="dialog" aria-modal="true" [attr.aria-labelledby]="titleId">
        <h3 [id]="titleId">{{heading()}}</h3>
        <ng-content />
      </div>
    </div>
  `,
})
export class ModalComponent implements AfterViewInit, OnDestroy {
  heading = input.required<string>();
  closed = output<void>();

  protected readonly titleId = `sg-dialog-${++dialogSeq}`;
  private card = viewChild.required<ElementRef<HTMLElement>>('card');
  private host = inject(ElementRef<HTMLElement>);
  private previouslyFocused: HTMLElement | null = null;

  ngAfterViewInit(): void {
    this.previouslyFocused = document.activeElement as HTMLElement | null;
    const first = this.card().nativeElement.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? this.card().nativeElement).focus({ preventScroll: true });
  }

  ngOnDestroy(): void {
    this.previouslyFocused?.focus({ preventScroll: true });
  }

  @HostListener('document:keydown.escape')
  dismiss(): void {
    this.closed.emit();
  }

  /** Keep Tab inside the dialog while it is open. */
  @HostListener('document:keydown.tab', ['$event'])
  @HostListener('document:keydown.shift.tab', ['$event'])
  onTab(event: KeyboardEvent): void {
    const items = Array.from(this.card().nativeElement.querySelectorAll<HTMLElement>(FOCUSABLE))
      .filter(el => el.offsetParent !== null);
    if (items.length === 0) {
      event.preventDefault();
      return;
    }
    const first = items[0];
    const last = items[items.length - 1];
    const active = document.activeElement as HTMLElement | null;
    const inside = this.host.nativeElement.contains(active);

    if (event.shiftKey && (active === first || !inside)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && (active === last || !inside)) {
      event.preventDefault();
      first.focus();
    }
  }
}
