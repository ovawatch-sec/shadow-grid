import { Component } from "@angular/core";
import { RouterOutlet, RouterLink, RouterLinkActive } from "@angular/router";

@Component({
  selector: "sg-root",
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="shell">
      <header class="topbar">
        <div class="logo">
          <div class="logo-div">
            <img class="logo-img" src="../assets/shadow-grid-logo-trans.png" />
          </div>
          <span>SHADOW<span class="logo-accent">GRID</span></span>
        </div>
        <div class="topbar-sep"></div>
        <nav class="topbar-nav">
          <a class="nav-link" routerLink="/projects" routerLinkActive="active"
            >Projects</a
          >
          <a class="nav-link" routerLink="/settings" routerLinkActive="active"
            >Settings</a
          >
        </nav>
      </header>
      <main class="main-content">
        <router-outlet />
      </main>
    </div>
  `,
  styles: [
    `
      .shell {
        display: flex;
        flex-direction: column;
        min-height: 100vh;
      }
      .topbar {
        position: sticky;
        top: 0;
        z-index: 100;
        height: var(--topbar-h);
        background: rgba(6, 12, 22, 0.96);
        backdrop-filter: blur(12px);
        border-bottom: 1px solid var(--border);
        display: flex;
        align-items: center;
        padding: 0 24px;
        gap: 16px;
      }
      .logo {
        display: flex;
        align-items: center;
        gap: 10px;
        font-family: var(--font-display);
        font-size: 13px;
        font-weight: 900;
        letter-spacing: 0.12em;
        color: var(--text);
        white-space: nowrap;
      }
      .logo-img {
        width: 50px;
        height: 50px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 14px;
      }
      .logo-accent {
        color: var(--accent);
      }

      .topbar-sep {
        width: 1px;
        height: 28px;
        background: var(--border);
        flex-shrink: 0;
      }
      .topbar-nav {
        display: flex;
        gap: 4px;
      }
      .nav-link {
        padding: 6px 14px;
        border-radius: var(--radius);
        font-family: var(--font-head);
        font-size: 13px;
        font-weight: 500;
        color: var(--text-dim);
        transition: all 150ms;
        text-decoration: none;
      }
      .nav-link:hover {
        color: var(--text);
        background: var(--bg-elevated);
      }
      .nav-link.active {
        color: var(--accent);
        background: rgba(0, 232, 122, 0.1);
      }
      .main-content {
        flex: 1;
      }
    `,
  ],
})
export class AppComponent {}
