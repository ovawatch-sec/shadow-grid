import { Component } from '@angular/core';
import { RouterOutlet, RouterLink, RouterLinkActive } from '@angular/router';

@Component({
  selector: 'sg-root',
  standalone: true,
  imports: [RouterOutlet, RouterLink, RouterLinkActive],
  template: `
    <div class="shell">
      <header class="topbar">
        <div class="logo">
          <div class="logo-hex">&#x2B21;</div>
          <span>SHADOW<span class="logo-accent">GRID</span></span>
        </div>
        <div class="topbar-sep"></div>
        <nav class="topbar-nav">
          <a class="nav-link" routerLink="/projects" routerLinkActive="active">Projects</a>
          <a class="nav-link" routerLink="/settings" routerLinkActive="active">Settings</a>
        </nav>
      </header>
      <main class="main-content">
        <router-outlet />
      </main>
    </div>
  `,
  styles: [`.shell{display:flex;flex-direction:column;min-height:100vh}
.topbar{position:sticky;top:0;z-index:100;height:var(--topbar-h);
background:rgba(6,12,22,.96);backdrop-filter:blur(12px);
border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 24px;gap:16px}
.logo{display:flex;align-items:center;gap:10px;font-family:var(--font-display);
font-size:13px;font-weight:900;letter-spacing:.12em;color:var(--text);white-space:nowrap}
.logo-hex{width:30px;height:30px;display:flex;align-items:center;justify-content:center;
background:rgba(0,232,122,.1);border:1px solid var(--accent);
clip-path:polygon(50% 0%,100% 25%,100% 75%,50% 100%,0% 75%,0% 25%);
color:var(--accent);font-size:14px}
.logo-accent{color:var(--accent)}
.topbar-sep{width:1px;height:28px;background:var(--border);flex-shrink:0}
.topbar-nav{display:flex;gap:4px}
.nav-link{padding:6px 14px;border-radius:var(--radius);font-family:var(--font-head);
font-size:13px;font-weight:500;color:var(--text-dim);transition:all 150ms;text-decoration:none}
.nav-link:hover{color:var(--text);background:var(--bg-elevated)}
.nav-link.active{color:var(--accent);background:rgba(0,232,122,.1)}
.main-content{flex:1}`]
})
export class AppComponent {}
