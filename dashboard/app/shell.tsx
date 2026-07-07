"use client";

import { useState } from "react";

export default function ClientShell({ children }: { children: React.ReactNode }) {
  const [activeSb, setActiveSb] = useState("Logs");

  const SbItem = ({
    name,
    badge,
    badgeClass,
    icon,
  }: {
    name: string;
    badge?: string;
    badgeClass?: string;
    icon: React.ReactNode;
  }) => (
    <div
      className={`sb-item${activeSb === name ? " active" : ""}`}
      onClick={() => setActiveSb(name)}
    >
      {icon}
      {name}
      {badge && <span className={`sb-badge ${badgeClass}`}>{badge}</span>}
    </div>
  );

  return (
    <div id="APP">
      <div id="NAV">
        <div id="nav-left">
          <div id="nav-logo">
            <div className="nl-shield">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none">
                <path d="M12 2L3 6.5V12c0 5.5 3.8 10.7 9 12 5.2-1.3 9-6.5 9-12V6.5L12 2z" stroke="#3b82f6" strokeWidth="1.5" fill="rgba(59,130,246,0.1)" />
                <path d="M8.5 12l2.5 2.5 4.5-4.5" stroke="#60a5fa" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
              </svg>
            </div>
            <div><div className="nl-brand">Next-Gen ESDS WAF</div></div>
            <div className="nl-ver">v4.2.1</div>
          </div>
          <div className="nav-link">Documentation</div>
          <div className="nav-link">Github</div>
          <div className="nav-link">Discord</div>
        </div>
        <div id="nav-right">
          <div className="nb-status"><div className="nb-sdot"></div>Operational</div>
          <div className="nb-badge nb-notif">ALERTS</div>
          <div className="nb-badge nb-news">NEWS</div>
        </div>
      </div>

      <div id="LAYOUT">
        <div id="SIDE">
          <div className="sb-section">Main</div>
          <SbItem name="Dashboard" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>
          } />
          <SbItem name="Global Settings" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="2"/><path d="M12 6v-2M12 20v-2M6 12H4M20 12h-2M7.05 7.05L5.64 5.64M18.36 18.36l-1.41-1.41M7.05 16.95l-1.41 1.41M18.36 5.64l-1.41 1.41"/></svg>
          } />
          <SbItem name="Services" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
          } />
          <SbItem name="Configs" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"/></svg>
          } />
          <SbItem name="Templates" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M4 5h16M4 12h16M4 19h16"/></svg>
          } />
          <SbItem name="Plugins" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
          } />
          <SbItem name="Cache" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.22 4.22l2.83 2.83M16.95 16.95l2.83 2.83M1 12h4M19 12h4M4.22 19.78l2.83-2.83M16.95 7.05l2.83-2.83"/></svg>
          } />
          <SbItem name="Reports" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          } />
          <SbItem name="Bans" badge="24" badgeClass="sbb-r" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>
          } />
          <SbItem name="Jobs" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 00-2-2h-4a2 2 0 00-2 2v16"/></svg>
          } />

          <div className="sb-section">Operations</div>
          <SbItem name="Logs" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
          } />

          <div className="sb-divider"></div>
          <div className="sb-extra">Extra Pages</div>
          <SbItem name="Letsencrypt" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
          } />

          <div className="sb-extra">Plugin Pages</div>
          <SbItem name="ACME" badge="ON" badgeClass="sbb-g" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M9 3H5a2 2 0 00-2 2v4m6-6h10a2 2 0 012 2v4M9 3v18m0 0h10a2 2 0 002-2V9M9 21H5a2 2 0 01-2-2V9m0 0h18"/></svg>
          } />
          <SbItem name="Antibot" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>
          } />
          <SbItem name="Anti DDoS" badge="XDP" badgeClass="sbb-p" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>
          } />
          <SbItem name="Auth basic" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"/></svg>
          } />
          <SbItem name="Backup" icon={
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M8 7H5a2 2 0 00-2 2v9a2 2 0 002 2h14a2 2 0 002-2V9a2 2 0 00-2-2h-3m-1 4l-3 3m0 0l-3-3m3 3V4"/></svg>
          } />
        </div>

        <div id="CONTENT">
          {children}
        </div>
      </div>
    </div>
  );
}
