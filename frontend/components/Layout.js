import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/router";
import {
  LayoutDashboard,
  Activity,
  Globe,
  Terminal,
  ShieldAlert,
  BarChart3,
  Shield,
  Menu,
  X,
} from "lucide-react";

const sidebarItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/live-feed", label: "Live Feed", icon: Activity },
  { href: "/map", label: "World Map", icon: Globe },
  { href: "/sessions", label: "Sessions", icon: Terminal },
  { href: "/threats", label: "Threats", icon: ShieldAlert },
  { href: "/analytics", label: "Analytics", icon: BarChart3 },
];

export default function Layout({ children }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const router = useRouter();
  const current = router.pathname;

  return (
    <div className="min-h-screen bg-background text-white flex">
      {/* Sidebar */}
      <aside
        className={`
          fixed inset-y-0 left-0 z-40 w-64 glass border-r border-border
          transform transition-transform duration-300 ease-out
          lg:relative lg:transform-none
          ${mobileOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
        `}
      >
        {/* Logo */}
        <div className="h-16 flex items-center px-6 border-b border-border">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-accent-cyan/10 border border-accent-cyan/20 flex items-center justify-center">
              <Shield className="w-4 h-4 text-accent-cyan" />
            </div>
            <div>
              <h1 className="text-sm font-bold tracking-wide text-white">
                ADAPTIVE
                <span className="text-accent-cyan">POT</span>
              </h1>
              <p className="text-[10px] text-muted font-medium tracking-wider uppercase">
                Honeypot Dashboard
              </p>
            </div>
          </div>
        </div>

        {/* Nav */}
        <nav className="p-3 space-y-1 overflow-y-auto" style={{ height: "calc(100% - 64px)" }}>
          {sidebarItems.map((item) => {
            const Icon = item.icon;
            const active = current === item.href;
            return (
              <Link key={item.href} href={item.href} onClick={() => setMobileOpen(false)}>
                <div className={`sidebar-item ${active ? "active" : ""}`}>
                  <Icon className="w-4 h-4" />
                  <span>{item.label}</span>
                  {active && (
                    <div className="ml-auto w-1 h-1 rounded-full bg-accent-cyan shadow-[0_0_6px_rgba(0,229,255,0.5)]" />
                  )}
                </div>
              </Link>
            );
          })}
        </nav>
      </aside>

      {/* Overlay for mobile */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/50 backdrop-blur-sm lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Topbar — minimal */}
        <header className="h-16 glass border-b border-border flex items-center px-4 lg:px-6 sticky top-0 z-20">
          <button
            onClick={() => setMobileOpen(true)}
            className="lg:hidden p-2 rounded-lg hover:bg-white/5 text-muted"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex-1" />

          {/* Honeypot status indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-success/10 border border-success/20">
            <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
            <span className="text-xs font-semibold text-success">Honeypot Active</span>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 p-4 lg:p-8 overflow-y-hidden">
          {children}
        </main>
      </div>
    </div>
  );
}