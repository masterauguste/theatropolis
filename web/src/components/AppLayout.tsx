import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useApp } from "../context/AppContext";

interface AppLayoutProps {
  activeNav: "servers" | "proxy-nodes" | "users" | "subscriptions" | "pool" | "settings" | "";
  width?: "default" | "narrow" | "wide";
  children: React.ReactNode;
}

export const AppLayout: React.FC<AppLayoutProps> = ({ activeNav, width = "default", children }) => {
  const { locale, changeLocale, t, submitMutation, refreshSession, refreshBanner, clearRefreshBanner, appNotice, setAppNotice } = useApp();
  const navigate = useNavigate();
  const [loggingOut, setLoggingOut] = useState(false);

  const handleLogout = async () => {
    if (loggingOut) return;
    setLoggingOut(true);
    try {
      await submitMutation("/logout", {}, { formAdapter: false });
      await refreshSession();
      navigate("/login", { replace: true });
    } catch {
      navigate("/login", { replace: true });
    } finally {
      setLoggingOut(false);
    }
  };

  const mainClass = [
    "main",
    width === "narrow" ? "main--narrow" : "",
    width === "wide" ? "main--wide" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <>
      <a className="skip-link" href="#main">
        {t("Skip to content")}
      </a>
      <header className="global-header">
        <div className="global-header__inner">
          <Link className="brand" to="/servers" aria-label={t("Theatropolis servers")}>
            <span className="brand__mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
                <path d="M7.5 12h3.2c2.8 0 3-5.2 6.3-5.2M10.7 12h.8c2.6 0 2.5 5.2 5.5 5.2" />
                <circle cx="5.5" cy="12" r="2.2" fill="currentColor" stroke="none" />
                <circle cx="18.5" cy="6.8" r="2" fill="#93c5fd" stroke="none" />
                <circle cx="18.5" cy="17.2" r="2" fill="#5eead4" stroke="none" />
              </svg>
            </span>
            <span className="brand__text">
              <strong>Theatropolis</strong>
            </span>
          </Link>

          <nav className="global-nav" aria-label={t("Primary navigation")}>
            <Link to="/servers" className={activeNav === "servers" ? "is-active" : undefined} aria-current={activeNav === "servers" ? "page" : undefined}>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <rect x="3" y="4" width="18" height="6" rx="1.8" />
                <rect x="3" y="14" width="18" height="6" rx="1.8" />
                <circle cx="7" cy="7" r="1" fill="currentColor" stroke="none" />
                <circle cx="7" cy="17" r="1" fill="currentColor" stroke="none" />
                <path d="M11 7h6M11 17h6" />
              </svg>
              <span>{t("Servers")}</span>
            </Link>
            <Link to="/proxy-nodes" className={activeNav === "proxy-nodes" ? "is-active" : undefined} aria-current={activeNav === "proxy-nodes" ? "page" : undefined}>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="5" cy="12" r="2.2" />
                <circle cx="19" cy="6.5" r="2.2" />
                <circle cx="19" cy="17.5" r="2.2" />
                <path d="M7.2 12h3.3c2.5 0 2.5-5.5 6.3-5.5M10.5 12c2.5 0 2.5 5.5 6.3 5.5" />
              </svg>
              <span>{t("Proxy Nodes")}</span>
            </Link>
            <Link to="/users" className={activeNav === "users" ? "is-active" : undefined} aria-current={activeNav === "users" ? "page" : undefined}>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <circle cx="9.5" cy="8" r="3.2" />
                <path d="M3.5 19a6 6 0 0 1 12 0" />
                <circle cx="17" cy="9" r="2.3" />
                <path d="M16.5 14.5a4.5 4.5 0 0 1 4 4.5" />
              </svg>
              <span>{t("Users")}</span>
            </Link>
            <Link to="/subscriptions" className={activeNav === "subscriptions" ? "is-active" : undefined} aria-current={activeNav === "subscriptions" ? "page" : undefined}>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="m12 3 9 4.8-9 4.8-9-4.8L12 3Z" />
                <path d="m3 12.2 9 4.8 9-4.8" />
                <path d="m3 16.5 9 4.8 9-4.8" />
              </svg>
              <span>{t("Subscriptions")}</span>
            </Link>
            <Link to="/settings" className={activeNav === "settings" ? "is-active" : undefined} aria-current={activeNav === "settings" ? "page" : undefined}>
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M4 7h10M18 7h2M4 12h4M12 12h8M4 17h12M20 17h0" />
                <circle cx="16" cy="7" r="2" />
                <circle cx="10" cy="12" r="2" />
                <circle cx="18" cy="17" r="2" />
              </svg>
              <span>{t("Settings")}</span>
            </Link>
          </nav>

          <div className="global-header__footer">
            <button
              type="button"
              className="language-switch"
              onClick={() => void changeLocale(locale === "zh-CN" ? "en" : "zh-CN")}
            >
              {locale === "zh-CN" ? "English" : "中文"}
            </button>
            <button
              type="button"
              className="button button--secondary button--small"
              onClick={() => void handleLogout()}
              disabled={loggingOut}
            >
              {t("Sign out")}
            </button>
          </div>
        </div>
      </header>

      <main className={mainClass} id="main">
        {refreshBanner && (
          <div className="notice notice--warning" role="status" data-refresh-notice="">
            <p>{refreshBanner.message}</p>
            {refreshBanner.signInTab ? (
              <a
                className="button button--secondary"
                href={refreshBanner.url}
                target="_blank"
                rel="noopener noreferrer"
              >
                {t("Sign in in another tab")}
              </a>
            ) : (
              <button
                type="button"
                className="button button--secondary"
                onClick={() => {
                  clearRefreshBanner();
                  window.location.reload();
                }}
              >
                {t("Refresh page")}
              </button>
            )}
          </div>
        )}
        {appNotice && (
          <div className="notice notice--error notice--dismissible" role="alert">
            <span>{appNotice}</span>
            <button
              type="button"
              className="button button--secondary button--small"
              onClick={() => setAppNotice("")}
            >
              {t("Dismiss")}
            </button>
          </div>
        )}
        {children}
      </main>
    </>
  );
};
