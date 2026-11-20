import React, { useEffect, useRef } from "react";
import { Link, useLocation } from "react-router-dom";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { CopyButton } from "../components/CopyButton";
import { LocalTime } from "../components/LocalTime";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const ServerCreatedPage: React.FC = () => {
  const location = useLocation();
  const { t } = useApp();
  // Capture the initial query once so replacing browser history to /servers
  // never triggers a second fetch that would find the one-time result consumed.
  const initialUrlRef = useRef(`${location.pathname}${location.search}`);
  const { data, loading, error } = usePageData(initialUrlRef.current);

  const created = data?.Created;

  useEffect(() => {
    if (created) {
      window.history.replaceState(null, "", "/servers");
    }
  }, [created]);

  return (
    <AppLayout activeNav="servers" width="narrow">
      <AsyncState loading={loading} error={error}>
        {created && (
          <>
            <nav className="breadcrumbs" aria-label={t("Breadcrumb")}>
              <Link to="/servers">{t("Servers")}</Link>
              <span aria-hidden="true">/</span>
              <span aria-current="page">{created.DisplayName}</span>
            </nav>

            <section className="result-card">
              <div className="result-card__success" aria-hidden="true">
                <svg viewBox="0 0 24 24">
                  <path d="m7 12 3 3 7-7" />
                </svg>
              </div>
              <p className="eyebrow">{t("Enrollment ready")}</p>
              <h1>{t("Install")} {created.DisplayName}</h1>
              <p className="result-card__lead">
                {t("Run this command as a sudo-capable user on the destination server.")}
              </p>

              <div className="copy-section">
                <div className="command-card">
                  <div className="command-card__header">
                    <strong>{t("Terminal")}</strong>
                    <CopyButton
                      value={created.InstallCommand}
                      label={t("Copy command")}
                      className="copy-button"
                    />
                  </div>
                  <pre>
                    <code>{created.InstallCommand}</code>
                  </pre>
                </div>
              </div>

              <div className="notice notice--warning">
                <strong>{t("Shown once.")}</strong>{" "}
                {t("This command contains a credential that expires at")}{" "}
                <LocalTime dateTime={created.ExpiresAtISO} fallback={created.ExpiresAt} />{" "}
                {t("and becomes unusable after enrollment. The master persists only its hash.")}
              </div>

              <div className="next-step">
                <span className="step-number">2</span>
                <div>
                  <h2>{t("Wait for the agent to connect")}</h2>
                  <p>
                    {t("After installation, return to Servers and refresh to see its authenticated connection state.")}
                  </p>
                </div>
              </div>

              <div className="result-card__actions">
                <Link className="button button--primary" to="/servers">
                  {t("Return to servers")}
                </Link>
                <Link className="button button--secondary" to="/servers/new">
                  {t("Add another server")}
                </Link>
              </div>
            </section>
          </>
        )}
      </AsyncState>
    </AppLayout>
  );
};
