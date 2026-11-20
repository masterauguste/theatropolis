import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AsyncState } from "../components/AsyncState";
import { CopyButton } from "../components/CopyButton";
import { DailyUsageTable } from "../components/DailyUsageTable";
import { LocalTime } from "../components/LocalTime";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const PortalPage: React.FC = () => {
  const navigate = useNavigate();
  const { locale, changeLocale, t, submitMutation, refreshSession } = useApp();
  const { data, loading, error, reload } = usePageData("/portal");
  const [loggingOut, setLoggingOut] = useState(false);

  useEffect(() => {
    document.body.className = "portal-page";
    return () => {
      document.body.className = "";
    };
  }, []);

  const portal = data?.EndUserPortal;

  const handleLogout = async () => {
    if (loggingOut || !portal) return;
    setLoggingOut(true);
    try {
      const res = await submitMutation("/portal/logout", { csrf_token: portal.CSRFToken }, { skipCSRF: true, formAdapter: false });
      await refreshSession();
      navigate(res.redirect || "/login", { replace: true });
    } catch {
      navigate("/login", { replace: true });
    } finally {
      setLoggingOut(false);
    }
  };

  return (
    <>
      <header className="portal-header">
        <div className="portal-header__inner">
          <div className="brand">
            <span className="brand__text">
              <strong>Theatropolis</strong>
            </span>
          </div>
          <div className="portal-header__account">
            {portal?.LoginUsername && <span>{portal.LoginUsername}</span>}
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

      <main className="portal-main" id="main">
        <header className="page-header">
          <div>
            <p className="eyebrow">{t("User portal")}</p>
            <h1>{t("My Access")}</h1>
          </div>
        </header>

        <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
          {portal && (
            <>
              <section className="panel subscription-links-panel">
                <div className="panel__header">
                  <h2>{t("Configuration Subscriptions")}</h2>
                  {portal.Subscription?.Enabled ? (
                    <span className="membership-status membership-status--active">{t("Available")}</span>
                  ) : (
                    <span className="membership-status membership-status--disabled">{t("Unavailable")}</span>
                  )}
                </div>
                {portal.Subscription?.Enabled ? (
                  <div className="subscription-link-grid">
                    <article>
                      <span className="protocol-badge">Clash</span>
                      <code>{portal.Subscription.ClashURL}</code>
                      <CopyButton value={portal.Subscription.ClashURL} />
                    </article>
                    <article>
                      <span className="protocol-badge">Surge</span>
                      <code>{portal.Subscription.SurgeURL}</code>
                      <CopyButton value={portal.Subscription.SurgeURL} />
                    </article>
                    <article>
                      <span className="protocol-badge">sing-box</span>
                      <code>{portal.Subscription.SingBoxURL}</code>
                      <CopyButton value={portal.Subscription.SingBoxURL} />
                    </article>
                  </div>
                ) : (
                  <div className="panel__empty">
                    <strong>{t("Configuration subscriptions are unavailable.")}</strong>
                  </div>
                )}
              </section>

              <section className="panel daily-usage-panel">
                <div className="panel__header">
                  <h2>{t("Daily Traffic")}</h2>
                  <span className="panel__count">{t("Last 30 Days")}</span>
                </div>
                <DailyUsageTable days={portal.DailyUsage} />
              </section>

              <section className="panel">
                <div className="panel__header">
                  <h2>{t("Node Access")}</h2>
                  <span className="panel__count">{portal.Nodes?.length || 0}</span>
                </div>
                {portal.Nodes && portal.Nodes.length > 0 ? (
                  <div className="portal-node-grid">
                    {portal.Nodes.map((node) => (
                      <article key={node.Name} className="portal-node-card">
                        <header>
                          <span className={`node-role-chip__mark node-role-chip__mark--${node.Tone}`} aria-hidden="true">
                            {node.Initial}
                          </span>
                          <span>
                            <strong>{node.Name}</strong>
                            {node.PendingApply ? (
                              <small>{t("Entrance is not available until topology is applied.")}</small>
                            ) : (
                              <small>
                                {node.Protocol} · {node.EntranceAgent}
                              </small>
                            )}
                          </span>
                          <span className={`membership-status membership-status--${node.StatusClass}`}>
                            {node.StatusLabel}
                          </span>
                        </header>
                        <dl className="membership-facts">
                          <div>
                            <dt>{t("Traffic Used")}</dt>
                            <dd>{node.UsageLabel}</dd>
                          </div>
                          <div>
                            <dt>{t("Monthly Quota")}</dt>
                            <dd>{node.QuotaLabel}</dd>
                          </div>
                          <div>
                            <dt>{t("Reset Time")}</dt>
                            <dd>
                              <LocalTime dateTime={node.ResetAt} fallback={node.ResetLabel} />
                            </dd>
                          </div>
                          <div>
                            <dt>{t("Expiration")}</dt>
                            <dd>
                              {node.ExpirationAt ? (
                                <LocalTime dateTime={node.ExpirationAt} fallback={node.ExpirationLabel} />
                              ) : (
                                node.ExpirationLabel
                              )}
                            </dd>
                          </div>
                        </dl>
                      </article>
                    ))}
                  </div>
                ) : (
                  <div className="panel__empty">
                    <strong>{t("No Node Access")}</strong>
                  </div>
                )}
              </section>
            </>
          )}
        </AsyncState>
      </main>
    </>
  );
};
