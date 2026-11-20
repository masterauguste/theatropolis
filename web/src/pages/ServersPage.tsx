import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, fetchJSON } from "../api/client";
import type { VersionCatalogResponse } from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { Modal } from "../components/Modal";
import { SelectBox } from "../components/SelectBox";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const ServersPage: React.FC = () => {
  const { t, countLabel, submitMutation } = useApp();
  const { data: shellData } = usePageData("/servers");
  const { data: contentData, loading, error, reload } = usePageData("/servers/content");

  const [settingsOpen, setSettingsOpen] = useState(false);
  const [notice, setNotice] = useState("");
  const [actionError, setActionError] = useState("");

  // Async sing-box fleet catalog
  const [sbLoading, setSbLoading] = useState(false);
  const [sbWarning, setSbWarning] = useState("");
  const [sbVersions, setSbVersions] = useState<{ value: string; label: string }[]>([]);
  const [selectedSB, setSelectedSB] = useState("");
  const [busyAction, setBusyAction] = useState<"" | "agent" | "sing-box">("");

  const loadSingBoxCatalog = useCallback(async () => {
    setSbLoading(true);
    setSbWarning("");
    try {
      const catalog = await fetchJSON<VersionCatalogResponse>("/servers/versions?catalog=sing-box");
      const list = (catalog.sing_box_versions || []).map((v) => ({
        value: v.Tag,
        label: `${v.Tag} (${v.Branch})`,
      }));
      setSbVersions(list);
      setSelectedSB(catalog.latest_sing_box_version || list[0]?.value || "");
      if (catalog.sing_box_catalog_warning) setSbWarning(catalog.sing_box_catalog_warning);
    } catch (err) {
      setSbWarning(err instanceof Error ? err.message : t("Unable to load sing-box versions."));
      setSbVersions([]);
      setSelectedSB("");
    } finally {
      setSbLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (settingsOpen) {
      void loadSingBoxCatalog();
    }
  }, [settingsOpen, loadSingBoxCatalog]);

  const handleUpdateAllAgents = async () => {
    if (busyAction) return;
    setBusyAction("agent");
    setActionError("");
    try {
      const res = await submitMutation("/servers/agent-update-all", {});
      if (res.notice) setNotice(res.notice);
      setSettingsOpen(false);
      await reload();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setBusyAction("");
    }
  };

  const handleUpdateAllSingBox = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busyAction || !selectedSB) return;
    setBusyAction("sing-box");
    setActionError("");
    try {
      const res = await submitMutation("/servers/sing-box-update-all", { target_version: selectedSB });
      if (res.notice) setNotice(res.notice);
      setSettingsOpen(false);
      await reload();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setBusyAction("");
    }
  };

  const stats = contentData?.Stats;
  const agents = contentData?.Agents || [];

  return (
    <AppLayout activeNav="servers">
      <header className="page-header">
        <div>
          <p className="eyebrow">{t("Infrastructure")}</p>
          <h1>{t("Servers")}</h1>
        </div>
        <div className="page-header__actions">
          <button
            type="button"
            className="button button--secondary button--icon"
            aria-label={t("Refresh server status")}
            onClick={() => void reload()}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path d="M20 11a8 8 0 1 0-2.3 5.7M20 5v6h-6" />
            </svg>
            {t("Refresh")}
          </button>
          <button
            type="button"
            className="button button--secondary"
            onClick={() => {
              setActionError("");
              setSettingsOpen(true);
            }}
          >
            {t("Server settings")}
          </button>
          <Link className="button button--primary" to="/servers/new">
            <span aria-hidden="true">+</span> {t("Add server")}
          </Link>
        </div>
      </header>

      {(notice || shellData?.Notice) && (
        <div className="notice notice--success" role="status">
          {notice || shellData?.Notice}
        </div>
      )}

      <AsyncState loading={loading} error={error} loadingLabel={t("Loading servers…")} onRetry={() => void reload()}>
        {stats && (
          <section className="metric-grid" aria-label={t("Fleet summary")}>
            <article className="metric-card">
              <div className="metric-card__top">
                <span className="metric-card__label">{t("Total servers")}</span>
                <span className="metric-card__icon" aria-hidden="true">
                  <svg viewBox="0 0 20 20">
                    <rect x="3" y="3.5" width="14" height="5" rx="1.4" />
                    <rect x="3" y="11.5" width="14" height="5" rx="1.4" />
                    <circle cx="6.2" cy="6" r=".8" fill="currentColor" stroke="none" />
                    <circle cx="6.2" cy="14" r=".8" fill="currentColor" stroke="none" />
                  </svg>
                </span>
              </div>
              <strong>{stats.Total}</strong>
              <span className="metric-card__hint">{t("Known to this master")}</span>
            </article>
            <article className="metric-card metric-card--positive">
              <div className="metric-card__top">
                <span className="metric-card__label">{t("Online")}</span>
                <span className="metric-card__icon" aria-hidden="true">
                  <svg viewBox="0 0 20 20">
                    <path d="M3.5 10.5 7.5 14.5 16.5 5.5" />
                  </svg>
                </span>
              </div>
              <strong>{stats.Online}</strong>
              <span className="metric-card__hint">{t("Authenticated sessions")}</span>
            </article>
            <article className="metric-card metric-card--pending">
              <div className="metric-card__top">
                <span className="metric-card__label">{t("Pending")}</span>
                <span className="metric-card__icon" aria-hidden="true">
                  <svg viewBox="0 0 20 20">
                    <circle cx="10" cy="10" r="6.8" />
                    <path d="M10 6.5V10l2.4 1.6" />
                  </svg>
                </span>
              </div>
              <strong>{stats.Pending}</strong>
              <span className="metric-card__hint">{t("Awaiting installation")}</span>
            </article>
            <article className="metric-card metric-card--attention">
              <div className="metric-card__top">
                <span className="metric-card__label">{t("Needs attention")}</span>
                <span className="metric-card__icon" aria-hidden="true">
                  <svg viewBox="0 0 20 20">
                    <path d="M10 3.5 17 16H3L10 3.5Z" />
                    <path d="M10 8.2v3.3" />
                    <circle cx="10" cy="13.8" r=".75" fill="currentColor" stroke="none" />
                  </svg>
                </span>
              </div>
              <strong>{stats.Attention}</strong>
              <span className="metric-card__hint">{t("Offline or expired")}</span>
            </article>
          </section>
        )}

        <section className="panel" aria-labelledby="fleet-heading">
          <div className="panel__header">
            <h2 id="fleet-heading">{t("Servers")}</h2>
            {stats && <span className="panel__count">{countLabel(stats.Total, "total")}</span>}
          </div>

          {agents.length === 0 ? (
            <div className="empty-state">
              <h3>{t("No servers enrolled yet")}</h3>
              <Link className="button button--primary" to="/servers/new">
                {t("Add your first server")}
              </Link>
            </div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t("Server")}</th>
                    <th scope="col">{t("Connection")}</th>
                    <th scope="col">{t("Agent version")}</th>
                    <th scope="col">{t("IP addresses")}</th>
                  </tr>
                </thead>
                <tbody>
                  {agents.map((agent) => (
                    <tr key={agent.ID}>
                      <td data-label={t("Server")}>
                        <strong>
                          <Link className="server-link" to={agent.URL}>
                            {agent.Name}
                          </Link>
                        </strong>
                      </td>
                      <td data-label={t("Connection")}>
                        <span className={`status status--${agent.ConnectionClass}`}>
                          <span aria-hidden="true" />
                          {agent.ConnectionClass === "online" ? t("Established") : t("Not established")}
                        </span>
                      </td>
                      <td data-label={t("Agent version")}>
                        {agent.AgentVersion ? (
                          <code className="server-version">{agent.AgentVersion}</code>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td data-label={t("IP addresses")}>
                        {agent.IPv4 || agent.IPv6 ? (
                          <>
                            {agent.IPv4 && <code className="pool-address-line">{agent.IPv4}</code>}
                            {agent.IPv6 && <code className="pool-address-line">{agent.IPv6}</code>}
                          </>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </AsyncState>

      <Modal
        open={settingsOpen}
        onClose={() => setSettingsOpen(false)}
        eyebrow={t("Fleet maintenance")}
        title={t("Server settings")}
        className="fleet-settings-dialog"
        footer={
          <button type="button" className="button button--secondary" onClick={() => setSettingsOpen(false)}>
            {t("Close")}
          </button>
        }
      >
        <div className="modal__body fleet-settings-actions">
          {actionError && (
            <div className="notice notice--error" role="alert">
              {actionError}
            </div>
          )}
          <section className="fleet-settings-action">
            <div className="fleet-settings-action__copy">
              <p className="eyebrow">Theatropolis</p>
              <h3>{t("Update Agent software")}</h3>
            </div>
            <button
              type="button"
              className="button button--secondary button--full"
              disabled={Boolean(busyAction)}
              onClick={() => void handleUpdateAllAgents()}
            >
              {busyAction === "agent" ? t("Queuing…") : t("Update all Agents")}
            </button>
          </section>

          <section className="fleet-settings-action">
            <div className="fleet-settings-action__copy">
              <p className="eyebrow">{t("Proxy runtime")}</p>
              <h3>{t("Change sing-box version")}</h3>
            </div>
            <form className="stack stack--compact" onSubmit={(e) => void handleUpdateAllSingBox(e)} noValidate>
              <label className="field">
                <span>{t("Target version")}</span>
                <SelectBox
                  value={selectedSB}
                  onChange={setSelectedSB}
                  disabled={sbLoading || sbVersions.length === 0}
                  placeholder={sbLoading ? t("loading available versions…") : t("No versions available")}
                  options={sbVersions}
                />
                {sbLoading && (
                  <small className="inline-loading">
                    <span className="loading-spinner loading-spinner--small" aria-hidden="true" />
                    <span>{t("Loading signed releases…")}</span>
                  </small>
                )}
                {sbWarning && <small className="field-warning">{sbWarning}</small>}
                <small>{t("Offline, incompatible, busy, and already-matching Agents are skipped.")}</small>
              </label>
              <button
                type="submit"
                className="button button--primary button--full"
                disabled={Boolean(busyAction) || sbLoading || !selectedSB}
              >
                {busyAction === "sing-box" ? t("Queuing…") : t("Change sing-box version")}
              </button>
            </form>
          </section>
        </div>
      </Modal>
    </AppLayout>
  );
};
