import React, { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError, fetchJSON } from "../api/client";
import type { VersionCatalogResponse } from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { Modal } from "../components/Modal";
import { SelectBox } from "../components/SelectBox";
import { useApp, useDirtyForm } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const ServerDetailPage: React.FC = () => {
  const { agentId = "" } = useParams();
  const navigate = useNavigate();
  const { t, submitMutation } = useApp();
  const { data, loading, error, reload } = usePageData(`/servers/${encodeURIComponent(agentId)}/manage`);

  const agent = data?.Agent;

  const [renameOpen, setRenameOpen] = useState(false);
  const [actionsOpen, setActionsOpen] = useState(false);

  // Rename draft
  const [renameValue, setRenameValue] = useState("");
  const [renameError, setRenameError] = useState("");
  const [renameBusy, setRenameBusy] = useState(false);

  // Actions modal drafts
  const [domainV4, setDomainV4] = useState("");
  const [domainV6, setDomainV6] = useState("");
  const [reverseOnly, setReverseOnly] = useState("0");
  const [replaceTTL, setReplaceTTL] = useState("900");
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [confirmForce, setConfirmForce] = useState(false);
  const [actionsError, setActionsError] = useState("");
  const [actionsNotice, setActionsNotice] = useState("");
  const [actionsBusy, setActionsBusy] = useState("");

  // Async version catalogs
  const [agentCatalogLoading, setAgentCatalogLoading] = useState(false);
  const [latestAgentVersion, setLatestAgentVersion] = useState("");
  const [agentCatalogWarning, setAgentCatalogWarning] = useState("");
  const [sbCatalogLoading, setSbCatalogLoading] = useState(false);
  const [sbOptions, setSbOptions] = useState<{ value: string; label: string }[]>([]);
  const [selectedSB, setSelectedSB] = useState("");
  const [sbCatalogWarning, setSbCatalogWarning] = useState("");

  useDirtyForm("server-rename", renameOpen && renameValue !== (agent?.Name || ""));

  // Poll pending deployment status
  useEffect(() => {
    if (!agent?.Deployment?.Pending || !agent.DeploymentStatusURL) return;
    const timer = window.setInterval(async () => {
      try {
        const res = await fetchJSON<{ pending?: boolean }>(agent.DeploymentStatusURL);
        if (!res.pending) {
          void reload();
        }
      } catch {
        // ignore transient polling failure
      }
    }, 3000);
    return () => window.clearInterval(timer);
  }, [agent?.Deployment?.Pending, agent?.DeploymentStatusURL, reload]);

  const loadCatalogs = useCallback(async () => {
    if (!agent) return;
    setAgentCatalogLoading(true);
    setSbCatalogLoading(true);
    setAgentCatalogWarning("");
    setSbCatalogWarning("");
    const base = `/servers/${encodeURIComponent(agent.ID)}/versions`;
    try {
      const a = await fetchJSON<VersionCatalogResponse>(`${base}?catalog=agent`);
      setLatestAgentVersion(a.latest_version || "");
      if (a.agent_catalog_warning) setAgentCatalogWarning(a.agent_catalog_warning);
    } catch (err) {
      setAgentCatalogWarning(err instanceof Error ? err.message : t("unavailable"));
    } finally {
      setAgentCatalogLoading(false);
    }
    try {
      const sb = await fetchJSON<VersionCatalogResponse>(`${base}?catalog=sing-box`);
      const list = (sb.sing_box_versions || []).map((v) => ({
        value: v.Tag,
        label: `${v.Tag} (${v.Branch})`,
      }));
      setSbOptions(list);
      setSelectedSB(sb.latest_sing_box_version || list[0]?.value || "");
      if (sb.sing_box_catalog_warning) setSbCatalogWarning(sb.sing_box_catalog_warning);
    } catch (err) {
      setSbCatalogWarning(err instanceof Error ? err.message : t("unavailable"));
      setSbOptions([]);
      setSelectedSB("");
    } finally {
      setSbCatalogLoading(false);
    }
  }, [agent, t]);

  const openActions = () => {
    if (!agent) return;
    setDomainV4(agent.SubscriptionDomainV4 || "");
    setDomainV6(agent.SubscriptionDomainV6 || "");
    setReverseOnly(agent.ReverseOnly ? "1" : "0");
    setReplaceTTL("900");
    setConfirmRevoke(false);
    setConfirmForce(false);
    setActionsError("");
    setActionsNotice("");
    setActionsOpen(true);
    void loadCatalogs();
  };

  const openRename = () => {
    if (!agent) return;
    setRenameValue(agent.Name);
    setRenameError("");
    setRenameOpen(true);
  };

  const handleRename = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!agent || renameBusy) return;
    setRenameBusy(true);
    setRenameError("");
    try {
      await submitMutation(`/servers/${encodeURIComponent(agent.ID)}/rename`, {
        display_name: renameValue.trim(),
      });
      setRenameOpen(false);
      await reload();
    } catch (err) {
      setRenameError(err instanceof ApiError ? err.message : t("Could not rename server."));
    } finally {
      setRenameBusy(false);
    }
  };

  const runServerAction = async (
    key: string,
    url: string,
    fields: Record<string, string>,
    options?: { closeOnSuccess?: boolean; followRedirect?: boolean },
  ) => {
    if (actionsBusy) return;
    setActionsBusy(key);
    setActionsError("");
    setActionsNotice("");
    try {
      const res = await submitMutation(url, fields);
      if (options?.followRedirect && res.redirect) {
        setActionsOpen(false);
        navigate(res.redirect);
        return;
      }
      if (res.notice) setActionsNotice(res.notice);
      if (options?.closeOnSuccess) setActionsOpen(false);
      await reload();
    } catch (err) {
      setActionsError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setActionsBusy("");
    }
  };

  return (
    <AppLayout activeNav="servers" width="wide">
      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        {agent && (
          <>
            <nav className="breadcrumbs" aria-label={t("Breadcrumb")}>
              <Link to="/servers">{t("Servers")}</Link>
              <span aria-hidden="true">/</span>
              <span aria-current="page">{agent.Name}</span>
            </nav>

            <header className="page-header">
              <div>
                <p className="eyebrow">{t("Server management")}</p>
                <div className="proxy-node-page-header__title">
                  <h1>{agent.Name}</h1>
                  <button
                    type="button"
                    className="button button--secondary button--icon-only"
                    aria-label={t("Rename Server")}
                    onClick={openRename}
                  >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M4 20h4l11-11a2.8 2.8 0 0 0-4-4L4 16v4Z" />
                      <path d="m13.5 6.5 4 4" />
                    </svg>
                  </button>
                </div>
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
                  className="button button--secondary button--icon-only"
                  aria-label={t("Open server and software actions")}
                  onClick={openActions}
                >
                  <svg viewBox="0 0 24 24" aria-hidden="true">
                    <path d="M12 15.5a3.5 3.5 0 1 0 0-7 3.5 3.5 0 0 0 0 7ZM19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1a1.7 1.7 0 0 0 1.9.3A1.7 1.7 0 0 0 10 3V2.8h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" />
                  </svg>
                </button>
              </div>
            </header>

            <section className="server-summary" aria-label={t("Server")}>
              <article className="summary-card">
                <span className="summary-card__label">{t("Enrollment")}</span>
                <span className={`status status--${agent.EnrollmentClass}`}>
                  <span aria-hidden="true" />
                  {agent.EnrollmentLabel}
                </span>
              </article>
              <article className="summary-card">
                <span className="summary-card__label">{t("Control connection")}</span>
                <span className={`status status--${agent.ConnectionClass}`}>
                  <span aria-hidden="true" />
                  {agent.ConnectionLabel}
                </span>
                {agent.ConnectionDetail && <small>{agent.ConnectionDetail}</small>}
              </article>
              <article className="summary-card">
                <span className="summary-card__label">{t("Proxy Node readiness")}</span>
                {agent.ConfigurationEnabled ? (
                  <strong className="summary-card__value summary-card__value--positive">{t("Ready")}</strong>
                ) : (
                  <>
                    <strong className="summary-card__value">
                      {agent.Online ? t("Upgrade required") : t("Unavailable")}
                    </strong>
                    {agent.ConfigurationHint && <small>{agent.ConfigurationHint}</small>}
                  </>
                )}
              </article>
              <article className="summary-card">
                <span className="summary-card__label">{t("Agent version")}</span>
                {agent.AgentVersion ? (
                  <>
                    <strong className="summary-card__value">{agent.AgentVersion}</strong>
                    <small>
                      {agent.OperatingSystem} / {agent.Architecture}
                    </small>
                  </>
                ) : (
                  <strong className="summary-card__value">{t("Unknown")}</strong>
                )}
              </article>
              <article className="summary-card">
                <span className="summary-card__label">{t("sing-box version")}</span>
                <strong className="summary-card__value">{agent.SingBoxVersion || t("Unknown")}</strong>
              </article>
              {agent.ACMEHTTP01Relay && (
                <article className="summary-card">
                  <span className="summary-card__label">{t("ACME HTTP-01")}</span>
                  <strong className="summary-card__value summary-card__value--positive">{t("Local relay ready")}</strong>
                  <small>{t("Caddy owns public port 80 and relays Agent challenges internally.")}</small>
                </article>
              )}
            </section>

            <section className="panel entrance-usage">
              <div className="panel__header">
                <h2>{t("Entrance Traffic")}</h2>
              </div>
              <dl className="server-usage-grid">
                <div>
                  <dt>{t("Finite Quota Allocated")}</dt>
                  <dd>{agent.EntranceAllocated}</dd>
                </div>
                <div>
                  <dt>{t("Finite Quota Used")}</dt>
                  <dd>{agent.EntranceUsed}</dd>
                </div>
                <div>
                  <dt>{t("Unlimited Users")}</dt>
                  <dd>{agent.EntranceUnlimited}</dd>
                </div>
              </dl>
            </section>

            <section className="panel">
              <div className="panel__header">
                <h2>{t("Proxy Node Assignments")}</h2>
                <Link className="button button--primary" to="/proxy-nodes">
                  {t("Open Proxy Nodes")}
                </Link>
              </div>
              {agent.ProxyNodeReferences && agent.ProxyNodeReferences.length > 0 ? (
                <div className="membership-list">
                  {agent.ProxyNodeReferences.map((ref) => (
                    <Link key={ref.ID} to={ref.URL}>
                      <span>
                        <strong>{ref.Name}</strong>
                        <small>
                          {ref.Desired && (
                            <>
                              {t("Configured")}: {ref.DesiredEntrance ? t("Entrance") : ""}
                              {ref.DesiredEntrance && ref.DesiredRelayHops ? " · " : ""}
                              {ref.DesiredRelayHops ? ref.DesiredRelayHopLabel : ""}
                            </>
                          )}
                          {ref.Desired && ref.Applied ? " · " : ""}
                          {ref.Applied && (
                            <>
                              {t("Applied")}: {ref.AppliedEntrance ? t("Entrance") : ""}
                              {ref.AppliedEntrance && ref.AppliedRelayHops ? " · " : ""}
                              {ref.AppliedRelayHops ? ref.AppliedRelayHopLabel : ""}
                            </>
                          )}
                        </small>
                      </span>
                      {ref.Applied && !ref.Desired ? (
                        <span className="membership-status membership-status--pending">{t("Pending Retirement")}</span>
                      ) : ref.Desired && !ref.Applied ? (
                        <span className="membership-status membership-status--pending">{t("Pending Apply")}</span>
                      ) : (
                        <span aria-hidden="true">→</span>
                      )}
                    </Link>
                  ))}
                </div>
              ) : agent.RetirementPending ? (
                <div className="panel__empty">
                  <strong>{t("Topology Retirement Pending")}</strong>
                  <p>{t("This Server still owns an applied managed configuration. Finish or retry the Proxy Node change before removing it.")}</p>
                </div>
              ) : (
                <div className="panel__empty">
                  <p>{t("This Server is not used by any Proxy Node.")}</p>
                </div>
              )}
            </section>

            <Modal
              open={renameOpen}
              onClose={() => setRenameOpen(false)}
              eyebrow={t("Server")}
              title={t("Rename Server")}
              className="resource-modal"
            >
              <form onSubmit={(e) => void handleRename(e)} noValidate>
                <div className="modal__body stack">
                  {renameError && (
                    <div className="notice notice--error" role="alert">
                      {renameError}
                    </div>
                  )}
                  <label className="field">
                    <span>{t("Server Name")}</span>
                    <input
                      value={renameValue}
                      onChange={(e) => setRenameValue(e.target.value)}
                      required
                      autoFocus
                    />
                  </label>
                  <dl className="detail-list detail-list--compact">
                    <div>
                      <dt>{t("Server Record ID")}</dt>
                      <dd>
                        <code>{agent.ID}</code>
                      </dd>
                    </div>
                  </dl>
                </div>
                <footer className="modal__footer">
                  <button type="button" className="button button--secondary" onClick={() => setRenameOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button type="submit" className="button button--primary" disabled={renameBusy}>
                    {renameBusy ? t("Saving…") : t("Save Name")}
                  </button>
                </footer>
              </form>
            </Modal>

            <Modal
              open={actionsOpen}
              onClose={() => setActionsOpen(false)}
              eyebrow={t("Operations")}
              title={t("Server and software actions")}
              className="actions-modal"
              footer={
                <button type="button" className="button button--primary" onClick={() => setActionsOpen(false)}>
                  {t("Done")}
                </button>
              }
            >
              <div className="modal__body actions-list">
                {actionsError && (
                  <div className="notice notice--error" role="alert">
                    {actionsError}
                  </div>
                )}
                {actionsNotice && (
                  <div className="notice notice--success" role="status">
                    {actionsNotice}
                  </div>
                )}

                <details className="action-section" open>
                  <summary>
                    <span>
                      <strong>{t("Subscription addresses")}</strong>
                      <small>
                        {agent.SubscriptionDomainV4 || agent.SubscriptionDomainV6
                          ? t("Custom domains")
                          : t("Automatic IP addresses")}
                      </small>
                    </span>
                  </summary>
                  <div className="action-section__body">
                    <form
                      className="stack stack--compact"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void runServerAction(
                          "domains",
                          `/servers/${encodeURIComponent(agent.ID)}/subscription-domains`,
                          { subscription_domain_ipv4: domainV4, subscription_domain_ipv6: domainV6 },
                        );
                      }}
                      noValidate
                    >
                      <label className="field">
                        <span>
                          {t("IPv4 domain")} <span className="field__optional">{t("Optional")}</span>
                        </span>
                        <input
                          value={domainV4}
                          onChange={(e) => setDomainV4(e.target.value)}
                          placeholder="ipv4.proxy.example.com"
                          autoComplete="off"
                          spellCheck={false}
                          maxLength={253}
                        />
                      </label>
                      <label className="field">
                        <span>
                          {t("IPv6 domain")} <span className="field__optional">{t("Optional")}</span>
                        </span>
                        <input
                          value={domainV6}
                          onChange={(e) => setDomainV6(e.target.value)}
                          placeholder="ipv6.proxy.example.com"
                          autoComplete="off"
                          spellCheck={false}
                          maxLength={253}
                        />
                      </label>
                      <button type="submit" className="button button--secondary button--full" disabled={Boolean(actionsBusy)}>
                        {actionsBusy === "domains" ? t("Saving…") : t("Save server settings")}
                      </button>
                    </form>
                  </div>
                </details>

                <details className="action-section" open>
                  <summary>
                    <span>
                      <strong>{t("sing-box runtime")}</strong>
                      <small>Running {agent.SingBoxVersion || "not detected"}</small>
                    </span>
                  </summary>
                  <div className="action-section__body">
                    {agent.SingBoxUpdate && (
                      <dl className="detail-list detail-list--compact">
                        <div>
                          <dt>{t("Update status")}</dt>
                          <dd>
                            <span className={`status status--${agent.SingBoxUpdate.StatusClass}`}>
                              <span aria-hidden="true" />
                              {agent.SingBoxUpdate.StatusLabel}
                            </span>
                          </dd>
                        </div>
                        <div>
                          <dt>{t("Target")}</dt>
                          <dd>
                            <code>{agent.SingBoxUpdate.TargetVersion}</code>
                          </dd>
                        </div>
                        <div>
                          <dt>{t("Reported running")}</dt>
                          <dd>
                            <code>{agent.SingBoxUpdate.RunningVersion}</code>
                          </dd>
                        </div>
                        <div>
                          <dt>{t("Updated")}</dt>
                          <dd>{agent.SingBoxUpdate.UpdatedAt}</dd>
                        </div>
                      </dl>
                    )}
                    {agent.SingBoxUpdate?.Diagnostic && (
                      <div className="diagnostic">
                        <strong>{t("sing-box update diagnostic")}</strong>
                        <pre>{agent.SingBoxUpdate.Diagnostic}</pre>
                      </div>
                    )}
                    <form
                      className="stack stack--compact"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void runServerAction(
                          "sing-box",
                          `/servers/${encodeURIComponent(agent.ID)}/sing-box-update`,
                          { target_version: selectedSB },
                        );
                      }}
                      noValidate
                    >
                      <label className="field">
                        <span>{t("sing-box release")}</span>
                        <SelectBox
                          value={selectedSB}
                          onChange={setSelectedSB}
                          disabled={!agent.SingBoxUpdateEnabled || sbCatalogLoading || sbOptions.length === 0}
                          placeholder={sbCatalogLoading ? t("loading available versions…") : t("No versions available")}
                          options={sbOptions}
                        />
                        {sbCatalogLoading && (
                          <small className="inline-loading">
                            <span className="loading-spinner loading-spinner--small" aria-hidden="true" />
                            <span>{t("Loading releases…")}</span>
                          </small>
                        )}
                        {agent.SingBoxUpdateHint && <small>{agent.SingBoxUpdateHint}</small>}
                        {sbCatalogWarning && <small className="field-warning">{sbCatalogWarning}</small>}
                      </label>
                      <button
                        type="submit"
                        className="button button--secondary button--full"
                        disabled={!agent.SingBoxUpdateEnabled || Boolean(actionsBusy) || !selectedSB}
                      >
                        {actionsBusy === "sing-box" ? t("Scheduling…") : t("Install selected sing-box version")}
                      </button>
                    </form>
                  </div>
                </details>

                <details className="action-section" open>
                  <summary>
                    <span>
                      <strong>{t("Agent software")}</strong>
                      <small>Running {agent.AgentVersion || "unknown version"}</small>
                    </span>
                  </summary>
                  <div className="action-section__body">
                    {agent.Update && (
                      <dl className="detail-list detail-list--compact">
                        <div>
                          <dt>{t("Update status")}</dt>
                          <dd>
                            <span className={`status status--${agent.Update.StatusClass}`}>
                              <span aria-hidden="true" />
                              {agent.Update.StatusLabel}
                            </span>
                          </dd>
                        </div>
                        <div>
                          <dt>{t("Target")}</dt>
                          <dd>
                            <code>{agent.Update.TargetVersion}</code>
                          </dd>
                        </div>
                        <div>
                          <dt>{t("Reported running")}</dt>
                          <dd>
                            <code>{agent.Update.RunningVersion}</code>
                          </dd>
                        </div>
                        <div>
                          <dt>{t("Updated")}</dt>
                          <dd>{agent.Update.UpdatedAt}</dd>
                        </div>
                      </dl>
                    )}
                    {agent.Update?.Diagnostic && (
                      <div className="diagnostic">
                        <strong>{t("Update diagnostic")}</strong>
                        <pre>{agent.Update.Diagnostic}</pre>
                      </div>
                    )}
                    <dl className="detail-list detail-list--compact">
                      <div>
                        <dt>{t("Current version")}</dt>
                        <dd>
                          <code>{agent.AgentVersion || "unknown"}</code>
                        </dd>
                      </div>
                      <div>
                        <dt>{t("Latest available")}</dt>
                        <dd className="inline-loading">
                          {agentCatalogLoading && <span className="loading-spinner loading-spinner--small" aria-hidden="true" />}
                          <code>{agentCatalogLoading ? t("loading…") : latestAgentVersion || t("unavailable")}</code>
                        </dd>
                      </div>
                    </dl>
                    {agent.UpdateHint && <small>{agent.UpdateHint}</small>}
                    {agentCatalogWarning && <small className="field-warning">{agentCatalogWarning}</small>}
                    <button
                      type="button"
                      className="button button--secondary button--full"
                      disabled={!agent.UpdateEnabled || Boolean(actionsBusy) || !latestAgentVersion}
                      onClick={() =>
                        void runServerAction(
                          "agent-update",
                          `/servers/${encodeURIComponent(agent.ID)}/agent-update`,
                          { target_version: latestAgentVersion },
                        )
                      }
                    >
                      {actionsBusy === "agent-update" ? t("Requesting…") : t("Update agent to latest")}
                    </button>
                  </div>
                </details>

                <details className="action-section">
                  <summary>
                    <span>
                      <strong>{t("Connectivity mode")}</strong>
                      <small>{agent.ReverseOnly ? t("CGNAT / Reverse-only") : t("Publicly reachable")}</small>
                    </span>
                  </summary>
                  <div className="action-section__body">
                    <form
                      className="stack stack--compact"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void runServerAction(
                          "connectivity",
                          `/servers/${encodeURIComponent(agent.ID)}/connectivity`,
                          { reverse_only: reverseOnly },
                        );
                      }}
                      noValidate
                    >
                      <label className="field">
                        <span>{t("Connectivity mode")}</span>
                        <SelectBox
                          searchable={false}
                          value={reverseOnly}
                          onChange={setReverseOnly}
                          options={[
                            { value: "0", label: t("Publicly reachable") },
                            { value: "1", label: t("CGNAT / Reverse-only") },
                          ]}
                        />
                        <small>{t("Retire existing desired and applied Hops before changing connectivity mode.")}</small>
                      </label>
                      <button type="submit" className="button button--secondary button--full" disabled={Boolean(actionsBusy)}>
                        {actionsBusy === "connectivity" ? t("Saving…") : t("Save Connectivity")}
                      </button>
                    </form>
                  </div>
                </details>

                <details className="action-section">
                  <summary>
                    <span>
                      <strong>{t("Latest deployment")}</strong>
                      <small>{agent.Deployment ? agent.Deployment.StatusLabel : t("No deployment yet")}</small>
                    </span>
                  </summary>
                  <div className="action-section__body">
                    {agent.Deployment ? (
                      <>
                        <dl className="detail-list">
                          <div>
                            <dt>{t("Status")}</dt>
                            <dd>
                              <span className={`status status--${agent.Deployment.StatusClass}`}>
                                <span aria-hidden="true" />
                                {agent.Deployment.StatusLabel}
                              </span>
                            </dd>
                          </div>
                          <div>
                            <dt>{t("Revision")}</dt>
                            <dd>
                              <code>{agent.Deployment.RevisionID}</code>
                            </dd>
                          </div>
                          <div>
                            <dt>SHA-256</dt>
                            <dd>
                              <code>{agent.Deployment.Digest}</code>
                            </dd>
                          </div>
                          <div>
                            <dt>{t("Updated")}</dt>
                            <dd>{agent.Deployment.UpdatedAt}</dd>
                          </div>
                        </dl>
                        {agent.Deployment.Diagnostic && (
                          <div className="diagnostic">
                            <strong>{t("Agent diagnostic")}</strong>
                            <pre>{agent.Deployment.Diagnostic}</pre>
                          </div>
                        )}
                      </>
                    ) : (
                      <div className="panel__empty">
                        <p>{t("No configuration has been sent to this agent yet.")}</p>
                      </div>
                    )}
                  </div>
                </details>

                {agent.CanReplace && (
                  <details className="action-section">
                    <summary>
                      <span>
                        <strong>{t("Replace Agent")}</strong>
                        <small>{t("Move this identity and its profile to another server")}</small>
                      </span>
                    </summary>
                    <div className="action-section__body">
                      <p>
                        {t("The current Agent remains authorized until the replacement uses its one-time token. At that moment the old connection is closed and this master immediately deploys the retained profile to the replacement.")}
                      </p>
                      <form
                        className="stack"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void runServerAction(
                            "replace",
                            `/servers/${encodeURIComponent(agent.ID)}/replace`,
                            { agent_id: agent.ID, ttl_seconds: replaceTTL },
                            { followRedirect: true },
                          );
                        }}
                        noValidate
                      >
                        <label className="field">
                          <span>{t("Command lifetime")}</span>
                          <SelectBox
                            searchable={false}
                            value={replaceTTL}
                            onChange={setReplaceTTL}
                            options={[
                              { value: "900", label: t("15 minutes · Recommended") },
                              { value: "3600", label: t("1 hour") },
                              { value: "86400", label: t("24 hours") },
                            ]}
                          />
                        </label>
                        <button type="submit" className="button button--secondary button--full" disabled={Boolean(actionsBusy)}>
                          {t("Create replacement command")}
                        </button>
                      </form>
                    </div>
                  </details>
                )}

                <details className="action-section action-section--danger">
                  <summary>
                    <span>
                      <strong>{t("Revoke access")}</strong>
                      <small>
                        {agent.RemovalBlocked
                          ? t("Move Proxy Node Hops First")
                          : t("Disconnect and invalidate this identity")}
                      </small>
                    </span>
                  </summary>
                  <div className="action-section__body">
                    {agent.RemovalBlocked ? (
                      <>
                        {agent.ProxyNodeReferences && agent.ProxyNodeReferences.length > 0 ? (
                          <>
                            <p>
                              {t("This Server cannot be removed while Proxy Nodes use it. Move the affected Hops to another Server, or delete the branches or Proxy Nodes that use them first.")}
                            </p>
                            <div className="membership-list">
                              {agent.ProxyNodeReferences.map((ref) => (
                                <Link key={ref.ID} to={ref.URL} onClick={() => setActionsOpen(false)}>
                                  <span>
                                    <strong>{ref.Name}</strong>
                                    <small>
                                      {ref.Desired ? t("Configured") : ""}
                                      {ref.Desired && ref.Applied ? " · " : ""}
                                      {ref.Applied ? t("Applied") : ""}
                                    </small>
                                  </span>
                                  <span aria-hidden="true">→</span>
                                </Link>
                              ))}
                            </div>
                          </>
                        ) : (
                          <p>
                            {t("This Server still owns an applied managed configuration. Finish or retry the Proxy Node change before removing it.")}
                          </p>
                        )}
                        <Link className="button button--secondary button--full" to="/proxy-nodes" onClick={() => setActionsOpen(false)}>
                          {t("Review Proxy Nodes")}
                        </Link>
                        {agent.CanForceRemove && (
                          <form
                            className="stack"
                            onSubmit={(e) => {
                              e.preventDefault();
                              if (!confirmForce) return;
                              void runServerAction(
                                "force-revoke",
                                `/servers/${encodeURIComponent(agent.ID)}/revoke`,
                                { agent_id: agent.ID, force: "yes", confirm_revoke: "yes" },
                                { followRedirect: true },
                              );
                            }}
                            noValidate
                          >
                            <p>
                              {t("Only when this machine is permanently gone: forget this Server without delivering a retirement profile. Remaining Proxy Node references turn into deleted-Server entries that you redirect or delete afterwards, and pending changes that wait for this Server finish locally. If the machine ever comes back, its Agent stays locked out and must be reinstalled.")}
                            </p>
                            <label className="danger-confirm">
                              <input
                                type="checkbox"
                                checked={confirmForce}
                                onChange={(e) => setConfirmForce(e.target.checked)}
                                required
                              />
                              <span>
                                {t("I understand the machine is permanently gone and its last configuration cannot be withdrawn remotely.")}
                              </span>
                            </label>
                            <button
                              type="submit"
                              className="button button--danger button--full"
                              disabled={!confirmForce || Boolean(actionsBusy)}
                            >
                              {t("Force remove offline Server")}
                            </button>
                          </form>
                        )}
                      </>
                    ) : (
                      <form
                        className="stack"
                        onSubmit={(e) => {
                          e.preventDefault();
                          if (!confirmRevoke) return;
                          void runServerAction(
                            "revoke",
                            `/servers/${encodeURIComponent(agent.ID)}/revoke`,
                            { agent_id: agent.ID, confirm_revoke: "yes" },
                            { followRedirect: true },
                          );
                        }}
                        noValidate
                      >
                        <p>
                          {t("This immediately closes an active control session and invalidates enrollment credentials. It does not uninstall the remote agent or stop its current sing-box process.")}
                        </p>
                        <label className="danger-confirm">
                          <input
                            type="checkbox"
                            checked={confirmRevoke}
                            onChange={(e) => setConfirmRevoke(e.target.checked)}
                            required
                          />
                          <span>{t("I understand that this agent will need a new enrollment credential to reconnect.")}</span>
                        </label>
                        <button
                          type="submit"
                          className="button button--danger button--full"
                          disabled={!confirmRevoke || Boolean(actionsBusy)}
                        >
                          {agent.RevokeLabel}
                        </button>
                      </form>
                    )}
                  </div>
                </details>
              </div>
            </Modal>
          </>
        )}
      </AsyncState>
    </AppLayout>
  );
};
