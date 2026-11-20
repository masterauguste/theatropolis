import React, { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, downloadArchiveForm, fetchJSON, submitMultipart } from "../api/client";
import type { VersionCatalogResponse } from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { Modal } from "../components/Modal";
import { SecretInput } from "../components/SecretInput";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const SettingsPage: React.FC = () => {
  const { t, locale, session, submitMutation } = useApp();
  const { data, loading, error, reload } = usePageData("/settings");

  // Master version catalog
  const [checkingCatalog, setCheckingCatalog] = useState(false);
  const [latestVersion, setLatestVersion] = useState("");
  const [catalogWarning, setCatalogWarning] = useState("");
  const [updateProgress, setUpdateProgress] = useState("");
  const [updatingMaster, setUpdatingMaster] = useState(false);

  // Modals
  const [adminAccessOpen, setAdminAccessOpen] = useState(false);
  const [migrationMenuOpen, setMigrationMenuOpen] = useState(false);
  const [migrationSourceOpen, setMigrationSourceOpen] = useState(false);
  const [migrationDestOpen, setMigrationDestOpen] = useState(false);
  const [clearLogOpen, setClearLogOpen] = useState(false);

  // Migration state
  const [exportPass, setExportPass] = useState("");
  const [exportConfirm, setExportConfirm] = useState("");
  const [cutoverAddr, setCutoverAddr] = useState("");
  const [cutoverConfirm, setCutoverConfirm] = useState("");
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [restorePass, setRestorePass] = useState("");
  const [restoreConfirm, setRestoreConfirm] = useState("");
  const [modalNotice, setModalNotice] = useState("");
  const [modalError, setModalError] = useState("");
  const [busy, setBusy] = useState("");
  const [pageNotice, setPageNotice] = useState("");

  const loadMasterCatalog = useCallback(async () => {
    setCheckingCatalog(true);
    setCatalogWarning("");
    try {
      const res = await fetchJSON<VersionCatalogResponse>("/settings/versions?catalog=agent");
      setLatestVersion(res.latest_version || "");
      if (res.agent_catalog_warning) setCatalogWarning(res.agent_catalog_warning);
    } catch (err) {
      setLatestVersion("");
      setCatalogWarning(err instanceof Error ? err.message : t("unavailable"));
    } finally {
      setCheckingCatalog(false);
    }
  }, [t]);

  useEffect(() => {
    void loadMasterCatalog();
  }, [loadMasterCatalog]);

  const pollMasterUpdate = (statusUrl: string) => {
    const check = async () => {
      try {
        const res = await fetchJSON<{ status?: string; diagnostic?: string; running_version?: string }>(statusUrl);
        if (res.status === "failed") {
          setUpdateProgress(res.diagnostic || t("Master update failed."));
          setUpdatingMaster(false);
          return;
        }
        if (res.status === "applied") {
          window.location.reload();
          return;
        }
      } catch {
        // Master is restarting — keep polling.
      }
      window.setTimeout(() => void check(), 2500);
    };
    window.setTimeout(() => void check(), 2500);
  };

  const handleMasterUpdate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (updatingMaster) return;
    setUpdatingMaster(true);
    setUpdateProgress(t("Scheduling…"));
    try {
      const res = await fetchJSON<{ status_url?: string; error?: string }>("/master-update", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
        body: new URLSearchParams({ csrf_token: data?.CSRFToken || session.csrfToken || "" }),
      });
      if (!res.status_url) throw new Error(res.error || t("master update could not be scheduled"));
      setUpdateProgress(t("Installing the update. Waiting for the master to restart…"));
      pollMasterUpdate(res.status_url);
    } catch (err) {
      setUpdateProgress(err instanceof Error ? err.message : t("master update could not be scheduled"));
      setUpdatingMaster(false);
    }
  };

  const handleToggleAdminAccess = async () => {
    if (!data || busy) return;
    setBusy("admin-access");
    setModalError("");
    try {
      await submitMutation("/settings/administrator-proxy-access", {
        enabled: data.AdministratorProxyAccessEnabled ? "false" : "true",
      });
      setAdminAccessOpen(false);
      await reload();
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setBusy("");
    }
  };

  const handleExportArchive = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy("export");
    setModalError("");
    setModalNotice("");
    try {
      await downloadArchiveForm("/settings/migration/export", {
        csrf_token: data?.CSRFToken || session.csrfToken || "",
        passphrase: exportPass,
        passphrase_confirm: exportConfirm,
      });
      setModalNotice(t("Archive ready. Check your browser downloads."));
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : t("Export failed."));
    } finally {
      setBusy("");
    }
  };

  const handleCutover = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busy) return;
    setBusy("cutover");
    setModalError("");
    setModalNotice("");
    try {
      const res = await submitMutation("/settings/migration/cutover", {
        master_address: cutoverAddr.trim(),
        confirmation: cutoverConfirm.trim(),
      });
      setModalNotice(res.data?.MigrationNotice || res.notice || t("Changes saved."));
      await reload();
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : t("Cutover failed."));
    } finally {
      setBusy("");
    }
  };

  const handleRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!restoreFile || busy) return;
    setBusy("restore");
    setModalError("");
    setModalNotice("");
    try {
      const fd = new FormData();
      fd.set("csrf_token", data?.CSRFToken || session.csrfToken || "");
      fd.set("archive", restoreFile);
      fd.set("passphrase", restorePass);
      fd.set("confirmation", restoreConfirm.trim());
      const res = await submitMultipart("/settings/migration/restore", fd);
      setModalNotice(res.notice || res.data?.MigrationNotice || t("Restarting Master…"));
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : t("Restore failed."));
    } finally {
      setBusy("");
    }
  };

  const handleClearLog = async () => {
    if (busy) return;
    setBusy("clear-log");
    try {
      await submitMutation("/settings/accounting-errors/clear", { confirmation: "clear" });
      setClearLogOpen(false);
      setPageNotice(t("Accounting error log cleared."));
      await reload();
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setBusy("");
    }
  };

  const isUpToDate = Boolean(latestVersion && data?.MasterVersion && latestVersion === data.MasterVersion);
  const canUpdateMaster = Boolean(latestVersion && !isUpToDate && !checkingCatalog && !updatingMaster);

  return (
    <AppLayout activeNav="settings" width="narrow">
      <header className="page-header page-header--compact">
        <div>
          <p className="eyebrow">{t("Global settings")}</p>
          <h1>{t("Master")}</h1>
        </div>
        <div className="page-header__actions">
          <button
            type="button"
            className="button button--secondary button--small"
            onClick={() => {
              setModalError("");
              setModalNotice("");
              setMigrationMenuOpen(true);
            }}
          >
            {t("Migration")}
          </button>
        </div>
      </header>

      {(pageNotice || data?.Notice || data?.MigrationNotice) && (
        <div className="notice notice--success" role="status">
          {pageNotice || data?.Notice || data?.MigrationNotice}
        </div>
      )}

      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        {data && (
          <>
            <section className="panel settings-panel">
              <div className="panel__header">
                <h2>{t("Master software")}</h2>
              </div>
              {data.MasterUpdate && (
                <>
                  <dl className="detail-list detail-list--compact">
                    <div>
                      <dt>{t("Last update")}</dt>
                      <dd>
                        <span className={`status status--${data.MasterUpdate.StatusClass}`}>
                          <span aria-hidden="true" />
                          {data.MasterUpdate.StatusLabel}
                        </span>
                      </dd>
                    </div>
                    <div>
                      <dt>{t("Target")}</dt>
                      <dd>
                        <code>{data.MasterUpdate.TargetVersion}</code>
                      </dd>
                    </div>
                    <div>
                      <dt>{t("Updated")}</dt>
                      <dd>{data.MasterUpdate.UpdatedAt}</dd>
                    </div>
                  </dl>
                  {data.MasterUpdate.Diagnostic && (
                    <div className="diagnostic">
                      <strong>{t("Update diagnostic")}</strong>
                      <pre>{data.MasterUpdate.Diagnostic}</pre>
                    </div>
                  )}
                </>
              )}

              <dl className="detail-list settings-version-list">
                <div>
                  <dt>{t("Running version")}</dt>
                  <dd>
                    <code>{data.MasterVersion}</code>
                  </dd>
                </div>
                <div>
                  <dt>{t("Latest available")}</dt>
                  <dd className="inline-loading">
                    {checkingCatalog && <span className="loading-spinner loading-spinner--small" aria-hidden="true" />}
                    <code>{checkingCatalog ? t("checking…") : latestVersion || t("unavailable")}</code>
                  </dd>
                </div>
              </dl>

              <button
                type="button"
                className="button button--secondary button--small"
                data-master-version-refresh=""
                disabled={checkingCatalog}
                onClick={() => void loadMasterCatalog()}
              >
                {checkingCatalog ? t("Checking…") : t("Check again")}
              </button>
              {catalogWarning && <small className="field-warning">{catalogWarning}</small>}

              <form onSubmit={(e) => void handleMasterUpdate(e)} noValidate>
                <button type="submit" className="button button--primary" disabled={!canUpdateMaster}>
                  {checkingCatalog
                    ? t("Checking for updates…")
                    : isUpToDate
                      ? t("Master is up to date")
                      : latestVersion
                        ? locale === "zh-CN"
                          ? `将主控端更新至 ${latestVersion}`
                          : `Update master to ${latestVersion}`
                        : t("Latest version unavailable")}
                </button>
              </form>
              {updateProgress && (
                <div className="notice" aria-live="polite">
                  {updateProgress}
                </div>
              )}
            </section>

            <section className="panel settings-panel settings-toggle-panel">
              <div className="settings-toggle-row">
                <div>
                  <h2>{t("Administrator Proxy Access")}</h2>
                  <p>{t("All Proxy Nodes · Unlimited")}</p>
                </div>
                <button
                  type="button"
                  className="settings-toggle"
                  role="switch"
                  aria-checked={data.AdministratorProxyAccessEnabled}
                  aria-label={t("Administrator Proxy Access")}
                  onClick={() => {
                    setModalError("");
                    setAdminAccessOpen(true);
                  }}
                >
                  <span className="settings-toggle__track" aria-hidden="true">
                    <span />
                  </span>
                  <span className="settings-toggle__state">
                    {data.AdministratorProxyAccessEnabled ? t("Enabled") : t("Off")}
                  </span>
                </button>
              </div>
            </section>

            <section className="panel settings-panel">
              <div className="panel__header">
                <h2>{t("Accounting errors")}</h2>
                <div className="panel__header-actions">
                  <span className="panel__count">
                    {data.AccountingFailureTotal} {t("recorded")}
                  </span>
                  {data.AccountingFailureTotal > 0 && (
                    <button
                      type="button"
                      className="button button--danger button--small"
                      onClick={() => setClearLogOpen(true)}
                    >
                      {t("Clear Log")}
                    </button>
                  )}
                </div>
              </div>

              {data.AccountingFailures && data.AccountingFailures.length > 0 ? (
                <>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>{t("Time")}</th>
                          <th>{t("Server")}</th>
                          <th>{t("Failure")}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.AccountingFailures.map((item, idx) => (
                          <tr key={`${item.OccurredAt}-${item.AgentID}-${idx}`}>
                            <td>
                              <time>{item.OccurredAt}</time>
                            </td>
                            <td>
                              <Link to={`/servers/${encodeURIComponent(item.AgentID)}/manage`}>{item.AgentName}</Link>
                            </td>
                            <td>{item.Reason}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {data.AccountingFailureTotal > 50 && (
                    <p className="form-help">{t("Showing the newest 50 entries.")}</p>
                  )}
                </>
              ) : (
                <div className="panel__empty">
                  <p>{t("No accounting errors have been recorded.")}</p>
                </div>
              )}
            </section>

            {/* Modals */}
            <Modal
              open={adminAccessOpen}
              onClose={() => setAdminAccessOpen(false)}
              eyebrow={t("Administrator Access")}
              title={
                data.AdministratorProxyAccessEnabled ? t("Disable Proxy Access?") : t("Enable Proxy Access?")
              }
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setAdminAccessOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className={`button ${data.AdministratorProxyAccessEnabled ? "button--danger" : "button--primary"}`}
                    disabled={busy === "admin-access"}
                    onClick={() => void handleToggleAdminAccess()}
                  >
                    {data.AdministratorProxyAccessEnabled ? t("Disable Access") : t("Enable Access")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                {modalError && <div className="notice notice--error">{modalError}</div>}
                <p>
                  {data.AdministratorProxyAccessEnabled
                    ? t("This revokes the administrator credential and configuration subscription on every Proxy Node.")
                    : t("This grants the administrator unlimited, non-expiring access to every Proxy Node.")}
                </p>
              </div>
            </Modal>

            <Modal
              open={migrationMenuOpen}
              onClose={() => setMigrationMenuOpen(false)}
              eyebrow={t("Master")}
              title={t("Migration")}
              className="migration-menu-dialog"
            >
              <div className="modal__body migration-choices">
                <button
                  type="button"
                  className="migration-choice"
                  onClick={() => {
                    setMigrationMenuOpen(false);
                    setModalError("");
                    setModalNotice("");
                    setMigrationSourceOpen(true);
                  }}
                >
                  <span className="migration-choice__direction" aria-hidden="true">↗</span>
                  <span>{t("Move From This Master")}</span>
                  <span className="migration-choice__arrow" aria-hidden="true">→</span>
                </button>
                <button
                  type="button"
                  className="migration-choice"
                  onClick={() => {
                    setMigrationMenuOpen(false);
                    setModalError("");
                    setModalNotice("");
                    setMigrationDestOpen(true);
                  }}
                >
                  <span className="migration-choice__direction" aria-hidden="true">↙</span>
                  <span>{t("Receive On This Master")}</span>
                  <span className="migration-choice__arrow" aria-hidden="true">→</span>
                </button>
              </div>
            </Modal>

            <Modal
              open={migrationSourceOpen}
              onClose={() => setMigrationSourceOpen(false)}
              eyebrow={t("Source Master")}
              title={t("Move From This Master")}
              className="migration-source-dialog"
              footer={
                <button type="button" className="button button--secondary" onClick={() => setMigrationSourceOpen(false)}>
                  {t("Close")}
                </button>
              }
            >
              <div className="modal__body migration-source-actions">
                {modalError && <div className="notice notice--error">{modalError}</div>}
                {modalNotice && <div className="notice notice--success">{modalNotice}</div>}
                <section className="migration-step">
                  <div className="migration-step__heading">
                    <span>1</span>
                    <h3>{t("Download Archive")}</h3>
                  </div>
                  <form className="stack" onSubmit={(e) => void handleExportArchive(e)} noValidate>
                    <label className="field">
                      <span>{t("Passphrase")}</span>
                      <SecretInput
                        secretLabel="passphrase"
                        minLength={15}
                        maxLength={512}
                        autoComplete="new-password"
                        value={exportPass}
                        onChange={(e) => setExportPass(e.target.value)}
                        required
                      />
                    </label>
                    <label className="field">
                      <span>{t("Confirm Passphrase")}</span>
                      <SecretInput
                        secretLabel="passphrase"
                        minLength={15}
                        maxLength={512}
                        autoComplete="new-password"
                        value={exportConfirm}
                        onChange={(e) => setExportConfirm(e.target.value)}
                        required
                      />
                    </label>
                    <button type="submit" className="button button--secondary" disabled={Boolean(busy)}>
                      {busy === "export" ? t("Exporting…") : t("Download Archive")}
                    </button>
                  </form>
                </section>

                <section className="migration-step migration-step--danger">
                  <div className="migration-step__heading">
                    <span>2</span>
                    <h3>{t("Switch Online Servers")}</h3>
                  </div>
                  <form className="stack" onSubmit={(e) => void handleCutover(e)} noValidate>
                    <label className="field">
                      <span>{t("New Master")}</span>
                      <input
                        value={cutoverAddr}
                        onChange={(e) => setCutoverAddr(e.target.value)}
                        placeholder="master.example.com:443"
                        autoComplete="off"
                        required
                      />
                    </label>
                    <label className="field">
                      <span>{t("Confirmation")}</span>
                      <input
                        value={cutoverConfirm}
                        onChange={(e) => setCutoverConfirm(e.target.value)}
                        placeholder="MIGRATE"
                        autoComplete="off"
                        required
                      />
                    </label>
                    <button type="submit" className="button button--danger" disabled={Boolean(busy)}>
                      {busy === "cutover" ? t("Switching…") : t("Switch Online Servers")}
                    </button>
                  </form>
                </section>
              </div>
            </Modal>

            <Modal
              open={migrationDestOpen}
              onClose={() => setMigrationDestOpen(false)}
              eyebrow={t("Destination Master")}
              title={t("Receive Migration")}
              className="migration-destination-dialog"
            >
              <form onSubmit={(e) => void handleRestore(e)} noValidate>
                <div className="modal__body stack">
                  {modalError && <div className="notice notice--error">{modalError}</div>}
                  {modalNotice && <div className="notice notice--success">{modalNotice}</div>}
                  <label className="field">
                    <span>{t("Archive")}</span>
                    <input
                      type="file"
                      accept=".zip,application/zip"
                      required
                      onChange={(e) => setRestoreFile(e.target.files?.[0] || null)}
                    />
                  </label>
                  <label className="field">
                    <span>{t("Passphrase")}</span>
                    <SecretInput
                      secretLabel="passphrase"
                      minLength={15}
                      maxLength={512}
                      autoComplete="current-password"
                      value={restorePass}
                      onChange={(e) => setRestorePass(e.target.value)}
                      required
                    />
                  </label>
                  <label className="field">
                    <span>{t("Confirmation")}</span>
                    <input
                      value={restoreConfirm}
                      onChange={(e) => setRestoreConfirm(e.target.value)}
                      placeholder="RESTORE"
                      autoComplete="off"
                      required
                    />
                  </label>
                </div>
                <footer className="modal__footer">
                  <button type="button" className="button button--secondary" onClick={() => setMigrationDestOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button type="submit" className="button button--danger" disabled={Boolean(busy) || !restoreFile}>
                    {busy === "restore" ? t("Restoring…") : t("Restore And Restart")}
                  </button>
                </footer>
              </form>
            </Modal>

            <Modal
              open={clearLogOpen}
              onClose={() => setClearLogOpen(false)}
              eyebrow={t("Accounting Errors")}
              title={t("Clear Error Log?")}
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setClearLogOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={busy === "clear-log"}
                    onClick={() => void handleClearLog()}
                  >
                    {t("Clear Log")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                <p>{t("This permanently deletes the complete accounting error log.")}</p>
              </div>
            </Modal>
          </>
        )}
      </AsyncState>
    </AppLayout>
  );
};
