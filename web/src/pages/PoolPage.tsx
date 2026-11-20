import React, { useState } from "react";
import { ApiError } from "../api/client";
import type { PoolInboundView } from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { Modal } from "../components/Modal";
import { useApp, useDirtyForm } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const PoolPage: React.FC = () => {
  const { t, submitMutation } = useApp();
  const { data: shellData, reload: reloadShell } = usePageData("/pool");
  const { data: contentData, loading: contentLoading, error: contentError, reload: reloadContent } =
    usePageData("/pool/content");

  const [name, setName] = useState("");
  const [remark, setRemark] = useState("");
  const [outboundJSON, setOutboundJSON] = useState("");
  const [formError, setFormError] = useState("");
  const [saving, setSaving] = useState(false);

  const [deleteConfirm, setDeleteConfirm] = useState<Record<string, boolean>>({});
  const [selectedInbound, setSelectedInbound] = useState<PoolInboundView | null>(null);
  const [overrideV4, setOverrideV4] = useState("");
  const [overrideV6, setOverrideV6] = useState("");
  const [overrideError, setOverrideError] = useState("");

  useDirtyForm("pool-manual-form", Boolean(name || remark || outboundJSON) && !saving);

  const handleSaveManual = async (e: React.FormEvent) => {
    e.preventDefault();
    if (saving) return;
    setSaving(true);
    setFormError("");
    try {
      await submitMutation("/pool", {
        name: name.trim(),
        remark: remark.trim(),
        outbound_json: outboundJSON,
      });
      setName("");
      setRemark("");
      setOutboundJSON("");
      await Promise.all([reloadShell(), reloadContent()]);
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : t("Could not save pool entry."));
    } finally {
      setSaving(false);
    }
  };

  const handleDeleteManual = async (entryName: string) => {
    if (!deleteConfirm[entryName] || saving) return;
    setSaving(true);
    setFormError("");
    try {
      await submitMutation("/pool/delete", { name: entryName, confirm_delete: "yes" });
      await Promise.all([reloadShell(), reloadContent()]);
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : t("Could not delete pool entry."));
    } finally {
      setSaving(false);
    }
  };

  const handleSaveOverrides = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedInbound || saving) return;
    setSaving(true);
    setOverrideError("");
    try {
      await submitMutation(selectedInbound.AddressURL, {
        override_ipv4: overrideV4.trim(),
        override_ipv6: overrideV6.trim(),
      });
      setSelectedInbound(null);
      await reloadContent();
    } catch (err) {
      setOverrideError(err instanceof ApiError ? err.message : t("Could not save address overrides."));
    } finally {
      setSaving(false);
    }
  };

  const pool = shellData?.Pool;
  const fleetPool = contentData?.Pool;
  const inbounds = fleetPool?.Inbounds || [];
  const manual = pool?.Manual || [];

  return (
    <AppLayout activeNav="pool" width="narrow">
      <header className="page-header page-header--compact">
        <div>
          <p className="eyebrow">{t("Fleet")}</p>
          <h1>{t("Outbound pool")}</h1>
        </div>
      </header>

      {shellData && !pool ? (
        <section className="panel">
          <p className="muted">{t("The outbound pool is not available on this master.")}</p>
        </section>
      ) : (
        <section className="panel settings-panel">
          <div className="panel__header">
            <h2>{t("Fleet outbound pool")}</h2>
          </div>

          {formError && (
            <div className="notice notice--error" role="alert">
              {formError}
            </div>
          )}

          <AsyncState
            loading={contentLoading}
            error={contentError}
            loadingLabel={t("Loading fleet outbounds…")}
            onRetry={() => void reloadContent()}
          >
            {fleetPool?.Diagnostics && fleetPool.Diagnostics.length > 0 && (
              <small className="field-warning">
                Some pool entries were skipped: {fleetPool.Diagnostics.join("; ")}
              </small>
            )}
            {inbounds.length > 0 ? (
              <div className="pool-summary-grid">
                {inbounds.map((item) => (
                  <button
                    key={item.DialogID}
                    type="button"
                    className="pool-summary-card"
                    onClick={() => {
                      setSelectedInbound(item);
                      setOverrideV4(item.OverrideV4 || "");
                      setOverrideV6(item.OverrideV6 || "");
                      setOverrideError("");
                    }}
                  >
                    <span className="pool-summary-card__heading">
                      <strong>{item.AgentName}</strong>
                      <code>{item.Tag}</code>
                    </span>
                    <span className="pool-summary-card__facts">
                      <span>
                        <small>{t("Protocol")}</small>
                        <strong>{item.Type}</strong>
                      </span>
                      <span>
                        <small>{t("Port")}</small>
                        <strong>{item.Port}</strong>
                      </span>
                      <span>
                        <small>IPv4</small>
                        {item.IPv4 ? <code>{item.IPv4}</code> : <span className="muted">—</span>}
                      </span>
                      <span>
                        <small>IPv6</small>
                        {item.IPv6 ? <code>{item.IPv6}</code> : <span className="muted">—</span>}
                      </span>
                    </span>
                    <span className="pool-summary-card__action">
                      {t("View users and address settings")} <span aria-hidden="true">→</span>
                    </span>
                  </button>
                ))}
              </div>
            ) : (
              <p className="muted">
                {t("No deployed inbounds are in the pool yet. Deploy a configuration with Shadowsocks, AnyTLS, or Hysteria2 inbounds to share them here.")}
              </p>
            )}
          </AsyncState>

          <h3>{t("Manual entries")}</h3>
          {manual.length > 0 ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th scope="col">{t("Name")}</th>
                    <th scope="col">{t("Remark")}</th>
                    <th scope="col">{t("Protocol")}</th>
                    <th scope="col">{t("Outbound JSON")}</th>
                    <th scope="col">
                      <span className="visually-hidden">{t("Actions")}</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {manual.map((entry) => (
                    <tr key={entry.Name}>
                      <td>
                        <code>manual/{entry.Name}</code>
                      </td>
                      <td>{entry.Remark || <span className="muted">—</span>}</td>
                      <td>
                        {entry.Type}
                        {entry.Port ? ` · ${entry.Port}` : ""}
                      </td>
                      <td>
                        <code className="pool-outbound-json">{entry.Outbound}</code>
                      </td>
                      <td>
                        <div className="pool-delete-form">
                          <label className="danger-confirm">
                            <input
                              type="checkbox"
                              checked={Boolean(deleteConfirm[entry.Name])}
                              onChange={(e) =>
                                setDeleteConfirm((prev) => ({ ...prev, [entry.Name]: e.target.checked }))
                              }
                            />
                            <span>{t("Confirm")}</span>
                          </label>
                          <button
                            type="button"
                            className="button-link button-link--danger"
                            disabled={!deleteConfirm[entry.Name] || saving}
                            onClick={() => void handleDeleteManual(entry.Name)}
                          >
                            {t("Delete")}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="muted">{t("No manual entries yet.")}</p>
          )}

          <form className="stack" onSubmit={(e) => void handleSaveManual(e)} noValidate>
            <label className="field">
              <span>{t("Entry name")}</span>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="backup-relay"
                maxLength={128}
                required
              />
            </label>
            <label className="field">
              <span>
                {t("Remark")} <span className="optional-tag">{t("Optional")}</span>
              </span>
              <input
                value={remark}
                onChange={(e) => setRemark(e.target.value)}
                placeholder="Singapore backup"
                maxLength={256}
              />
            </label>
            <label className="field">
              <span>{t("Proxy URI or outbound JSON")}</span>
              <textarea
                className="resize-none"
                data-outbound-field="json"
                rows={4}
                spellCheck={false}
                value={outboundJSON}
                onChange={(e) => setOutboundJSON(e.target.value)}
                placeholder="ss://method:password@example.com:8388#Singapore"
                required
              />
            </label>
            <button className="button button--secondary" type="submit" disabled={saving}>
              {saving ? t("Saving…") : t("Save pool entry")}
            </button>
          </form>
        </section>
      )}

      <Modal
        open={Boolean(selectedInbound)}
        onClose={() => setSelectedInbound(null)}
        eyebrow={selectedInbound?.AgentName}
        title={selectedInbound?.Tag || ""}
        className="resource-modal"
        footer={
          <button type="button" className="button button--secondary" onClick={() => setSelectedInbound(null)}>
            {t("Close")}
          </button>
        }
      >
        {selectedInbound && (
          <div className="modal__body stack">
            {overrideError && (
              <div className="notice notice--error" role="alert">
                {overrideError}
              </div>
            )}
            <section>
              <h3>{t("Server addresses")}</h3>
              <div className="pool-address-grid">
                <span>
                  <small>IPv4</small>
                  {selectedInbound.IPv4 ? <code>{selectedInbound.IPv4}</code> : <span className="muted">{t("Unavailable")}</span>}
                </span>
                <span>
                  <small>IPv6</small>
                  {selectedInbound.IPv6 ? <code>{selectedInbound.IPv6}</code> : <span className="muted">{t("Unavailable")}</span>}
                </span>
              </div>
            </section>
            <section>
              <h3>{t("Users")}</h3>
              <div className="pool-user-list">
                {(selectedInbound.Users || []).map((u) => (
                  <div key={u.Ref} className="pool-user">
                    <strong>{u.Label}</strong>
                  </div>
                ))}
              </div>
            </section>
            <section>
              <h3>{t("Address overrides")}</h3>
              <form className="stack" onSubmit={(e) => void handleSaveOverrides(e)} noValidate>
                <div className="builder-fields">
                  <label className="field">
                    <span>{t("IPv4 override")}</span>
                    <input
                      value={overrideV4}
                      onChange={(e) => setOverrideV4(e.target.value)}
                      placeholder={t("Automatic")}
                      maxLength={64}
                    />
                  </label>
                  <label className="field">
                    <span>{t("IPv6 override")}</span>
                    <input
                      value={overrideV6}
                      onChange={(e) => setOverrideV6(e.target.value)}
                      placeholder={t("Automatic")}
                      maxLength={64}
                    />
                  </label>
                </div>
                <button type="submit" className="button button--primary" disabled={saving}>
                  {t("Save address overrides")}
                </button>
              </form>
            </section>
          </div>
        )}
      </Modal>
    </AppLayout>
  );
};
