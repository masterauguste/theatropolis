import React, { useState } from "react";
import { Link, useLocation, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { CopyButton } from "../components/CopyButton";
import { Modal } from "../components/Modal";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const UserSubscriptionPage: React.FC = () => {
  const { userId = "" } = useParams();
  const location = useLocation();
  const isAdminSub = location.pathname === "/subscriptions/admin";
  const url = isAdminSub ? "/subscriptions/admin" : `/users/${encodeURIComponent(userId)}/subscription/nodes`;

  const { t, countLabel, submitMutation } = useApp();
  const { data, loading, error, reload } = usePageData(url);

  const sub = data?.UserSubscription;
  const [resetOpen, setResetOpen] = useState(false);
  const [revokeOpen, setRevokeOpen] = useState(false);
  const [actionError, setActionError] = useState("");
  const [busy, setBusy] = useState(false);

  const runAction = async (endpoint: string, fields: Record<string, string>, onDone?: () => void) => {
    if (busy) return;
    setBusy(true);
    setActionError("");
    try {
      await submitMutation(endpoint, fields);
      onDone?.();
      await reload();
    } catch (err) {
      setActionError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <AppLayout activeNav={isAdminSub ? "subscriptions" : "users"}>
      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        {sub && (
          <>
            <nav className="breadcrumbs" aria-label={t("Breadcrumb")}>
              {sub.System ? (
                <>
                  <Link to="/subscriptions">{t("Subscriptions")}</Link>
                  <span aria-hidden="true">/</span>
                  <span>{t("My Subscription")}</span>
                </>
              ) : (
                <>
                  <Link to="/users">{t("Users")}</Link>
                  <span aria-hidden="true">/</span>
                  <Link to={`/users/${encodeURIComponent(sub.UserID)}`}>{sub.UserName}</Link>
                  <span aria-hidden="true">/</span>
                  <span>{t("Subscription")}</span>
                </>
              )}
            </nav>

            <header className="page-header">
              <div>
                <p className="eyebrow">
                  {sub.System ? t("Administrator Subscription") : t("User Subscription")}
                </p>
                <h1>{sub.System ? t("My Subscription") : sub.UserName}</h1>
              </div>
            </header>

            {actionError && (
              <div className="notice notice--error" role="alert">
                {actionError}
              </div>
            )}

            <section className="panel subscription-links-panel">
              <div className="panel__header">
                <h2>{t("Subscription links")}</h2>
                <span className={`membership-status membership-status--${sub.Enabled ? "active" : "disabled"}`}>
                  {sub.Enabled ? t("Active") : t("Inactive")}
                </span>
              </div>

              {sub.Enabled ? (
                <>
                  <div className="subscription-link-grid">
                    <article>
                      <span className="protocol-badge">Clash</span>
                      <code>{sub.ClashURL}</code>
                      <CopyButton value={sub.ClashURL} />
                    </article>
                    <article>
                      <span className="protocol-badge">Surge</span>
                      <code>{sub.SurgeURL}</code>
                      <CopyButton value={sub.SurgeURL} />
                    </article>
                    <article>
                      <span className="protocol-badge">sing-box</span>
                      <code>{sub.SingBoxURL}</code>
                      <CopyButton value={sub.SingBoxURL} />
                    </article>
                  </div>
                  {!sub.System && (
                    <div className="panel__actions">
                      <button type="button" className="button button--danger" onClick={() => setResetOpen(true)}>
                        {t("Reset subscription link")}
                      </button>
                      <button type="button" className="button button--danger" onClick={() => setRevokeOpen(true)}>
                        {t("Revoke link")}
                      </button>
                    </div>
                  )}
                </>
              ) : (
                <div className="panel__empty panel__empty--action">
                  <strong>{t("No subscription link")}</strong>
                  <button
                    type="button"
                    className="button button--primary"
                    disabled={busy}
                    onClick={() => void runAction(`/users/${encodeURIComponent(sub.UserID)}/subscription/token`, {})}
                  >
                    {t("Create subscription")}
                  </button>
                </div>
              )}
            </section>

            <section className="panel">
              <div className="panel__header">
                <h2>{t("Nodes")}</h2>
                <span className="panel__count">{countLabel(sub.Nodes?.length || 0, "node")}</span>
              </div>
              {sub.Nodes && sub.Nodes.length > 0 ? (
                <div className="subscription-node-list">
                  {sub.Nodes.map((node) => (
                    <article key={`${node.AgentID}-${node.Name}`} className="subscription-node">
                      <span className="node-role-chip__mark" aria-hidden="true">
                        {node.Initial}
                      </span>
                      <div>
                        <strong>{node.Name}</strong>
                        <small>
                          {node.Protocol}
                          {node.AgentName ? ` · ${node.AgentName}` : ""}
                        </small>
                      </div>
                      <div className="subscription-node__families">
                        {(node.Addresses || []).map((addr) => (
                          <span key={addr}>{addr}</span>
                        ))}
                      </div>
                      <span className={`membership-status membership-status--${node.StatusCSS}`}>
                        {node.Status}
                      </span>
                    </article>
                  ))}
                </div>
              ) : (
                <div className="panel__empty">
                  <strong>{t("No Node Access")}</strong>
                  {!sub.System && (
                    <Link className="button-link" to={`/users/${encodeURIComponent(sub.UserID)}`}>
                      {t("Assign a Node")}
                    </Link>
                  )}
                </div>
              )}
            </section>

            <Modal
              open={resetOpen}
              onClose={() => setResetOpen(false)}
              eyebrow={t("Subscription link")}
              title={t("Reset subscription link?")}
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setResetOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={busy}
                    onClick={() =>
                      void runAction(
                        `/users/${encodeURIComponent(sub.UserID)}/subscription/reset`,
                        { confirm_reset: "yes" },
                        () => setResetOpen(false),
                      )
                    }
                  >
                    {t("Reset link and credentials")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                <p>
                  {t("The current subscription URLs and every Proxy Node credential for this user will stop working immediately.")}
                </p>
              </div>
            </Modal>

            <Modal
              open={revokeOpen}
              onClose={() => setRevokeOpen(false)}
              eyebrow={t("Subscription link")}
              title={t("Revoke link")}
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setRevokeOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={busy}
                    onClick={() =>
                      void runAction(
                        `/users/${encodeURIComponent(sub.UserID)}/subscription/revoke`,
                        {},
                        () => setRevokeOpen(false),
                      )
                    }
                  >
                    {t("Revoke link")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                <p>{t("All three format links will stop working immediately.")}</p>
              </div>
            </Modal>
          </>
        )}
      </AsyncState>
    </AppLayout>
  );
};
