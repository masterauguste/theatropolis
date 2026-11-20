import React, { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import type { UserProxyAccessView } from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { CopyButton } from "../components/CopyButton";
import { DailyUsageTable } from "../components/DailyUsageTable";
import { LocalTime } from "../components/LocalTime";
import {
  MembershipPlanFields,
  planDraftToFields,
  planToDraft,
  type MembershipPlanDraft,
} from "../components/MembershipPlanFields";
import { Modal } from "../components/Modal";
import { SelectBox } from "../components/SelectBox";
import { useApp, useDirtyForm } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const UserDetailPage: React.FC = () => {
  const { userId = "" } = useParams();
  const navigate = useNavigate();
  const { t, countLabel, submitMutation } = useApp();
  const { data, loading, error, reload } = usePageData(`/users/${encodeURIComponent(userId)}`);
  const user = data?.EndUser;

  const [renameName, setRenameName] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [pageError, setPageError] = useState("");
  const [busy, setBusy] = useState("");

  // Modals
  const [activeAccess, setActiveAccess] = useState<UserProxyAccessView | null>(null);
  const [confirmCredResetProxyId, setConfirmCredResetProxyId] = useState<string | null>(null);
  const [grantOpen, setGrantOpen] = useState(false);
  const [resetAllCredsOpen, setResetAllCredsOpen] = useState(false);
  const [resetLoginOpen, setResetLoginOpen] = useState(false);
  const [resetTokenOpen, setResetTokenOpen] = useState(false);

  // Per-role plan & extension drafts
  const [rolePlan, setRolePlan] = useState<MembershipPlanDraft>(planToDraft());
  const [extendValue, setExtendValue] = useState("1");
  const [extendUnit, setExtendUnit] = useState("months");
  const [modalError, setModalError] = useState("");

  // Grant role modal state
  const [grantSearch, setGrantSearch] = useState("");
  const [grantProxyId, setGrantProxyId] = useState("");
  const [grantPlan, setGrantPlan] = useState<MembershipPlanDraft>(planToDraft());

  useEffect(() => {
    if (user) {
      setRenameName(user.Name);
      setGrantPlan(planToDraft(user.DefaultPlan));
      if (activeAccess) {
        const updated = (user.AssignedAccess || []).find((a) => a.ProxyID === activeAccess.ProxyID) || null;
        setActiveAccess(updated);
        if (updated) setRolePlan(planToDraft(updated.Plan));
      }
    }
  }, [user]);

  useDirtyForm("user-rename", Boolean(user && renameName.trim() !== user.Name));

  const runAction = async (
    key: string,
    url: string,
    fields: Record<string, string>,
    options?: { onDone?: () => void; followRedirect?: boolean; modalTarget?: boolean },
  ) => {
    if (busy) return;
    setBusy(key);
    if (options?.modalTarget) setModalError("");
    else setPageError("");
    try {
      const res = await submitMutation(url, fields);
      if (options?.followRedirect && res.redirect) {
        navigate(res.redirect);
        return;
      }
      options?.onDone?.();
      await reload();
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : t("Request failed.");
      if (options?.modalTarget) setModalError(msg);
      else setPageError(msg);
    } finally {
      setBusy("");
    }
  };

  const openRoleModal = (access: UserProxyAccessView) => {
    setActiveAccess(access);
    setRolePlan(planToDraft(access.Plan));
    setExtendValue("1");
    setExtendUnit("months");
    setModalError("");
  };

  const openGrantModal = () => {
    setGrantSearch("");
    setGrantProxyId("");
    setGrantPlan(planToDraft(user?.DefaultPlan));
    setModalError("");
    setGrantOpen(true);
  };

  const assigned = user?.AssignedAccess || [];
  const available = user?.AvailableAccess || [];
  const filteredAvailable = available.filter((item) => {
    const q = grantSearch.trim().toLocaleLowerCase();
    if (!q) return true;
    return `${item.ProxyName} ${item.EntranceLabel} ${item.EntranceAgent}`.toLocaleLowerCase().includes(q);
  });

  return (
    <AppLayout activeNav="users">
      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        {user && (
          <>
            <nav className="breadcrumbs" aria-label={t("Breadcrumb")}>
              <Link to="/users">{t("Users")}</Link>
              <span aria-hidden="true">/</span>
              <span>{user.Name}</span>
            </nav>

            <header className="page-header user-page-header">
              <div>
                <p className="eyebrow">{t("Global user")}</p>
                <h1>{user.Name}</h1>
              </div>
              <div className="page-header__actions">
                <Link className="button button--secondary" to={`/users/${encodeURIComponent(user.ID)}/subscription/nodes`}>
                  {t("Subscription")}
                </Link>
                {assigned.length > 0 && (
                  <button
                    type="button"
                    className="button button--danger"
                    onClick={() => {
                      setModalError("");
                      setResetAllCredsOpen(true);
                    }}
                  >
                    {t("Reset all credentials")}
                  </button>
                )}
              </div>
            </header>

            {pageError && (
              <div className="notice notice--error" role="alert">
                {pageError}
              </div>
            )}

            <section className="panel user-login-panel">
              <div className="panel__header">
                <div>
                  <h2>{t("User login")}</h2>
                  {user.Login.LoginUsername && <p>{user.Login.LoginUsername}</p>}
                </div>
                <span className={`membership-status membership-status--${user.Login.StatusClass}`}>
                  {user.Login.StatusLabel}
                </span>
              </div>

              {user.Login.Invitation && (
                <div className="credential-row user-invitation-result">
                  <span className="protocol-badge">{t("Invite")}</span>
                  <code>{user.Login.Invitation.URL}</code>
                  <CopyButton value={user.Login.Invitation.URL} />
                  <small>
                    {t("Expires")} {user.Login.Invitation.ExpiresAt}
                  </small>
                </div>
              )}

              {user.Login.Claimed ? (
                <div className="panel__actions">
                  <button
                    type="button"
                    className="button button--danger"
                    onClick={() => {
                      setModalError("");
                      setResetLoginOpen(true);
                    }}
                  >
                    {t("Reset Login")}
                  </button>
                </div>
              ) : user.Login.InvitationReady ? (
                <div className="panel__actions">
                  <button
                    type="button"
                    className="button button--danger"
                    onClick={() => {
                      setModalError("");
                      setResetTokenOpen(true);
                    }}
                  >
                    {t("Reset Registration Token")}
                  </button>
                  <span className="form-help">
                    {t("Registration link expires")} {user.Login.InviteExpiresAt}
                  </span>
                </div>
              ) : (
                <button
                  type="button"
                  className="button button--primary"
                  disabled={Boolean(busy)}
                  onClick={() =>
                    void runAction("invite", `/users/${encodeURIComponent(user.ID)}/login/invitation`, {
                      confirm_reset: "",
                    })
                  }
                >
                  {t("Create Registration Link")}
                </button>
              )}
            </section>

            <section className="panel daily-usage-panel">
              <div className="panel__header">
                <h2>{t("Daily Traffic")}</h2>
                <span className="panel__count">{t("Last 30 Days")}</span>
              </div>
              <DailyUsageTable days={user.DailyUsage} showPerNode />
            </section>

            <section className="panel user-access-panel">
              <div className="panel__header">
                <h2>{t("Node roles")}</h2>
                <div className="user-access-panel__actions">
                  <span className="panel__count">
                    {assigned.length} {t("assigned")}
                  </span>
                </div>
              </div>

              {user.ProxyNodeCount > 0 ? (
                <div className="user-node-roles" aria-label={t("Assigned Proxy Node roles")}>
                  {assigned.map((access) => (
                    <button
                      key={access.ProxyID}
                      type="button"
                      className={`node-role-chip node-role-chip--${access.Tone}`}
                      onClick={() => openRoleModal(access)}
                    >
                      <span className="node-role-chip__mark" aria-hidden="true">
                        {access.Initial}
                      </span>
                      <span className="node-role-chip__copy">
                        <strong>{access.ProxyName}</strong>
                        <small>
                          {access.EntranceLabel} · {access.EntranceAgent}
                        </small>
                      </span>
                      <span className={`node-role-chip__state node-role-chip__state--${access.Plan.StatusClass}`}>
                        {access.Plan.StatusLabel}
                      </span>
                    </button>
                  ))}
                  <button
                    type="button"
                    className="node-role-chip node-role-chip--add"
                    onClick={openGrantModal}
                  >
                    <span className="node-role-chip__add" aria-hidden="true">
                      +
                    </span>
                    <span>
                      <strong>{t("Add Node")}</strong>
                      <small>
                        {available.length} {t("available")}
                      </small>
                    </span>
                  </button>
                </div>
              ) : (
                <div className="user-access-empty">
                  <span className="node-role-chip__add" aria-hidden="true">
                    0
                  </span>
                  <div>
                    <strong>{t("No Proxy Nodes exist yet")}</strong>
                    <p>{t("Create a Proxy Node before assigning access.")}</p>
                    <Link className="button-link" to="/proxy-nodes/new">
                      {t("Create Proxy Node")}
                    </Link>
                  </div>
                </div>
              )}
            </section>

            <div className="split-panels">
              <section className="panel">
                <div className="panel__header">
                  <h2>{t("Rename")}</h2>
                </div>
                <form
                  className="inline-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void runAction("rename", `/users/${encodeURIComponent(user.ID)}/rename`, {
                      name: renameName.trim(),
                    });
                  }}
                  noValidate
                >
                  <input value={renameName} onChange={(e) => setRenameName(e.target.value)} required />
                  <button className="button button--secondary" type="submit" disabled={Boolean(busy)}>
                    {t("Rename")}
                  </button>
                </form>
              </section>

              <section className="panel panel--danger">
                <div className="panel__header">
                  <div>
                    <h2>{t("Delete user")}</h2>
                    <p>{t("Immediately revokes this user's access to every active Proxy Node.")}</p>
                  </div>
                </div>
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (!confirmDelete) return;
                    void runAction(
                      "delete-user",
                      `/users/${encodeURIComponent(user.ID)}/delete`,
                      { confirm_delete: "yes" },
                      { followRedirect: true },
                    );
                  }}
                  noValidate
                >
                  <label className="danger-confirm">
                    <input
                      type="checkbox"
                      checked={confirmDelete}
                      onChange={(e) => setConfirmDelete(e.target.checked)}
                      required
                    />
                    <span>{t("Delete this user and all Proxy Node access.")}</span>
                  </label>
                  <button
                    className="button button--danger"
                    type="submit"
                    disabled={!confirmDelete || Boolean(busy)}
                  >
                    {t("Delete user")}
                  </button>
                </form>
              </section>
            </div>

            {/* Manage assigned role modal */}
            <Modal
              open={Boolean(activeAccess) && !confirmCredResetProxyId}
              onClose={() => setActiveAccess(null)}
              eyebrow={t("Node role")}
              title={activeAccess?.ProxyName || ""}
              className="user-access-dialog"
              footer={
                activeAccess && (
                  <>
                    <Link className="button button--secondary" to={activeAccess.ProxyURL}>
                      {t("Open Proxy Node")}
                    </Link>
                    <button
                      type="button"
                      className="button button--danger"
                      disabled={Boolean(busy)}
                      onClick={() =>
                        void runAction(
                          "revoke-access",
                          `/users/${encodeURIComponent(user.ID)}/access/remove`,
                          { proxy_id: activeAccess.ProxyID },
                          { modalTarget: true, onDone: () => setActiveAccess(null) },
                        )
                      }
                    >
                      {t("Revoke access")}
                    </button>
                    <button type="button" className="button button--secondary" onClick={() => setActiveAccess(null)}>
                      {t("Close")}
                    </button>
                  </>
                )
              }
            >
              {activeAccess && (
                <div className="modal__body stack">
                  {modalError && (
                    <div className="notice notice--error" role="alert">
                      {modalError}
                    </div>
                  )}
                  <div className="user-access-identity">
                    <span className={`node-role-chip__mark node-role-chip__mark--${activeAccess.Tone}`} aria-hidden="true">
                      {activeAccess.Initial}
                    </span>
                    <span>
                      <small>{t("Authenticated user")}</small>
                      <code>{activeAccess.AuthUser}</code>
                    </span>
                    <span className={`membership-status membership-status--${activeAccess.Plan.StatusClass}`}>
                      {activeAccess.Plan.StatusLabel}
                    </span>
                  </div>

                  <dl className="membership-facts">
                    <div>
                      <dt>{t("Traffic used")}</dt>
                      <dd>{activeAccess.Plan.UsageLabel}</dd>
                    </div>
                    <div>
                      <dt>{t("Monthly quota")}</dt>
                      <dd>{activeAccess.Plan.QuotaLabel}</dd>
                    </div>
                    <div>
                      <dt>{t("Reset time")}</dt>
                      <dd>
                        <LocalTime dateTime={activeAccess.Plan.ResetAt} fallback={activeAccess.Plan.ResetLabel} />
                      </dd>
                    </div>
                    <div>
                      <dt>{t("Expiration")}</dt>
                      <dd>
                        {activeAccess.Plan.ExpirationAt ? (
                          <LocalTime
                            dateTime={activeAccess.Plan.ExpirationAt}
                            fallback={activeAccess.Plan.ExpirationLabel}
                          />
                        ) : (
                          activeAccess.Plan.ExpirationLabel
                        )}
                      </dd>
                    </div>
                  </dl>

                  <form
                    className="stack membership-plan-editor"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void runAction(
                        "save-plan",
                        `/users/${encodeURIComponent(user.ID)}/access/update`,
                        { proxy_id: activeAccess.ProxyID, ...planDraftToFields(rolePlan) },
                        { modalTarget: true },
                      );
                    }}
                    noValidate
                  >
                    <MembershipPlanFields value={rolePlan} onChange={setRolePlan} />
                    <button className="button button--secondary" type="submit" disabled={Boolean(busy)}>
                      {t("Save allowance")}
                    </button>
                  </form>

                  <section className="membership-maintenance">
                    <h3>{t("Access maintenance")}</h3>
                    {activeAccess.Plan.CanExtend && (
                      <form
                        className="membership-extension"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void runAction(
                            "extend-sub",
                            `/proxy-nodes/${encodeURIComponent(activeAccess.ProxyID)}/users/${encodeURIComponent(user.ID)}/subscription-extend`,
                            {
                              return_to: "user",
                              extension_value: extendValue,
                              extension_unit: extendUnit,
                            },
                            { modalTarget: true },
                          );
                        }}
                        noValidate
                      >
                        <label className="field">
                          <span>{t("Extend by")}</span>
                          <input
                            type="number"
                            min={1}
                            max={52560000}
                            value={extendValue}
                            onChange={(e) => setExtendValue(e.target.value)}
                            required
                          />
                        </label>
                        <label className="field">
                          <span>{t("Unit")}</span>
                          <SelectBox
                            searchable={false}
                            value={extendUnit}
                            onChange={setExtendUnit}
                            options={[
                              { value: "minutes", label: t("Minutes") },
                              { value: "hours", label: t("Hours") },
                              { value: "days", label: t("Days") },
                              { value: "months", label: t("Calendar months") },
                            ]}
                          />
                        </label>
                        <button className="button button--secondary" type="submit" disabled={Boolean(busy)}>
                          {t("Extend subscription")}
                        </button>
                      </form>
                    )}

                    <div className="membership-maintenance__actions">
                      <button
                        type="button"
                        className="button button--secondary"
                        disabled={Boolean(busy)}
                        onClick={() =>
                          void runAction(
                            "reset-traffic",
                            `/proxy-nodes/${encodeURIComponent(activeAccess.ProxyID)}/users/${encodeURIComponent(user.ID)}/traffic-reset`,
                            { return_to: "user" },
                            { modalTarget: true },
                          )
                        }
                      >
                        {t("Reset traffic")}
                      </button>
                      <button
                        type="button"
                        className="button button--danger"
                        onClick={() => setConfirmCredResetProxyId(activeAccess.ProxyID)}
                      >
                        {t("Reset credential")}
                      </button>
                    </div>
                    <p className="form-help">
                      {t("Resetting the credential immediately invalidates the previous import credential.")}
                    </p>
                  </section>

                  <div>
                    <h3>{t("Import credentials")}</h3>
                    <p className="form-help">{t("These values contain secrets. Copy them only to the intended user.")}</p>
                  </div>
                  {activeAccess.URIs && activeAccess.URIs.length > 0 ? (
                    <div className="user-access-credentials">
                      {activeAccess.URIs.map((item) => (
                        <div key={item.URI} className="credential-row">
                          <span className="protocol-badge">{item.Family}</span>
                          <code>{item.URI}</code>
                          <CopyButton value={item.URI} />
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="panel__empty">
                      <p>{t("Access is active, but no routable entrance address is available yet.")}</p>
                    </div>
                  )}
                </div>
              )}
            </Modal>

            {/* Confirm credential reset for one Node */}
            <Modal
              open={Boolean(confirmCredResetProxyId)}
              onClose={() => setConfirmCredResetProxyId(null)}
              eyebrow={t("Node role")}
              title={`${t("Reset credential")}?`}
              size="compact"
              footer={
                <>
                  <button
                    type="button"
                    className="button button--secondary"
                    onClick={() => setConfirmCredResetProxyId(null)}
                  >
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={Boolean(busy)}
                    onClick={() => {
                      if (!confirmCredResetProxyId) return;
                      void runAction(
                        "reset-cred",
                        `/proxy-nodes/${encodeURIComponent(confirmCredResetProxyId)}/users/${encodeURIComponent(user.ID)}/credential-reset`,
                        { return_to: "user", confirm_reset: "yes" },
                        { modalTarget: true, onDone: () => setConfirmCredResetProxyId(null) },
                      );
                    }}
                  >
                    {t("Reset credential")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                <p>
                  <strong>{user.Name}</strong> · <strong>{activeAccess?.ProxyName}</strong>
                  <br />
                  <span>{t("This credential will stop working immediately.")}</span>
                </p>
              </div>
            </Modal>

            {/* Grant Node access modal */}
            <Modal
              open={grantOpen}
              onClose={() => setGrantOpen(false)}
              eyebrow={t("Node roles")}
              title={t("Add a role to %s").replace("%s", user.Name)}
              className="grant-access-dialog node-role-dialog"
            >
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!grantProxyId) return;
                  void runAction(
                    "grant-role",
                    `/users/${encodeURIComponent(user.ID)}/access`,
                    { proxy_id: grantProxyId, ...planDraftToFields(grantPlan) },
                    { modalTarget: true, onDone: () => setGrantOpen(false) },
                  );
                }}
                noValidate
              >
                <div className="modal__body stack">
                  {modalError && (
                    <div className="notice notice--error" role="alert">
                      {modalError}
                    </div>
                  )}
                  <section className="node-role-picker">
                    <div className="node-role-picker__heading">
                      <h3>{t("Choose a Node")}</h3>
                      <span>{countLabel(available.length, "available-node")}</span>
                    </div>
                    <label className="module-search">
                      <span className="sr-only">{t("Search available Proxy Nodes")}</span>
                      <input
                        type="search"
                        value={grantSearch}
                        onChange={(e) => setGrantSearch(e.target.value)}
                        placeholder={t("Search Nodes, protocols, or Agents")}
                        autoComplete="off"
                        autoFocus
                      />
                      {grantSearch && (
                        <button
                          type="button"
                          aria-label={t("Clear Node search")}
                          onClick={() => setGrantSearch("")}
                        >
                          ×
                        </button>
                      )}
                    </label>
                    {filteredAvailable.length > 0 ? (
                      <div className="node-role-options" role="radiogroup" aria-label={t("Available Proxy Nodes")}>
                        {filteredAvailable.map((opt) => (
                          <label key={opt.ProxyID} className={`node-role-option node-role-option--${opt.Tone}`}>
                            <input
                              type="radio"
                              name="proxy_id"
                              value={opt.ProxyID}
                              checked={grantProxyId === opt.ProxyID}
                              onChange={() => setGrantProxyId(opt.ProxyID)}
                            />
                            <span className="node-role-chip__mark" aria-hidden="true">
                              {opt.Initial}
                            </span>
                            <span>
                              <strong>{opt.ProxyName}</strong>
                              <small>
                                {opt.EntranceLabel} · {opt.EntranceAgent}
                              </small>
                            </span>
                            <span className="node-role-option__check" aria-hidden="true">
                              ✓
                            </span>
                          </label>
                        ))}
                      </div>
                    ) : (
                      <p className="panel__empty">{t("No Nodes available.")}</p>
                    )}
                  </section>

                  {available.length > 0 && (
                    <section className="node-role-plan">
                      <h3>{t("Role allowance")}</h3>
                      <MembershipPlanFields value={grantPlan} onChange={setGrantPlan} />
                    </section>
                  )}
                </div>
                <footer className="modal__footer">
                  <button type="button" className="button button--secondary" onClick={() => setGrantOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="submit"
                    className="button button--primary"
                    disabled={!grantProxyId || Boolean(busy)}
                  >
                    {t("Assign role")}
                  </button>
                </footer>
              </form>
            </Modal>

            {/* Confirm modals */}
            <Modal
              open={resetAllCredsOpen}
              onClose={() => setResetAllCredsOpen(false)}
              eyebrow={t("Global user")}
              title={t("Reset all credentials?")}
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setResetAllCredsOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={Boolean(busy)}
                    onClick={() =>
                      void runAction(
                        "reset-all-creds",
                        `/users/${encodeURIComponent(user.ID)}/credentials/reset`,
                        { confirm_reset: "yes" },
                        { onDone: () => setResetAllCredsOpen(false) },
                      )
                    }
                  >
                    {t("Reset all credentials")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                <p>
                  {t("Every Proxy Node credential for %s will stop working immediately. The subscription link will not change.").replace(
                    "%s",
                    user.Name,
                  )}
                </p>
              </div>
            </Modal>

            <Modal
              open={resetLoginOpen}
              onClose={() => setResetLoginOpen(false)}
              eyebrow={t("User login")}
              title={t("Reset Login?")}
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setResetLoginOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={Boolean(busy)}
                    onClick={() =>
                      void runAction(
                        "reset-login",
                        `/users/${encodeURIComponent(user.ID)}/login/invitation`,
                        { confirm_reset: "yes" },
                        { onDone: () => setResetLoginOpen(false) },
                      )
                    }
                  >
                    {t("Reset Login")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                <p>
                  {user.Login.LoginUsername}
                  {t(" will be signed out everywhere. The current password will stop working and a new invitation will be created.")}
                </p>
              </div>
            </Modal>

            <Modal
              open={resetTokenOpen}
              onClose={() => setResetTokenOpen(false)}
              eyebrow={t("User login")}
              title={t("Reset Registration Token?")}
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setResetTokenOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={Boolean(busy)}
                    onClick={() =>
                      void runAction(
                        "reset-token",
                        `/users/${encodeURIComponent(user.ID)}/login/invitation`,
                        { confirm_reset: "yes" },
                        { onDone: () => setResetTokenOpen(false) },
                      )
                    }
                  >
                    {t("Reset Registration Token")}
                  </button>
                </>
              }
            >
              <div className="modal__body">
                <p>
                  {t("The current registration link will stop working immediately. A new single-use link valid for 24 hours will be created.")}
                </p>
              </div>
            </Modal>
          </>
        )}
      </AsyncState>
    </AppLayout>
  );
};
