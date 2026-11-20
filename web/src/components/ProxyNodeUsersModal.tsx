import React, { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../api/client";
import type { NodeUserAccessView, ProxyNodeDetailView } from "../api/types";
import { LocalTime } from "./LocalTime";
import {
  MembershipPlanFields,
  planDraftToFields,
  planToDraft,
  type MembershipPlanDraft,
} from "./MembershipPlanFields";
import { Modal } from "./Modal";
import { SelectBox } from "./SelectBox";
import { useApp } from "../context/AppContext";

interface ProxyNodeUsersModalProps {
  open: boolean;
  node: ProxyNodeDetailView;
  onClose: () => void;
  onReload: () => Promise<void>;
}

function parseUTC8Input(val: string): number {
  if (!val) return Number.NaN;
  return Date.parse(`${val}${val.length === 16 ? ":00" : ""}+08:00`);
}

export const ProxyNodeUsersModal: React.FC<ProxyNodeUsersModalProps> = ({
  open,
  node,
  onClose,
  onReload,
}) => {
  const { t, countLabel, submitMutation } = useApp();

  const [subModal, setSubModal] = useState<
    | { kind: "roster" }
    | { kind: "user"; user: NodeUserAccessView }
    | { kind: "reset-cred"; user: NodeUserAccessView }
    | { kind: "grant" }
    | { kind: "compensate" }
  >({ kind: "roster" });

  const [rosterSearch, setRosterSearch] = useState("");
  const [modalError, setModalError] = useState("");
  const [busy, setBusy] = useState("");

  // Per-user plan/extend draft
  const [planDraft, setPlanDraft] = useState<MembershipPlanDraft>(planToDraft());
  const [extendValue, setExtendValue] = useState("1");
  const [extendUnit, setExtendUnit] = useState("months");

  // Grant modal state
  const [grantUserId, setGrantUserId] = useState("");
  const [grantPlan, setGrantPlan] = useState<MembershipPlanDraft>(planToDraft(node.DefaultPlan));

  // Compensation modal state
  const [compStart, setCompStart] = useState(node.CompensationStart || "");
  const [compEnd, setCompEnd] = useState(node.CompensationEnd || "");
  const [compValue, setCompValue] = useState("1");
  const [compUnit, setCompUnit] = useState("days");
  const [compSearch, setCompSearch] = useState("");
  const [compSelected, setCompSelected] = useState<Record<string, boolean>>({});

  useEffect(() => {
    if (!open) {
      setSubModal({ kind: "roster" });
      setRosterSearch("");
      setModalError("");
      return;
    }
    if (subModal.kind === "user") {
      const refreshed = (node.UserAccess || []).find((u) => u.UserID === subModal.user.UserID);
      if (refreshed) {
        setSubModal({ kind: "user", user: refreshed });
        setPlanDraft(planToDraft(refreshed.Plan));
      } else {
        setSubModal({ kind: "roster" });
      }
    }
  }, [open, node]);

  const users = node.UserAccess || [];
  const filteredUsers = useMemo(() => {
    const q = rosterSearch.trim().toLocaleLowerCase();
    if (!q) return users;
    return users.filter((u) => u.Name.toLocaleLowerCase().includes(q));
  }, [users, rosterSearch]);

  const finiteCandidates = useMemo(() => users.filter((u) => Boolean(u.MembershipID)), [users]);

  const openCompensate = () => {
    setCompStart(node.CompensationStart || "");
    setCompEnd(node.CompensationEnd || "");
    setCompValue("1");
    setCompUnit("days");
    setCompSearch("");
    const initial: Record<string, boolean> = {};
    for (const u of finiteCandidates) {
      initial[u.MembershipID] = Boolean(u.CompensationSelected);
    }
    setCompSelected(initial);
    setModalError("");
    setSubModal({ kind: "compensate" });
  };

  const applyCompRange = (nextStart: string, nextEnd: string) => {
    setCompStart(nextStart);
    setCompEnd(nextEnd);
    const s = parseUTC8Input(nextStart);
    const e = parseUTC8Input(nextEnd);
    const valid = Number.isFinite(s) && Number.isFinite(e) && s < e;
    const nextSel: Record<string, boolean> = {};
    for (const u of finiteCandidates) {
      const subStart = Date.parse(u.SubscriptionStartedAt || "");
      const subEnd = Date.parse(u.SubscriptionEndsAfter || "");
      nextSel[u.MembershipID] = valid && subStart < e && subEnd > s;
    }
    setCompSelected(nextSel);
  };

  const runAction = async (
    key: string,
    url: string,
    fields: Record<string, string | string[]>,
    after?: () => void,
  ) => {
    if (busy) return;
    setBusy(key);
    setModalError("");
    try {
      await submitMutation(url, fields);
      after?.();
      await onReload();
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setBusy("");
    }
  };

  if (!open) return null;

  // Nested sub-modals return cleanly to roster on close!
  if (subModal.kind === "reset-cred") {
    const targetUser = subModal.user;
    return (
      <Modal
        open
        onClose={() => setSubModal({ kind: "user", user: targetUser })}
        eyebrow={`${node.Name} · ${t("User access")}`}
        title={t("Reset %s credential?").replace("%s", targetUser.Name)}
        size="compact"
        footer={
          <>
            <button
              type="button"
              className="button button--secondary"
              onClick={() => setSubModal({ kind: "user", user: targetUser })}
            >
              {t("Cancel")}
            </button>
            <button
              type="button"
              className="button button--danger"
              disabled={Boolean(busy)}
              onClick={() =>
                void runAction(
                  "reset-cred",
                  `/proxy-nodes/${encodeURIComponent(node.ID)}/users/${encodeURIComponent(targetUser.UserID)}/credential-reset`,
                  { return_to: "node", confirm_reset: "yes" },
                  () => setSubModal({ kind: "user", user: targetUser }),
                )
              }
            >
              {t("Reset credential")}
            </button>
          </>
        }
      >
        <div className="modal__body">
          {modalError && <div className="notice notice--error">{modalError}</div>}
          <p>
            {t("The current %s credential will stop working immediately. Other Node credentials and subscription links will not change.").replace(
              "%s",
              node.Name,
            )}
          </p>
        </div>
      </Modal>
    );
  }

  if (subModal.kind === "user") {
    const u = subModal.user;
    return (
      <Modal
        open
        onClose={() => setSubModal({ kind: "roster" })}
        eyebrow={`${node.Name} · ${t("User access")}`}
        title={u.Name}
        className="user-access-dialog"
        footer={
          <>
            <Link className="button button--secondary" to={u.URL} onClick={onClose}>
              {u.System ? t("Open My Subscription") : t("Open User")}
            </Link>
            {!u.System && (
              <button
                type="button"
                className="button button--danger"
                disabled={Boolean(busy)}
                onClick={() =>
                  void runAction(
                    "remove-user",
                    `/proxy-nodes/${encodeURIComponent(node.ID)}/users/${encodeURIComponent(u.UserID)}/remove`,
                    {},
                    () => setSubModal({ kind: "roster" }),
                  )
                }
              >
                {t("Revoke Access")}
              </button>
            )}
            <button type="button" className="button button--secondary" onClick={() => setSubModal({ kind: "roster" })}>
              {t("Close")}
            </button>
          </>
        }
      >
        <div className="modal__body stack">
          {modalError && <div className="notice notice--error">{modalError}</div>}
          <dl className="membership-facts">
            {!u.System && (
              <div>
                <dt>{t("Traffic used")}</dt>
                <dd>{u.Plan.UsageLabel}</dd>
              </div>
            )}
            <div>
              <dt>{t("Monthly quota")}</dt>
              <dd>{u.Plan.QuotaLabel}</dd>
            </div>
            {!u.System && (
              <div>
                <dt>{t("Reset time")}</dt>
                <dd>
                  <LocalTime dateTime={u.Plan.ResetAt} fallback={u.Plan.ResetLabel} />
                </dd>
              </div>
            )}
            <div>
              <dt>{t("Expiration")}</dt>
              <dd>
                {u.Plan.ExpirationAt ? (
                  <LocalTime dateTime={u.Plan.ExpirationAt} fallback={u.Plan.ExpirationLabel} />
                ) : (
                  u.Plan.ExpirationLabel
                )}
              </dd>
            </div>
          </dl>

          {!u.System && (
            <>
              <form
                className="stack membership-plan-editor"
                onSubmit={(e) => {
                  e.preventDefault();
                  void runAction(
                    "save-plan",
                    `/proxy-nodes/${encodeURIComponent(node.ID)}/users/${encodeURIComponent(u.UserID)}/plan`,
                    planDraftToFields(planDraft),
                  );
                }}
                noValidate
              >
                <MembershipPlanFields value={planDraft} onChange={setPlanDraft} />
                <button type="submit" className="button button--primary" disabled={Boolean(busy)}>
                  {t("Save Allowance")}
                </button>
              </form>

              <section className="membership-maintenance">
                <h3>{t("Access Maintenance")}</h3>
                {u.Plan.CanExtend && (
                  <form
                    className="membership-extension"
                    onSubmit={(e) => {
                      e.preventDefault();
                      void runAction(
                        "extend",
                        `/proxy-nodes/${encodeURIComponent(node.ID)}/users/${encodeURIComponent(u.UserID)}/subscription-extend`,
                        { return_to: "node", extension_value: extendValue, extension_unit: extendUnit },
                      );
                    }}
                    noValidate
                  >
                    <label className="field">
                      <span>{t("Extend By")}</span>
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
                          { value: "months", label: t("Calendar Months") },
                        ]}
                      />
                    </label>
                    <button type="submit" className="button button--secondary" disabled={Boolean(busy)}>
                      {t("Extend Subscription")}
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
                        `/proxy-nodes/${encodeURIComponent(node.ID)}/users/${encodeURIComponent(u.UserID)}/traffic-reset`,
                        { return_to: "node" },
                      )
                    }
                  >
                    {t("Reset Traffic")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    onClick={() => setSubModal({ kind: "reset-cred", user: u })}
                  >
                    {t("Reset Credential")}
                  </button>
                </div>
              </section>
            </>
          )}
        </div>
      </Modal>
    );
  }

  if (subModal.kind === "grant") {
    const avail = node.AvailableUsers || [];
    return (
      <Modal
        open
        onClose={() => setSubModal({ kind: "roster" })}
        eyebrow={`${node.Name} · ${t("User access")}`}
        title={t("Add user")}
        className="grant-access-dialog"
      >
        {avail.length > 0 ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!grantUserId) return;
              void runAction(
                "grant-user",
                `/proxy-nodes/${encodeURIComponent(node.ID)}/users`,
                { user_id: grantUserId, ...planDraftToFields(grantPlan) },
                () => setSubModal({ kind: "roster" }),
              );
            }}
            noValidate
          >
            <div className="modal__body stack">
              {modalError && <div className="notice notice--error">{modalError}</div>}
              <label className="field">
                <span>{t("End user")}</span>
                <SelectBox
                  value={grantUserId}
                  onChange={setGrantUserId}
                  placeholder={t("Search users")}
                  options={[
                    { value: "", label: t("Search users"), disabled: true },
                    ...avail.map((u) => ({ value: u.UserID, label: u.Label })),
                  ]}
                />
              </label>
              <MembershipPlanFields value={grantPlan} onChange={setGrantPlan} />
            </div>
            <footer className="modal__footer">
              <button
                type="button"
                className="button button--secondary"
                onClick={() => setSubModal({ kind: "roster" })}
              >
                {t("Cancel")}
              </button>
              <button
                type="submit"
                className="button button--primary"
                disabled={!grantUserId || Boolean(busy)}
              >
                {t("Grant access")}
              </button>
            </footer>
          </form>
        ) : (
          <>
            <div className="modal__body">
              <div className="panel__empty">
                <strong>{t("No users available.")}</strong>
              </div>
            </div>
            <footer className="modal__footer">
              <button
                type="button"
                className="button button--secondary"
                onClick={() => setSubModal({ kind: "roster" })}
              >
                {t("Close")}
              </button>
            </footer>
          </>
        )}
      </Modal>
    );
  }

  if (subModal.kind === "compensate") {
    const selectedIds = Object.entries(compSelected)
      .filter(([, checked]) => checked)
      .map(([id]) => id);
    const q = compSearch.trim().toLocaleLowerCase();
    const visibleCandidates = finiteCandidates.filter((c) => !q || c.Name.toLocaleLowerCase().includes(q));

    return (
      <Modal
        open
        onClose={() => setSubModal({ kind: "roster" })}
        eyebrow={t("Subscription compensation")}
        title={node.Name}
        className="grant-access-dialog"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (selectedIds.length === 0) return;
            void runAction(
              "compensate",
              `/proxy-nodes/${encodeURIComponent(node.ID)}/users/compensate`,
              {
                outage_started_at: compStart,
                outage_ended_at: compEnd,
                compensation_value: compValue,
                compensation_unit: compUnit,
                membership_ids: selectedIds,
              },
              () => setSubModal({ kind: "roster" }),
            );
          }}
          noValidate
        >
          <div className="modal__body stack">
            {modalError && <div className="notice notice--error">{modalError}</div>}
            <div className="compensation-range">
              <label className="field">
                <span>{t("Outage started (UTC+8)")}</span>
                <input
                  type="datetime-local"
                  value={compStart}
                  onChange={(e) => applyCompRange(e.target.value, compEnd)}
                  required
                />
              </label>
              <label className="field">
                <span>{t("Outage ended (UTC+8)")}</span>
                <input
                  type="datetime-local"
                  value={compEnd}
                  onChange={(e) => applyCompRange(compStart, e.target.value)}
                  required
                />
              </label>
            </div>

            <div className="membership-extension">
              <label className="field">
                <span>{t("Compensation")}</span>
                <input
                  type="number"
                  min={1}
                  max={52560000}
                  value={compValue}
                  onChange={(e) => setCompValue(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                <span>{t("Unit")}</span>
                <SelectBox
                  searchable={false}
                  value={compUnit}
                  onChange={setCompUnit}
                  options={[
                    { value: "minutes", label: t("Minutes") },
                    { value: "hours", label: t("Hours") },
                    { value: "days", label: t("Days") },
                    { value: "months", label: t("Calendar months") },
                  ]}
                />
              </label>
            </div>

            <section className="compensation-selector">
              <div className="compensation-selector__header">
                <h3>{t("Affected subscriptions")}</h3>
                <strong>
                  {selectedIds.length} {t("selected")}
                </strong>
              </div>
              <label className="module-search">
                <span className="sr-only">{t("Search affected users")}</span>
                <input
                  type="search"
                  value={compSearch}
                  onChange={(e) => setCompSearch(e.target.value)}
                  placeholder={t("Filter by user name")}
                />
                {compSearch && (
                  <button type="button" onClick={() => setCompSearch("")} aria-label={t("Clear affected-user search")}>
                    ×
                  </button>
                )}
              </label>
              {visibleCandidates.length > 0 ? (
                <div className="compensation-candidates">
                  {visibleCandidates.map((cand) => (
                    <label key={cand.MembershipID} className="compensation-candidate">
                      <input
                        type="checkbox"
                        checked={Boolean(compSelected[cand.MembershipID])}
                        onChange={(e) =>
                          setCompSelected((prev) => ({ ...prev, [cand.MembershipID]: e.target.checked }))
                        }
                      />
                      <span>
                        <strong>{cand.Name}</strong>
                        <small>
                          {cand.Plan.StatusLabel} ·{" "}
                          {cand.Plan.ExpirationAt ? (
                            <LocalTime dateTime={cand.Plan.ExpirationAt} fallback={cand.Plan.ExpirationLabel} />
                          ) : (
                            cand.Plan.ExpirationLabel
                          )}
                        </small>
                      </span>
                    </label>
                  ))}
                </div>
              ) : (
                <p className="form-help">{t("No finite subscriptions match this search.")}</p>
              )}
            </section>
          </div>
          <footer className="modal__footer">
            <button type="button" className="button button--secondary" onClick={() => setSubModal({ kind: "roster" })}>
              {t("Cancel")}
            </button>
            <button
              type="submit"
              className="button button--primary"
              disabled={selectedIds.length === 0 || Boolean(busy)}
            >
              {t("Add compensation")}
            </button>
          </footer>
        </form>
      </Modal>
    );
  }

  // Main Users Roster Modal
  return (
    <Modal
      open
      onClose={onClose}
      eyebrow={`${node.Name} · ${t("User access")}`}
      title={t("Users")}
      className="proxy-node-users-dialog"
      footer={
        <>
          {node.FiniteMemberCount > 0 && (
            <button type="button" className="button button--secondary" onClick={openCompensate}>
              {t("Compensate")}
            </button>
          )}
          {node.EndUserCount > 0 ? (
            <button
              type="button"
              className="button button--primary"
              onClick={() => {
                setGrantUserId("");
                setGrantPlan(planToDraft(node.DefaultPlan));
                setModalError("");
                setSubModal({ kind: "grant" });
              }}
            >
              {t("Add user")}
            </button>
          ) : (
            <Link className="button button--primary" to="/users" onClick={onClose}>
              {t("Add user")}
            </Link>
          )}
          <button type="button" className="button button--secondary" onClick={onClose}>
            {t("Close")}
          </button>
        </>
      }
    >
      <div className="modal__body proxy-node-users-dialog__body">
        <section className="panel proxy-node-user-module">
          <div className="panel__header">
            <h3>{t("Access roster")}</h3>
          </div>
          {users.length > 0 ? (
            <>
              <div className="module-toolbar">
                <label className="module-search">
                  <span className="sr-only">{t("Search assigned users")}</span>
                  <input
                    type="search"
                    value={rosterSearch}
                    onChange={(e) => setRosterSearch(e.target.value)}
                    placeholder={t("Search assigned users")}
                    autoComplete="off"
                  />
                  {rosterSearch && (
                    <button
                      type="button"
                      aria-label={t("Clear user search")}
                      onClick={() => setRosterSearch("")}
                    >
                      ×
                    </button>
                  )}
                </label>
                <span className="module-toolbar__result" aria-live="polite">
                  {countLabel(filteredUsers.length, "user")}
                </span>
              </div>
              {filteredUsers.length > 0 ? (
                <div className="proxy-node-user-grid">
                  {filteredUsers.map((u) => (
                    <button
                      key={u.UserID}
                      type="button"
                      className={`proxy-node-user-card ${u.System ? "proxy-node-user-card--system" : ""}`}
                      onClick={() => {
                        setPlanDraft(planToDraft(u.Plan));
                        setExtendValue("1");
                        setExtendUnit("months");
                        setModalError("");
                        setSubModal({ kind: "user", user: u });
                      }}
                    >
                      <span className="proxy-node-user-card__avatar" aria-hidden="true">
                        {u.Initial}
                      </span>
                      <span className="proxy-node-user-card__copy">
                        <strong>{u.Name}</strong>
                        <small>
                          {u.System
                            ? t("System Access · Unlimited")
                            : `${t("Used")} ${u.Plan.UsageLabel} · ${u.Plan.QuotaLabel}`}
                        </small>
                      </span>
                      <span
                        className={`membership-status membership-status--${u.System ? "reference" : u.Plan.StatusClass}`}
                      >
                        {u.System ? t("Protected") : u.Plan.StatusLabel}
                      </span>
                      <span className="proxy-node-user-card__arrow" aria-hidden="true">
                        ›
                      </span>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="panel__empty">
                  <p>{t("No assigned users match this search.")}</p>
                </div>
              )}
            </>
          ) : (
            <div className="panel__empty panel__empty--action">
              <strong>{t("No users assigned")}</strong>
              {node.EndUserCount > 0 ? (
                <button
                  type="button"
                  className="button button--primary"
                  onClick={() => {
                    setGrantUserId("");
                    setGrantPlan(planToDraft(node.DefaultPlan));
                    setModalError("");
                    setSubModal({ kind: "grant" });
                  }}
                >
                  {t("Add user")}
                </button>
              ) : (
                <Link className="button button--primary" to="/users" onClick={onClose}>
                  {t("Create user")}
                </Link>
              )}
            </div>
          )}
        </section>
      </div>
    </Modal>
  );
};
