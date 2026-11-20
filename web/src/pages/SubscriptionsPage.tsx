import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, fetchRuleSetCatalog } from "../api/client";
import type {
  SubscriptionGroupView,
  SubscriptionRuleView,
  SubscriptionTargetOption,
  SubscriptionTargetPicker,
} from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { Modal } from "../components/Modal";
import { SelectBox } from "../components/SelectBox";
import { useApp, useDirtyForm } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

function suggestGroupName(raw: string): string {
  const first =
    String(raw || "")
      .split(/[\r\n,]+/)
      .map((part) => part.trim())
      .find(Boolean) || "";
  const cleaned = first
    .replace(/^\*?\./, "")
    .replace(/[,="\\[\]#;]+/g, "")
    .trim()
    .slice(0, 100);
  if (!cleaned || /^(proxy|direct|reject)$/i.test(cleaned)) return "";
  return cleaned;
}

interface GroupModalProps {
  open: boolean;
  group: SubscriptionGroupView | null;
  isNew: boolean;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

const GroupEditorModal: React.FC<GroupModalProps> = ({ open, group, isNew, onClose, onSaved }) => {
  const { t, submitMutation } = useApp();
  const [name, setName] = useState("");
  const [type, setType] = useState("select");
  const [interval, setInterval] = useState("300");
  const [tolerance, setTolerance] = useState("50");
  const [allNodes, setAllNodes] = useState("yes");
  const [orderedChoices, setOrderedChoices] = useState<(SubscriptionTargetOption & { checked: boolean })[]>([]);
  const [memberSearch, setMemberSearch] = useState("");
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open || !group) return;
    setName(group.Name || "");
    setType(group.Type || "select");
    setInterval(String(group.Interval || 300));
    setTolerance(String(group.Tolerance || 50));
    setAllNodes(group.AllNodes ? "yes" : "no");
    setOrderedChoices((group.Choices || []).map((c) => ({ ...c, checked: c.Selected })));
    setMemberSearch("");
    setDirty(false);
    setError("");
  }, [open, group]);

  useDirtyForm("sub-group-modal", open && dirty && !saving);

  const selectedChoices = useMemo(() => orderedChoices.filter((c) => c.checked), [orderedChoices]);

  const toggleMember = (val: string) => {
    setDirty(true);
    setOrderedChoices((prev) => {
      const toggled = prev.map((item) => (item.Value === val ? { ...item, checked: !item.checked } : item));
      return [...toggled.filter((i) => i.checked), ...toggled.filter((i) => !i.checked)];
    });
  };

  const moveMember = (val: string, delta: -1 | 1) => {
    setDirty(true);
    setOrderedChoices((prev) => {
      const selected = prev.filter((i) => i.checked);
      const unselected = prev.filter((i) => !i.checked);
      const idx = selected.findIndex((i) => i.Value === val);
      const nextIdx = idx + delta;
      if (idx < 0 || nextIdx < 0 || nextIdx >= selected.length) return prev;
      const copy = [...selected];
      const [moved] = copy.splice(idx, 1);
      copy.splice(nextIdx, 0, moved);
      return [...copy, ...unselected];
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!group || saving) return;
    setSaving(true);
    setError("");
    try {
      const action = isNew ? "/subscriptions/groups" : `/subscriptions/groups/${encodeURIComponent(group.ID)}`;
      await submitMutation(action, {
        name: name.trim(),
        type,
        interval,
        tolerance,
        all_nodes: allNodes,
        members: selectedChoices.map((c) => c.Value).join("\n"),
      });
      setDirty(false);
      onClose();
      await onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("Could not save proxy group."));
    } finally {
      setSaving(false);
    }
  };

  const query = memberSearch.trim().toLocaleLowerCase();

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isNew ? t("Add proxy group") : t("Edit proxy group")}
      size="form"
    >
      <form onSubmit={(e) => void handleSubmit(e)} noValidate>
        <div className="modal__body stack">
          {error && (
            <div className="notice notice--error" role="alert">
              {error}
            </div>
          )}
          <label className="field">
            <span>{t("Group name")}</span>
            <input
              value={name}
              maxLength={100}
              required
              placeholder={t("e.g. Streaming")}
              onChange={(e) => {
                setName(e.target.value);
                setDirty(true);
              }}
            />
          </label>
          <label className="field">
            <span>{t("Selection mode")}</span>
            <SelectBox
              searchable={false}
              value={type}
              onChange={(v) => {
                setType(v);
                setDirty(true);
              }}
              options={[
                { value: "select", label: t("Manual selection") },
                { value: "url-test", label: t("Automatic latency test") },
              ]}
            />
          </label>

          {type === "url-test" && (
            <div className="subscription-group-test-options">
              <label className="field">
                <span>{t("Test interval (seconds)")}</span>
                <input
                  type="number"
                  min={30}
                  max={86400}
                  value={interval}
                  required
                  onChange={(e) => {
                    setInterval(e.target.value);
                    setDirty(true);
                  }}
                />
              </label>
              <label className="field">
                <span>{t("Switch tolerance (ms)")}</span>
                <input
                  type="number"
                  min={1}
                  max={10000}
                  value={tolerance}
                  required
                  onChange={(e) => {
                    setTolerance(e.target.value);
                    setDirty(true);
                  }}
                />
              </label>
            </div>
          )}

          <label className="field">
            <span>{t("Automatically include new proxies")}</span>
            <SelectBox
              searchable={false}
              value={allNodes}
              onChange={(v) => {
                setAllNodes(v);
                setDirty(true);
              }}
              options={[
                { value: "yes", label: t("All available proxies") },
                { value: "no", label: t("Only selected members") },
              ]}
            />
          </label>
          <p className="form-help">
            {t("Selected members come first. In manual groups, the first available member is the initial choice. A Node without a family includes both addresses.")}
          </p>

          <fieldset className="subscription-member-picker">
            <legend>{t("Select proxies and groups")}</legend>
            <label className="field">
              <span className="sr-only">{t("Search members")}</span>
              <input
                type="search"
                value={memberSearch}
                onChange={(e) => setMemberSearch(e.target.value)}
                placeholder={t("Search members")}
              />
            </label>
            <div className="subscription-member-list">
              {orderedChoices.map((choice) => {
                const label = choice.Builtin ? t(choice.Label) : choice.Label;
                const kind = t(choice.Kind);
                if (query && !`${label} ${kind}`.toLocaleLowerCase().includes(query)) return null;
                const selIdx = selectedChoices.findIndex((s) => s.Value === choice.Value);
                return (
                  <div key={choice.Value} className={`subscription-member ${choice.checked ? "is-selected" : ""}`}>
                    <label>
                      <input
                        type="checkbox"
                        checked={choice.checked}
                        onChange={() => toggleMember(choice.Value)}
                      />
                      <span>
                        {label}
                        <small>{kind}</small>
                      </span>
                    </label>
                    <div>
                      <button
                        type="button"
                        className="button button--secondary button--icon-only"
                        aria-label={t("Move up")}
                        disabled={selIdx <= 0}
                        onClick={() => moveMember(choice.Value, -1)}
                      >
                        ↑
                      </button>
                      <button
                        type="button"
                        className="button button--secondary button--icon-only"
                        aria-label={t("Move down")}
                        disabled={selIdx < 0 || selIdx === selectedChoices.length - 1}
                        onClick={() => moveMember(choice.Value, 1)}
                      >
                        ↓
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
            <small role="status">
              {t("{count} members selected").replace("{count}", String(selectedChoices.length))}
            </small>
          </fieldset>
        </div>

        <footer className="modal__footer">
          <button type="button" className="button button--secondary" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="button button--primary" disabled={saving}>
            {saving ? t("Saving…") : isNew ? t("Add group") : t("Save group")}
          </button>
        </footer>
      </form>
    </Modal>
  );
};

interface RuleModalProps {
  open: boolean;
  rule: SubscriptionRuleView | null;
  targets: SubscriptionTargetPicker;
  onClose: () => void;
  onSaved: () => Promise<void>;
}

const RuleEditorModal: React.FC<RuleModalProps> = ({ open, rule, targets, onClose, onSaved }) => {
  const { t, submitMutation } = useApp();
  const isNew = !rule;

  const [match, setMatch] = useState("domain");
  const [values, setValues] = useState("");
  const [noResolve, setNoResolve] = useState(false);
  const [action, setAction] = useState("proxy");
  const [newGroupName, setNewGroupName] = useState("");
  const [userEditedGroupName, setUserEditedGroupName] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const [catalogOptions, setCatalogOptions] = useState<string[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState("");

  useEffect(() => {
    if (!open) return;
    setMatch(rule?.Match || "domain");
    setValues(rule?.Values || "");
    setNoResolve(Boolean(rule?.NoResolve));
    setAction(rule?.Action || targets.Action || "proxy");
    setNewGroupName("");
    setUserEditedGroupName(false);
    setDirty(false);
    setError("");
  }, [open, rule, targets.Action]);

  useDirtyForm("sub-rule-modal", open && dirty && !saving);

  const kind = match === "geosite" || match === "geoip" ? match : "";

  const loadCatalog = useCallback(async (targetKind: "geosite" | "geoip") => {
    setCatalogLoading(true);
    setCatalogError("");
    try {
      const opts = await fetchRuleSetCatalog(targetKind);
      setCatalogOptions(opts);
    } catch {
      setCatalogError(t("Rule set catalog unavailable."));
    } finally {
      setCatalogLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (open && (kind === "geosite" || kind === "geoip")) {
      void loadCatalog(kind);
    }
  }, [open, kind, loadCatalog]);

  const updateValues = (next: string) => {
    setValues(next);
    setDirty(true);
    if (action === "new_group" && !userEditedGroupName) {
      setNewGroupName(suggestGroupName(next));
    }
  };

  const handleActionChange = (nextAction: string) => {
    setAction(nextAction);
    setDirty(true);
    if (nextAction === "new_group" && !userEditedGroupName) {
      const suggested = suggestGroupName(values);
      if (suggested) setNewGroupName(suggested);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (saving) return;
    setSaving(true);
    setError("");
    try {
      const url = isNew ? "/subscriptions/rules" : `/subscriptions/rules/${encodeURIComponent(rule.ID)}`;
      const supportsNoResolve = match === "ip_cidr" || match === "geoip";
      const fields: Record<string, string> = {
        match,
        values,
        action,
        no_resolve: supportsNoResolve && noResolve ? "yes" : "no",
      };
      if (action === "new_group") {
        fields.new_group_name = newGroupName.trim();
      }
      await submitMutation(url, fields);
      setDirty(false);
      onClose();
      await onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("Could not save rule."));
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!rule || saving) return;
    setSaving(true);
    setError("");
    try {
      await submitMutation(`/subscriptions/rules/${encodeURIComponent(rule.ID)}/delete`, {});
      setDirty(false);
      onClose();
      await onSaved();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("Could not delete rule."));
    } finally {
      setSaving(false);
    }
  };

  const matchOptions = [
    { value: "domain", label: t("Domain") },
    { value: "domain_suffix", label: t("Domain suffix") },
    { value: "domain_keyword", label: t("Domain keyword") },
    { value: "domain_regex", label: t("Domain regex") },
    { value: "ip_cidr", label: "IP/CIDR" },
    { value: "source_ip_cidr", label: t("Source IP/CIDR") },
    { value: "geosite", label: "Geosite" },
    { value: "geoip", label: "GeoIP" },
    { value: "destination_port", label: t("Destination port") },
    { value: "source_port", label: t("Source port") },
    { value: "network", label: t("Network") },
    { value: "process_name", label: t("Process name") },
  ];

  const routeOptions = [
    { value: "new_group", label: t("Create new proxy group"), detail: t("Copy of PROXY") },
    ...(targets.Options || []).map((opt) => ({
      value: opt.Value,
      label: opt.Builtin ? t(opt.Label) : opt.Label,
      detail: t(opt.Kind),
    })),
  ];

  const ruleSetSelectOptions = useMemo(() => {
    const items: { value: string; label: string; disabled?: boolean }[] = [
      {
        value: "",
        label: kind === "geosite" ? t("Select a Geosite rule set") : t("Select a GeoIP rule set"),
        disabled: true,
      },
    ];
    if (values && !catalogOptions.includes(values)) {
      items.push({ value: values, label: values.replaceAll("\n", ", ") });
    }
    for (const opt of catalogOptions) items.push({ value: opt, label: opt });
    return items;
  }, [kind, values, catalogOptions, t]);

  const supportsNoResolve = match === "ip_cidr" || match === "geoip";

  return (
    <Modal
      open={open}
      onClose={onClose}
      eyebrow={isNew ? t("Subscription rule") : `${t("Rule")} ${rule.Position}`}
      title={isNew ? t("Add rule") : t("Edit rule")}
      size="form"
    >
      <form onSubmit={(e) => void handleSubmit(e)} noValidate>
        <div className="modal__body stack">
          {error && (
            <div className="notice notice--error" role="alert">
              {error}
            </div>
          )}
          <label className="field">
            <span>{t("Match")}</span>
            <SelectBox
              searchable={false}
              value={match}
              onChange={(nextMatch) => {
                const nextKind = nextMatch === "geosite" || nextMatch === "geoip" ? nextMatch : "";
                setMatch(nextMatch);
                setDirty(true);
                if (nextKind && nextKind !== kind) setValues("");
              }}
              options={matchOptions}
            />
          </label>

          {!kind ? (
            <label className="field">
              <span>{t("Values")}</span>
              <textarea
                className="resize-none"
                data-route-field="match_values"
                rows={5}
                placeholder={t("One value per line")}
                value={values}
                onChange={(e) => updateValues(e.target.value)}
                required
              />
            </label>
          ) : (
            <label className="field">
              <span>{kind === "geosite" ? "Geosite" : "GeoIP"}</span>
              <SelectBox
                value={values}
                onChange={updateValues}
                options={ruleSetSelectOptions}
                disabled={catalogLoading && !values}
                placeholder={catalogLoading ? t("Loading…") : undefined}
              />
              {catalogLoading && <small className="subscription-rule-set-status">{t("Loading…")}</small>}
              {catalogError && (
                <small className="subscription-rule-set-status">
                  <span>{catalogError}</span>{" "}
                  <button type="button" className="button-link" onClick={() => void loadCatalog(kind)}>
                    {t("Retry")}
                  </button>
                </small>
              )}
            </label>
          )}

          {supportsNoResolve && (
            <label className="field-check">
              <input
                type="checkbox"
                checked={noResolve}
                onChange={(e) => {
                  setNoResolve(e.target.checked);
                  setDirty(true);
                }}
              />
              <span>{t("No Resolve")}</span>
            </label>
          )}

          <label className="field">
            <span>{t("Route")}</span>
            <SelectBox value={action} onChange={handleActionChange} options={routeOptions} />
          </label>

          {action === "new_group" && (
            <label className="field">
              <span>{t("New proxy group name")}</span>
              <input
                maxLength={100}
                placeholder={t("e.g. Streaming")}
                value={newGroupName}
                required
                autoFocus
                onChange={(e) => {
                  setNewGroupName(e.target.value);
                  setUserEditedGroupName(Boolean(e.target.value.trim()));
                  setDirty(true);
                }}
              />
              <small>
                {t("Copies the main PROXY group (all available proxies, Direct, and Reject). You can edit or delete it later.")}
              </small>
            </label>
          )}
        </div>

        <footer className="modal__footer">
          {!isNew && (
            <button
              type="button"
              className="button button--danger"
              disabled={saving}
              onClick={() => void handleDelete()}
            >
              {t("Delete rule")}
            </button>
          )}
          <button type="button" className="button button--secondary" onClick={onClose}>
            {t("Cancel")}
          </button>
          <button type="submit" className="button button--primary" disabled={saving}>
            {saving ? t("Saving…") : isNew ? t("Add rule") : t("Save")}
          </button>
        </footer>
      </form>
    </Modal>
  );
};

export const SubscriptionsPage: React.FC = () => {
  const { t, countLabel, submitMutation } = useApp();
  const { data, loading, error, reload } = usePageData("/subscriptions");

  const policy = data?.SubscriptionPolicy;
  const groups = policy?.Groups || [];

  const [ruleSearch, setRuleSearch] = useState("");
  const [orderedRules, setOrderedRules] = useState<SubscriptionRuleView[]>([]);
  const [ruleActions, setRuleActions] = useState<Record<string, string>>({});
  const [defaultAction, setDefaultAction] = useState("proxy");
  const [reorderStatus, setReorderStatus] = useState("");
  const [reorderError, setReorderError] = useState(false);
  const [dragId, setDragId] = useState<string | null>(null);
  const dragOriginRef = useRef<SubscriptionRuleView[] | null>(null);
  const droppedRef = useRef(false);
  const [busyKey, setBusyKey] = useState("");
  const [pageError, setPageError] = useState("");

  // Modals
  const [groupModal, setGroupModal] = useState<{ open: boolean; group: SubscriptionGroupView | null; isNew: boolean }>({
    open: false,
    group: null,
    isNew: true,
  });
  const [deleteGroup, setDeleteGroup] = useState<SubscriptionGroupView | null>(null);
  const [deleteReplacement, setDeleteReplacement] = useState("proxy");
  const [ruleModal, setRuleModal] = useState<{ open: boolean; rule: SubscriptionRuleView | null }>({
    open: false,
    rule: null,
  });

  useEffect(() => {
    if (!policy) return;
    setOrderedRules(policy.Rules || []);
    const nextActions: Record<string, string> = {};
    for (const r of policy.Rules || []) nextActions[r.ID] = r.Action;
    setRuleActions(nextActions);
    setDefaultAction(policy.DefaultAction || policy.DefaultTargets.Action || "proxy");
  }, [policy]);

  const persistRuleOrder = async (
    nextList: SubscriptionRuleView[],
    movedIndex: number,
    rollbackList: SubscriptionRuleView[] = orderedRules,
  ) => {
    setOrderedRules(nextList);
    setBusyKey("reorder");
    setReorderError(false);
    try {
      await submitMutation("/subscriptions/rules/reorder", {
        rule_ids: nextList.map((r) => r.ID).join(","),
      });
      setReorderStatus(t("Rule moved to position {position}.").replace("{position}", String(movedIndex + 1)));
      await reload();
    } catch {
      setOrderedRules(rollbackList);
      setReorderError(true);
      setReorderStatus(t("Rule order could not be saved. Previous order restored."));
    } finally {
      setBusyKey("");
    }
  };

  const moveRuleByKey = (index: number, delta: -1 | 1) => {
    const nextIdx = index + delta;
    if (nextIdx < 0 || nextIdx >= orderedRules.length || busyKey === "reorder" || ruleSearch.trim()) return;
    const copy = [...orderedRules];
    const [moved] = copy.splice(index, 1);
    copy.splice(nextIdx, 0, moved);
    void persistRuleOrder(copy, nextIdx);
  };

  const saveRuleAction = async (ruleId: string) => {
    if (busyKey) return;
    setBusyKey(`rule-${ruleId}`);
    setPageError("");
    try {
      await submitMutation(`/subscriptions/rules/${encodeURIComponent(ruleId)}/action`, {
        action: ruleActions[ruleId] || "proxy",
      });
      await reload();
    } catch (err) {
      setPageError(err instanceof ApiError ? err.message : t("Could not update rule."));
    } finally {
      setBusyKey("");
    }
  };

  const saveDefaultAction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busyKey) return;
    setBusyKey("default");
    setPageError("");
    try {
      await submitMutation("/subscriptions/default", { action: defaultAction });
      await reload();
    } catch (err) {
      setPageError(err instanceof ApiError ? err.message : t("Could not save final policy."));
    } finally {
      setBusyKey("");
    }
  };

  const confirmDeleteGroup = async () => {
    if (!deleteGroup || busyKey) return;
    setBusyKey("delete-group");
    setPageError("");
    try {
      await submitMutation(`/subscriptions/groups/${encodeURIComponent(deleteGroup.ID)}/delete`, {
        replacement: deleteReplacement,
      });
      setDeleteGroup(null);
      await reload();
    } catch (err) {
      setPageError(err instanceof ApiError ? err.message : t("Could not delete proxy group."));
    } finally {
      setBusyKey("");
    }
  };

  const mapTargetOptions = (picker: SubscriptionTargetPicker) =>
    (picker.Options || []).map((opt) => ({
      value: opt.Value,
      label: opt.Builtin ? t(opt.Label) : opt.Label,
      detail: t(opt.Kind),
    }));

  const searchLower = ruleSearch.trim().toLocaleLowerCase();

  return (
    <AppLayout activeNav="subscriptions">
      <header className="page-header">
        <div>
          <p className="eyebrow">{t("Universal Export Policy")}</p>
          <h1>{t("Subscriptions")}</h1>
        </div>
        {data?.AdministratorProxyAccessEnabled && (
          <div className="page-header__actions">
            <Link className="button button--secondary" to="/subscriptions/admin">
              {t("My Subscription")}
            </Link>
          </div>
        )}
      </header>
      <p className="form-help">
        {t("Domain-regex rules are not exported to Surge. Use Domain or Domain suffix when the rule must work in all clients.")}
      </p>

      {pageError && (
        <div className="notice notice--error" role="alert">
          {pageError}
        </div>
      )}

      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        {policy && (
          <>
            <section className="panel" id="proxy-groups">
              <div className="panel__header">
                <div>
                  <h2>{t("Proxy groups")}</h2>
                  <p className="form-help">
                    {t("Organize proxies once, then choose a group or individual proxy for any rule.")}
                  </p>
                </div>
                <button
                  type="button"
                  className="button button--primary"
                  onClick={() => setGroupModal({ open: true, group: policy.NewGroup, isNew: true })}
                >
                  {t("Add group")}
                </button>
              </div>

              <div className="subscription-group-grid">
                <article className="subscription-group-card subscription-group-card--builtin">
                  <div className="subscription-group-card__heading">
                    <strong>PROXY</strong>
                    <span className="protocol-badge">{t("Built-in")}</span>
                  </div>
                  <p>{t("All available proxies")}</p>
                  <small>{t("Includes each user's available proxies, Direct, and Reject.")}</small>
                </article>

                {groups.map((group) => (
                  <article key={group.ID} className="subscription-group-card">
                    <div className="subscription-group-card__heading">
                      <strong>{group.Name}</strong>
                      <span className="protocol-badge">
                        {group.Type === "url-test" ? t("Automatic latency test") : t("Manual selection")}
                      </span>
                    </div>
                    <div className="subscription-group-members">
                      {group.AllNodes && <span>{t("All available proxies")}</span>}
                      {(group.Choices || [])
                        .filter((c) => c.Selected)
                        .map((c) => (
                          <span key={c.Value}>{c.Builtin ? t(c.Label) : c.Label}</span>
                        ))}
                    </div>
                    <footer>
                      <small>{countLabel(group.References, "reference")}</small>
                      <div>
                        <button
                          type="button"
                          className="button button--secondary button--small"
                          onClick={() => setGroupModal({ open: true, group, isNew: false })}
                        >
                          {t("Edit")}
                        </button>
                        <button
                          type="button"
                          className="button button--danger button--small"
                          onClick={() => {
                            setDeleteGroup(group);
                            setDeleteReplacement(group.Replacement.Action || "proxy");
                          }}
                        >
                          {t("Delete")}
                        </button>
                      </div>
                    </footer>
                  </article>
                ))}
              </div>
              <p className="form-help subscription-policy-help">
                {t("Each user only receives proxies they can access. Unavailable proxy targets and empty custom groups reject traffic.")}
              </p>
            </section>

            <section className="panel" id="subscription-rules">
              <div className="panel__header">
                <h2>{t("Rules")}</h2>
                <button
                  type="button"
                  className="button button--primary"
                  onClick={() => setRuleModal({ open: true, rule: null })}
                >
                  {t("Add rule")}
                </button>
              </div>
              <div className="subscription-rule-toolbar">
                <label className="field">
                  <span className="sr-only">{t("Search rules")}</span>
                  <input
                    type="search"
                    value={ruleSearch}
                    onChange={(e) => setRuleSearch(e.target.value)}
                    placeholder={t("Search rules")}
                  />
                </label>
                <p className="form-help">
                  {t("First match wins. Drag the handle or use its arrow keys to reorder.")}
                </p>
              </div>

              {orderedRules.length > 0 ? (
                <>
                  <ol className="subscription-rule-list" aria-busy={busyKey === "reorder"}>
                    {orderedRules.map((rule, index) => {
                      const targetOpts = mapTargetOptions(rule.Targets);
                      const currentAct = ruleActions[rule.ID] ?? rule.Action;
                      const selectedLabel = targetOpts.find((o) => o.value === currentAct)?.label || "";
                      const matchesSearch =
                        !searchLower ||
                        `${rule.MatchLabel} ${rule.Summary} ${selectedLabel}`.toLocaleLowerCase().includes(searchLower);
                      if (!matchesSearch) return null;

                      return (
                        <li
                          key={rule.ID}
                          draggable={!searchLower && busyKey !== "reorder"}
                          className={dragId === rule.ID ? "is-dragging" : ""}
                          onDragStart={() => {
                            dragOriginRef.current = orderedRules;
                            droppedRef.current = false;
                            setDragId(rule.ID);
                          }}
                          onDragOver={(e) => {
                            if (!dragId || dragId === rule.ID) return;
                            e.preventDefault();
                            const fromIdx = orderedRules.findIndex((r) => r.ID === dragId);
                            if (fromIdx < 0 || fromIdx === index) return;
                            const copy = [...orderedRules];
                            const [moved] = copy.splice(fromIdx, 1);
                            copy.splice(index, 0, moved);
                            setOrderedRules(copy);
                          }}
                          onDrop={(e) => {
                            e.preventDefault();
                            if (!dragId) return;
                            const finalIdx = orderedRules.findIndex((r) => r.ID === dragId);
                            const origin = dragOriginRef.current || orderedRules;
                            droppedRef.current = true;
                            dragOriginRef.current = null;
                            setDragId(null);
                            if (finalIdx >= 0) void persistRuleOrder(orderedRules, finalIdx, origin);
                          }}
                          onDragEnd={() => {
                            if (!droppedRef.current && dragOriginRef.current) {
                              setOrderedRules(dragOriginRef.current);
                            }
                            dragOriginRef.current = null;
                            droppedRef.current = false;
                            setDragId(null);
                          }}
                        >
                          <button
                            type="button"
                            className="subscription-rule__handle"
                            disabled={Boolean(searchLower) || busyKey === "reorder"}
                            aria-keyshortcuts="ArrowUp ArrowDown"
                            onKeyDown={(e) => {
                              if (e.key === "ArrowUp") {
                                e.preventDefault();
                                moveRuleByKey(index, -1);
                              } else if (e.key === "ArrowDown") {
                                e.preventDefault();
                                moveRuleByKey(index, 1);
                              }
                            }}
                          >
                            <svg viewBox="0 0 20 20" aria-hidden="true">
                              <circle cx="7" cy="5" r="1.2" />
                              <circle cx="13" cy="5" r="1.2" />
                              <circle cx="7" cy="10" r="1.2" />
                              <circle cx="13" cy="10" r="1.2" />
                              <circle cx="7" cy="15" r="1.2" />
                              <circle cx="13" cy="15" r="1.2" />
                            </svg>
                            <span className="sr-only">{t("Reorder Rule")}</span>
                          </button>
                          <span className="subscription-rule__order">{index + 1}</span>
                          <div className="subscription-rule__copy">
                            <strong>{rule.MatchLabel}</strong>
                            <small>
                              {rule.Summary}
                              {rule.NoResolve && (
                                <>
                                  {" · "}
                                  <b>{t("No Resolve")}</b>
                                </>
                              )}
                            </small>
                          </div>
                          <form
                            className="subscription-rule__target"
                            onSubmit={(e) => {
                              e.preventDefault();
                              void saveRuleAction(rule.ID);
                            }}
                            noValidate
                          >
                            <label className="field">
                              <span className="sr-only">
                                {t("Final policy")} · {t("Rule")} {index + 1}
                              </span>
                              <SelectBox
                                value={currentAct}
                                onChange={(val) => setRuleActions((prev) => ({ ...prev, [rule.ID]: val }))}
                                options={targetOpts}
                              />
                            </label>
                            <button
                              type="submit"
                              className="button button--secondary button--small"
                              disabled={busyKey === `rule-${rule.ID}`}
                            >
                              {t("Save")}
                            </button>
                          </form>
                          <div className="subscription-rule__actions">
                            <button
                              type="button"
                              className="button button--secondary button--small"
                              onClick={() => setRuleModal({ open: true, rule })}
                            >
                              {t("Edit")}
                            </button>
                          </div>
                        </li>
                      );
                    })}
                  </ol>
                  {reorderStatus && (
                    <p
                      className={`subscription-rule__reorder-status ${reorderError ? "is-error" : "sr-only"}`}
                      role="status"
                      aria-live="polite"
                    >
                      {reorderStatus}
                    </p>
                  )}
                </>
              ) : (
                <div className="panel__empty">
                  <strong>{t("No rules")}</strong>
                </div>
              )}
            </section>

            <section className="panel subscription-default">
              <div className="panel__header">
                <h2>{t("FINAL (Unmatched Rules)")}</h2>
              </div>
              <form className="inline-form" onSubmit={(e) => void saveDefaultAction(e)} noValidate>
                <label className="field">
                  <span>{t("Route")}</span>
                  <SelectBox
                    value={defaultAction}
                    onChange={setDefaultAction}
                    options={mapTargetOptions(policy.DefaultTargets)}
                  />
                </label>
                <button type="submit" className="button button--secondary" disabled={busyKey === "default"}>
                  {t("Save")}
                </button>
              </form>
            </section>

            <GroupEditorModal
              open={groupModal.open}
              group={groupModal.group}
              isNew={groupModal.isNew}
              onClose={() => setGroupModal((prev) => ({ ...prev, open: false }))}
              onSaved={reload}
            />

            <RuleEditorModal
              open={ruleModal.open}
              rule={ruleModal.rule}
              targets={ruleModal.rule ? ruleModal.rule.Targets : policy.NewRuleTargets}
              onClose={() => setRuleModal({ open: false, rule: null })}
              onSaved={reload}
            />

            <Modal
              open={Boolean(deleteGroup)}
              onClose={() => setDeleteGroup(null)}
              title={t("Delete proxy group?")}
              size="compact"
              footer={
                <>
                  <button type="button" className="button button--secondary" onClick={() => setDeleteGroup(null)}>
                    {t("Cancel")}
                  </button>
                  <button
                    type="button"
                    className="button button--danger"
                    disabled={busyKey === "delete-group"}
                    onClick={() => void confirmDeleteGroup()}
                  >
                    {t("Delete group")}
                  </button>
                </>
              }
            >
              {deleteGroup && (
                <div className="modal__body stack">
                  <strong>{deleteGroup.Name}</strong>
                  <p>
                    {t("Choose a replacement for every rule, group member, and final policy that references this group.")}
                  </p>
                  <label className="field">
                    <span>{t("Replace references with")}</span>
                    <SelectBox
                      value={deleteReplacement}
                      onChange={setDeleteReplacement}
                      options={mapTargetOptions(deleteGroup.Replacement)}
                    />
                  </label>
                </div>
              )}
            </Modal>
          </>
        )}
      </AsyncState>
    </AppLayout>
  );
};
