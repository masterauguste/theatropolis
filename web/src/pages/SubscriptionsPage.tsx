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
  const [activeChoices, setActiveChoices] = useState<SubscriptionTargetOption[]>([]);
  const [inactiveChoices, setInactiveChoices] = useState<SubscriptionTargetOption[]>([]);
  const [memberSearch, setMemberSearch] = useState("");
  const [draggingValue, setDraggingValue] = useState<string | null>(null);
  const [dropPreview, setDropPreview] = useState<{ zone: "active" | "inactive"; index: number } | null>(null);
  const [dirty, setDirty] = useState(false);
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!open || !group) return;
    setName(group.Name || "");
    const all = group.Choices || [];
    setActiveChoices(all.filter((c) => c.Selected));
    setInactiveChoices(all.filter((c) => !c.Selected));
    setMemberSearch("");
    setDraggingValue(null);
    setDropPreview(null);
    setDirty(false);
    setError("");
  }, [open, group]);

  useDirtyForm("sub-group-modal", open && dirty && !saving);

  const commitDrop = useCallback(
    (dragVal: string, targetZone: "active" | "inactive", targetIndex: number) => {
      const sourceZone = activeChoices.some((c) => c.Value === dragVal)
        ? "active"
        : inactiveChoices.some((c) => c.Value === dragVal)
          ? "inactive"
          : null;
      if (!sourceZone) return;
      const sourceList = sourceZone === "active" ? activeChoices : inactiveChoices;
      const sourceIdx = sourceList.findIndex((c) => c.Value === dragVal);
      if (sourceIdx < 0) return;
      const item = sourceList[sourceIdx];

      let adjustedIndex = targetIndex;
      if (sourceZone === targetZone && sourceIdx < targetIndex) {
        adjustedIndex -= 1;
      }

      const nextActive = activeChoices.filter((c) => c.Value !== dragVal);
      const nextInactive = inactiveChoices.filter((c) => c.Value !== dragVal);

      if (targetZone === "active") {
        const clamped = Math.max(0, Math.min(adjustedIndex, nextActive.length));
        nextActive.splice(clamped, 0, item);
      } else {
        const clamped = Math.max(0, Math.min(adjustedIndex, nextInactive.length));
        nextInactive.splice(clamped, 0, item);
      }

      const activeSame =
        nextActive.length === activeChoices.length &&
        nextActive.every((c, i) => c.Value === activeChoices[i].Value);
      const inactiveSame =
        nextInactive.length === inactiveChoices.length &&
        nextInactive.every((c, i) => c.Value === inactiveChoices[i].Value);
      if (activeSame && inactiveSame) return;

      setActiveChoices(nextActive);
      setInactiveChoices(nextInactive);
      setDirty(true);
    },
    [activeChoices, inactiveChoices],
  );

  const handleCardKeyDown = (zone: "active" | "inactive", val: string, e: React.KeyboardEvent) => {
    if (zone === "active" && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
      e.preventDefault();
      const idx = activeChoices.findIndex((c) => c.Value === val);
      const nextIdx = idx + (e.key === "ArrowUp" ? -1 : 1);
      if (idx < 0 || nextIdx < 0 || nextIdx >= activeChoices.length) return;
      const copy = [...activeChoices];
      const [moved] = copy.splice(idx, 1);
      copy.splice(nextIdx, 0, moved);
      setActiveChoices(copy);
      setDirty(true);
    } else if (e.key === " " || e.key === "Enter") {
      e.preventDefault();
      if (zone === "active") {
        commitDrop(val, "inactive", 0);
      } else {
        commitDrop(val, "active", activeChoices.length);
      }
    }
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
        type: "select",
        members: activeChoices.map((c) => c.Value).join("\n"),
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

  const totalCount = activeChoices.length + inactiveChoices.length;
  const query = memberSearch.trim().toLocaleLowerCase();

  const matchesQuery = (choice: SubscriptionTargetOption) => {
    if (!query) return true;
    const label = choice.Builtin ? t(choice.Label) : choice.Label;
    const kind = t(choice.Kind);
    return `${label} ${kind}`.toLocaleLowerCase().includes(query);
  };

  const gripIcon = (
    <span className="subscription-member__grip" aria-hidden="true">
      <svg viewBox="0 0 20 20">
        <circle cx="7" cy="5" r="1.2" />
        <circle cx="13" cy="5" r="1.2" />
        <circle cx="7" cy="10" r="1.2" />
        <circle cx="13" cy="10" r="1.2" />
        <circle cx="7" cy="15" r="1.2" />
        <circle cx="13" cy="15" r="1.2" />
      </svg>
    </span>
  );

  const startDrag = (val: string, e: React.DragEvent) => {
    setDraggingValue(val);
    setDropPreview(null);
    e.dataTransfer.effectAllowed = "move";
    e.dataTransfer.setData("text/plain", val);
  };

  const finishDrag = () => {
    setDraggingValue(null);
    setDropPreview(null);
  };

  const updateDropPreview = (zone: "active" | "inactive", index: number) => {
    setDropPreview((prev) => (prev && prev.zone === zone && prev.index === index ? prev : { zone, index }));
  };

  const handleDropOn = (zone: "active" | "inactive", fallbackIndex: number, e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    const dragVal = draggingValue || e.dataTransfer.getData("text/plain");
    const targetIndex = dropPreview && dropPreview.zone === zone ? dropPreview.index : fallbackIndex;
    if (dragVal) {
      commitDrop(dragVal, zone, targetIndex);
    }
    setDraggingValue(null);
    setDropPreview(null);
  };

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

          <p className="form-help">
            {t("Drag options between Active and Inactive, or drag within Active to reorder. The first active option is selected by default. All available nodes expands to every proxy each user has access to.")}
          </p>

          <fieldset className="subscription-member-picker">
            <legend>{t("Policy options")}</legend>
            {totalCount > 8 && (
              <label className="field">
                <span className="sr-only">{t("Search members")}</span>
                <input
                  type="search"
                  value={memberSearch}
                  onChange={(e) => setMemberSearch(e.target.value)}
                  placeholder={t("Search members")}
                />
              </label>
            )}

            <div className="subscription-member-zones">
              <div
                className={`subscription-member-zone subscription-member-zone--active ${dropPreview?.zone === "active" ? "is-drop-target" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.dataTransfer.dropEffect = "move";
                  updateDropPreview("active", activeChoices.length);
                }}
                onDrop={(e) => handleDropOn("active", activeChoices.length, e)}
              >
                <div className="subscription-member-zone__header">
                  <strong>{t("Active options")}</strong>
                  <span className="panel__count">{activeChoices.length}</span>
                </div>
                <div className="subscription-member-list">
                  {activeChoices.length === 0 ? (
                    <div className="subscription-member-zone__empty">{t("Drag options here to enable")}</div>
                  ) : (
                    <>
                      {activeChoices.map((choice, idx) => {
                        if (!matchesQuery(choice)) return null;
                        const label = choice.Builtin ? t(choice.Label) : choice.Label;
                        const kind = t(choice.Kind);
                        const showBefore = dropPreview?.zone === "active" && dropPreview.index === idx;
                        return (
                          <React.Fragment key={choice.Value}>
                            {showBefore && <div className="subscription-member-drop-line" aria-hidden="true" />}
                            <div
                              draggable
                              tabIndex={0}
                              className={`subscription-member subscription-member--draggable is-selected ${draggingValue === choice.Value ? "is-dragging" : ""}`}
                              onDragStart={(e) => startDrag(choice.Value, e)}
                              onDragOver={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                e.dataTransfer.dropEffect = "move";
                                const rect = e.currentTarget.getBoundingClientRect();
                                const placeAfter = e.clientY > rect.top + rect.height / 2;
                                updateDropPreview("active", placeAfter ? idx + 1 : idx);
                              }}
                              onDrop={(e) => handleDropOn("active", idx, e)}
                              onDragEnd={finishDrag}
                              onKeyDown={(e) => handleCardKeyDown("active", choice.Value, e)}
                            >
                              {gripIcon}
                              <span className="subscription-member__order">{idx + 1}</span>
                              <div className="subscription-member__copy">
                                <span>{label}</span>
                                <small>{kind}</small>
                              </div>
                              {idx === 0 && <span className="subscription-member__default">{t("Default")}</span>}
                            </div>
                          </React.Fragment>
                        );
                      })}
                      {dropPreview?.zone === "active" && dropPreview.index === activeChoices.length && (
                        <div className="subscription-member-drop-line" aria-hidden="true" />
                      )}
                    </>
                  )}
                </div>
              </div>

              <div
                className={`subscription-member-zone subscription-member-zone--inactive ${dropPreview?.zone === "inactive" ? "is-drop-target" : ""}`}
                onDragOver={(e) => {
                  e.preventDefault();
                  e.dataTransfer.dropEffect = "move";
                  updateDropPreview("inactive", inactiveChoices.length);
                }}
                onDrop={(e) => handleDropOn("inactive", inactiveChoices.length, e)}
              >
                <div className="subscription-member-zone__header">
                  <strong>{t("Inactive options")}</strong>
                  <span className="panel__count">{inactiveChoices.length}</span>
                </div>
                <div className="subscription-member-list">
                  {inactiveChoices.length === 0 ? (
                    <div className="subscription-member-zone__empty">{t("Drag options here to disable")}</div>
                  ) : (
                    <>
                      {inactiveChoices.map((choice, idx) => {
                        if (!matchesQuery(choice)) return null;
                        const label = choice.Builtin ? t(choice.Label) : choice.Label;
                        const kind = t(choice.Kind);
                        const showBefore = dropPreview?.zone === "inactive" && dropPreview.index === idx;
                        return (
                          <React.Fragment key={choice.Value}>
                            {showBefore && <div className="subscription-member-drop-line" aria-hidden="true" />}
                            <div
                              draggable
                              tabIndex={0}
                              className={`subscription-member subscription-member--draggable is-inactive ${draggingValue === choice.Value ? "is-dragging" : ""}`}
                              onDragStart={(e) => startDrag(choice.Value, e)}
                              onDragOver={(e) => {
                                e.preventDefault();
                                e.stopPropagation();
                                e.dataTransfer.dropEffect = "move";
                                const rect = e.currentTarget.getBoundingClientRect();
                                const placeAfter = e.clientY > rect.top + rect.height / 2;
                                updateDropPreview("inactive", placeAfter ? idx + 1 : idx);
                              }}
                              onDrop={(e) => handleDropOn("inactive", idx, e)}
                              onDragEnd={finishDrag}
                              onKeyDown={(e) => handleCardKeyDown("inactive", choice.Value, e)}
                            >
                              {gripIcon}
                              <div className="subscription-member__copy">
                                <span>{label}</span>
                                <small>{kind}</small>
                              </div>
                            </div>
                          </React.Fragment>
                        );
                      })}
                      {dropPreview?.zone === "inactive" && dropPreview.index === inactiveChoices.length && (
                        <div className="subscription-member-drop-line" aria-hidden="true" />
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
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
    { value: "new_group", label: t("Create new proxy group"), detail: t("PROXY, user's proxies, Direct, Reject") },
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
                {t("Creates a manual group with PROXY (follows the user's current PROXY selection), every proxy each user has access to, Direct, and Reject. You can edit or delete it later.")}
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
                    {t("Define global policy groups for all users. Choose and order PROXY, All available nodes, Direct, Reject, or other groups.")}
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
                  <p>{t("Main proxy selector")}</p>
                  <small>{t("Includes every proxy each user has access to, plus Direct and Reject.")}</small>
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
                {t("All available nodes expands per user to only the proxies that account has access to.")}
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
