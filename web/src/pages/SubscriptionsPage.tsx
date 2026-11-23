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
import {
  computeDropIndex,
  isNoOpSameListDrop,
  moveBetweenLists,
  reorderList,
  type DragDirection,
} from "../utils/dragSort";

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

interface GroupDragState {
  value: string;
  sourceZone: "active" | "inactive";
  sourceIdx: number;
  label: string;
  kind: string;
  x: number;
  y: number;
  offsetX: number;
  offsetY: number;
  width: number;
  targetZone: "active" | "inactive";
  targetIdx: number;
}

const GroupEditorModal: React.FC<GroupModalProps> = ({ open, group, isNew, onClose, onSaved }) => {
  const { t, submitMutation } = useApp();
  const [name, setName] = useState("");
  const [activeChoices, setActiveChoices] = useState<SubscriptionTargetOption[]>([]);
  const [inactiveChoices, setInactiveChoices] = useState<SubscriptionTargetOption[]>([]);
  const [memberSearch, setMemberSearch] = useState("");
  const [dragState, setDragState] = useState<GroupDragState | null>(null);
  const activeZoneRef = useRef<HTMLDivElement>(null);
  const inactiveZoneRef = useRef<HTMLDivElement>(null);
  const activeListRef = useRef<HTMLDivElement>(null);
  const inactiveListRef = useRef<HTMLDivElement>(null);
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
    setDragState(null);
    setDirty(false);
    setError("");
  }, [open, group]);

  useDirtyForm("sub-group-modal", open && dirty && !saving);

  const commitMove = useCallback(
    (sourceZone: "active" | "inactive", sourceIdx: number, targetZone: "active" | "inactive", targetIdx: number) => {
      const res = moveBetweenLists(activeChoices, inactiveChoices, sourceZone, sourceIdx, targetZone, targetIdx);
      if (!res.changed) return;
      setActiveChoices(res.active);
      setInactiveChoices(res.inactive);
      setDirty(true);
    },
    [activeChoices, inactiveChoices],
  );

  const handleCardKeyDown = (zone: "active" | "inactive", idx: number, e: React.KeyboardEvent) => {
    if (zone === "active" && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
      e.preventDefault();
      const targetIdx = e.key === "ArrowUp" ? idx - 1 : idx + 2;
      if (targetIdx < 0 || targetIdx > activeChoices.length) return;
      commitMove("active", idx, "active", targetIdx);
    } else if (e.key === " " || e.key === "Enter") {
      e.preventDefault();
      if (zone === "active") {
        commitMove("active", idx, "inactive", 0);
      } else {
        commitMove("inactive", idx, "active", activeChoices.length);
      }
    }
  };

  const handlePointerDown = (
    zone: "active" | "inactive",
    idx: number,
    choice: SubscriptionTargetOption,
    e: React.PointerEvent<HTMLDivElement>,
  ) => {
    if (e.button !== 0 || saving) return;
    const cardEl = e.currentTarget;
    const rect = cardEl.getBoundingClientRect();
    const startX = e.clientX;
    const startY = e.clientY;
    const offsetX = startX - rect.left;
    const offsetY = startY - rect.top;
    const label = choice.Builtin ? t(choice.Label) : choice.Label;
    const kind = t(choice.Kind);

    let active = false;
    let lastY = startY;
    let direction: DragDirection = "none";
    let currentTargetZone: "active" | "inactive" = zone;
    let currentTargetIdx = idx;

    const measureZoneTarget = (clientY: number, dir: DragDirection): { zone: "active" | "inactive"; index: number } => {
      const activeZoneRect = activeZoneRef.current?.getBoundingClientRect();
      const inactiveZoneRect = inactiveZoneRef.current?.getBoundingClientRect();
      let targetZone: "active" | "inactive" = currentTargetZone;
      if (activeZoneRect && inactiveZoneRect) {
        const boundaryY = (activeZoneRect.bottom + inactiveZoneRect.top) / 2;
        targetZone = clientY <= boundaryY ? "active" : "inactive";
      }
      const listEl = targetZone === "active" ? activeListRef.current : inactiveListRef.current;
      const itemEls = listEl ? Array.from(listEl.querySelectorAll<HTMLElement>("[data-group-drag-item]")) : [];
      const rects = itemEls.map((el) => {
        const r = el.getBoundingClientRect();
        return { top: r.top, height: r.height };
      });
      return { zone: targetZone, index: computeDropIndex(rects, clientY, dir) };
    };

    const cleanup = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onCancel);
      window.removeEventListener("keydown", onKeyDown, true);
      document.body.classList.remove("is-pointer-dragging");
      setDragState(null);
    };

    const onMove = (ev: PointerEvent) => {
      if (!active) {
        if (Math.hypot(ev.clientX - startX, ev.clientY - startY) < 4) return;
        active = true;
        document.body.classList.add("is-pointer-dragging");
      }
      ev.preventDefault();
      const dy = ev.clientY - lastY;
      if (Math.abs(dy) >= 1) {
        direction = dy > 0 ? "down" : "up";
        lastY = ev.clientY;
      }
      const next = measureZoneTarget(ev.clientY, direction);
      currentTargetZone = next.zone;
      currentTargetIdx = next.index;
      setDragState({
        value: choice.Value,
        sourceZone: zone,
        sourceIdx: idx,
        label,
        kind,
        x: ev.clientX - offsetX,
        y: ev.clientY - offsetY,
        offsetX,
        offsetY,
        width: rect.width,
        targetZone: currentTargetZone,
        targetIdx: currentTargetIdx,
      });
    };

    const onUp = () => {
      const wasActive = active;
      const finalZone = currentTargetZone;
      const finalIdx = currentTargetIdx;
      cleanup();
      if (wasActive) {
        commitMove(zone, idx, finalZone, finalIdx);
      }
    };

    const onCancel = () => {
      cleanup();
    };

    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && active) {
        ev.preventDefault();
        ev.stopPropagation();
        cleanup();
      }
    };

    window.addEventListener("pointermove", onMove, { passive: false });
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onCancel);
    window.addEventListener("keydown", onKeyDown, true);
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
      await onSaved();
      onClose();
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

  const visibleDropIndex = (zone: "active" | "inactive") => {
    if (!dragState || dragState.targetZone !== zone) return -1;
    if (dragState.sourceZone === zone && isNoOpSameListDrop(dragState.sourceIdx, dragState.targetIdx)) {
      return -1;
    }
    return dragState.targetIdx;
  };

  const activeDropIdx = visibleDropIndex("active");
  const inactiveDropIdx = visibleDropIndex("inactive");

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
                ref={activeZoneRef}
                className={`subscription-member-zone subscription-member-zone--active ${dragState?.targetZone === "active" ? "is-drop-target" : ""}`}
              >
                <div className="subscription-member-zone__header">
                  <strong>{t("Active options")}</strong>
                  <span className="panel__count">{activeChoices.length}</span>
                </div>
                <div ref={activeListRef} className="subscription-member-list">
                  {activeChoices.length === 0 ? (
                    <div className="subscription-member-zone__empty">{t("Drag options here to enable")}</div>
                  ) : (
                    activeChoices.map((choice, idx) => {
                      if (!matchesQuery(choice)) return null;
                      const label = choice.Builtin ? t(choice.Label) : choice.Label;
                      const kind = t(choice.Kind);
                      const isSource = dragState?.value === choice.Value;
                      const dropBefore = activeDropIdx === idx;
                      const dropAfter = idx === activeChoices.length - 1 && activeDropIdx === activeChoices.length;
                      return (
                        <div
                          key={choice.Value}
                          data-group-drag-item=""
                          tabIndex={0}
                          className={[
                            "subscription-member",
                            "subscription-member--draggable",
                            "is-selected",
                            isSource ? "is-dragging" : "",
                            dropBefore ? "is-drop-before" : "",
                            dropAfter ? "is-drop-after" : "",
                          ]
                            .filter(Boolean)
                            .join(" ")}
                          onPointerDown={(e) => handlePointerDown("active", idx, choice, e)}
                          onKeyDown={(e) => handleCardKeyDown("active", idx, e)}
                        >
                          {gripIcon}
                          <span className="subscription-member__order">{idx + 1}</span>
                          <div className="subscription-member__copy">
                            <span>{label}</span>
                            <small>{kind}</small>
                          </div>
                          {idx === 0 && <span className="subscription-member__default">{t("Default")}</span>}
                        </div>
                      );
                    })
                  )}
                </div>
              </div>

              <div
                ref={inactiveZoneRef}
                className={`subscription-member-zone subscription-member-zone--inactive ${dragState?.targetZone === "inactive" ? "is-drop-target" : ""}`}
              >
                <div className="subscription-member-zone__header">
                  <strong>{t("Inactive options")}</strong>
                  <span className="panel__count">{inactiveChoices.length}</span>
                </div>
                <div ref={inactiveListRef} className="subscription-member-list">
                  {inactiveChoices.length === 0 ? (
                    <div className="subscription-member-zone__empty">{t("Drag options here to disable")}</div>
                  ) : (
                    inactiveChoices.map((choice, idx) => {
                      if (!matchesQuery(choice)) return null;
                      const label = choice.Builtin ? t(choice.Label) : choice.Label;
                      const kind = t(choice.Kind);
                      const isSource = dragState?.value === choice.Value;
                      const dropBefore = inactiveDropIdx === idx;
                      const dropAfter = idx === inactiveChoices.length - 1 && inactiveDropIdx === inactiveChoices.length;
                      return (
                        <div
                          key={choice.Value}
                          data-group-drag-item=""
                          tabIndex={0}
                          className={[
                            "subscription-member",
                            "subscription-member--draggable",
                            "is-inactive",
                            isSource ? "is-dragging" : "",
                            dropBefore ? "is-drop-before" : "",
                            dropAfter ? "is-drop-after" : "",
                          ]
                            .filter(Boolean)
                            .join(" ")}
                          onPointerDown={(e) => handlePointerDown("inactive", idx, choice, e)}
                          onKeyDown={(e) => handleCardKeyDown("inactive", idx, e)}
                        >
                          {gripIcon}
                          <div className="subscription-member__copy">
                            <span>{label}</span>
                            <small>{kind}</small>
                          </div>
                        </div>
                      );
                    })
                  )}
                </div>
              </div>
            </div>
          </fieldset>
        </div>

        {dragState && (
          <div
            className={`subscription-member subscription-member--floating ${dragState.targetZone === "active" ? "is-selected" : "is-inactive"}`}
            style={{
              left: dragState.x,
              top: dragState.y,
              width: dragState.width,
            }}
            aria-hidden="true"
          >
            {gripIcon}
            <div className="subscription-member__copy">
              <span>{dragState.label}</span>
              <small>{dragState.kind}</small>
            </div>
          </div>
        )}

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
      const supportsNoResolve = match === "ip_cidr" || match === "geoip" || match === "ip_is_private";
      const fields: Record<string, string> = {
        match,
        values: match === "ip_is_private" ? "private" : values,
        action,
        no_resolve: supportsNoResolve && noResolve ? "yes" : "no",
      };
      if (action === "new_group") {
        fields.new_group_name = newGroupName.trim();
      }
      await submitMutation(url, fields);
      setDirty(false);
      await onSaved();
      onClose();
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
      await onSaved();
      onClose();
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
    { value: "ip_is_private", label: t("Private / LAN") },
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

  const supportsNoResolve = match === "ip_cidr" || match === "geoip" || match === "ip_is_private";

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
                if (nextMatch === "ip_is_private") {
                  setValues("private");
                  if (isNew) {
                    setNoResolve(true);
                    if (action === "proxy") setAction("direct");
                  }
                } else if (match === "ip_is_private") {
                  setValues("");
                }
              }}
              options={matchOptions}
            />
          </label>

          {match === "ip_is_private" ? (
            <p className="form-help">
              {t("Matches private and local network IP addresses (RFC 1918, loopback, link-local, and IPv6 ULA).")}
            </p>
          ) : !kind ? (
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
  const [defaultAction, setDefaultAction] = useState("proxy");
  const [reorderStatus, setReorderStatus] = useState("");
  const [reorderError, setReorderError] = useState(false);
  const [ruleDrag, setRuleDrag] = useState<{
    id: string;
    sourceIdx: number;
    targetIdx: number;
    matchLabel: string;
    summary: string;
    noResolve: boolean;
    policyLabel: string;
    toneClass: string;
    x: number;
    y: number;
    width: number;
  } | null>(null);
  const ruleListRef = useRef<HTMLOListElement>(null);
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
  const [finalModalOpen, setFinalModalOpen] = useState(false);
  const [finalDraft, setFinalDraft] = useState("proxy");
  const [finalError, setFinalError] = useState("");

  useEffect(() => {
    if (!policy) return;
    setOrderedRules(policy.Rules || []);
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

  const handleRulePointerDown = (
    rule: SubscriptionRuleView,
    index: number,
    policyLabel: string,
    toneClass: string,
    e: React.PointerEvent<HTMLLIElement>,
  ) => {
    if (e.button !== 0 || Boolean(ruleSearch.trim()) || busyKey === "reorder") return;
    const target = e.target as HTMLElement | null;
    if (target?.closest("button:not([data-rule-drag-handle]), a, input")) return;

    const rowEl = e.currentTarget;
    const rect = rowEl.getBoundingClientRect();
    const startX = e.clientX;
    const startY = e.clientY;
    const offsetX = startX - rect.left;
    const offsetY = startY - rect.top;

    let active = false;
    let lastY = startY;
    let direction: DragDirection = "none";
    let currentTargetIdx = index;
    const originRules = orderedRules;

    const measureTargetIdx = (clientY: number, dir: DragDirection): number => {
      const listEl = ruleListRef.current;
      if (!listEl) return index;
      const itemEls = Array.from(listEl.querySelectorAll<HTMLElement>("[data-rule-drag-item]"));
      const rects = itemEls.map((el) => {
        const r = el.getBoundingClientRect();
        return { top: r.top, height: r.height };
      });
      return computeDropIndex(rects, clientY, dir);
    };

    const cleanup = () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerup", onUp);
      window.removeEventListener("pointercancel", onCancel);
      window.removeEventListener("keydown", onKeyDown, true);
      document.body.classList.remove("is-pointer-dragging");
      setRuleDrag(null);
    };

    const onMove = (ev: PointerEvent) => {
      if (!active) {
        if (Math.hypot(ev.clientX - startX, ev.clientY - startY) < 4) return;
        active = true;
        document.body.classList.add("is-pointer-dragging");
      }
      ev.preventDefault();
      // Gently scroll viewport if dragging near the top or bottom edge.
      if (ev.clientY < 72) {
        window.scrollBy(0, -10);
      } else if (ev.clientY > window.innerHeight - 72) {
        window.scrollBy(0, 10);
      }
      const dy = ev.clientY - lastY;
      if (Math.abs(dy) >= 1) {
        direction = dy > 0 ? "down" : "up";
        lastY = ev.clientY;
      }
      currentTargetIdx = measureTargetIdx(ev.clientY, direction);
      setRuleDrag({
        id: rule.ID,
        sourceIdx: index,
        targetIdx: currentTargetIdx,
        matchLabel: rule.MatchLabel,
        summary: rule.Summary,
        noResolve: rule.NoResolve,
        policyLabel,
        toneClass,
        x: ev.clientX - offsetX,
        y: ev.clientY - offsetY,
        width: rect.width,
      });
    };

    const onUp = () => {
      const wasActive = active;
      const finalTargetIdx = currentTargetIdx;
      cleanup();
      if (!wasActive) return;
      const res = reorderList(originRules, index, finalTargetIdx);
      if (res.changed) {
        void persistRuleOrder(res.list, res.finalIndex, originRules);
      }
    };

    const onCancel = () => {
      cleanup();
    };

    const onKeyDown = (ev: KeyboardEvent) => {
      if (ev.key === "Escape" && active) {
        ev.preventDefault();
        ev.stopPropagation();
        cleanup();
      }
    };

    window.addEventListener("pointermove", onMove, { passive: false });
    window.addEventListener("pointerup", onUp);
    window.addEventListener("pointercancel", onCancel);
    window.addEventListener("keydown", onKeyDown, true);
  };

  const saveDefaultAction = async (e: React.FormEvent) => {
    e.preventDefault();
    if (busyKey) return;
    setBusyKey("default");
    setFinalError("");
    try {
      await submitMutation("/subscriptions/default", { action: finalDraft });
      await reload();
      setFinalModalOpen(false);
    } catch (err) {
      setFinalError(err instanceof ApiError ? err.message : t("Could not save final policy."));
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
      await reload();
      setDeleteGroup(null);
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
              {orderedRules.length > 0 && (
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
              )}

              <ol ref={ruleListRef} className="subscription-rule-list" aria-busy={busyKey === "reorder"}>
                {orderedRules.map((rule, index) => {
                  const targetOpts = mapTargetOptions(rule.Targets);
                  const selectedLabel =
                    targetOpts.find((o) => o.value === rule.Action)?.label ||
                    (rule.ActionLabel ? t(rule.ActionLabel) : rule.Action);
                  const actionToneClass =
                    rule.Action === "proxy"
                      ? "subscription-action--proxy"
                      : rule.Action === "direct"
                        ? "subscription-action--direct"
                        : rule.Action === "reject"
                          ? "subscription-action--reject"
                          : "subscription-action--group";
                  const matchesSearch =
                    !searchLower ||
                    `${rule.MatchLabel} ${rule.Summary} ${selectedLabel}`.toLocaleLowerCase().includes(searchLower);
                  if (!matchesSearch) return null;

                  const visibleRuleDropIdx =
                    ruleDrag && !isNoOpSameListDrop(ruleDrag.sourceIdx, ruleDrag.targetIdx)
                      ? ruleDrag.targetIdx
                      : -1;
                  const dropBefore = visibleRuleDropIdx === index;
                  const dropAfter = index === orderedRules.length - 1 && visibleRuleDropIdx === orderedRules.length;

                  return (
                    <li
                      key={rule.ID}
                      data-rule-drag-item=""
                      className={[
                        ruleDrag?.id === rule.ID ? "is-dragging" : "",
                        dropBefore ? "is-drop-before" : "",
                        dropAfter ? "is-drop-after" : "",
                      ]
                        .filter(Boolean)
                        .join(" ")}
                      onPointerDown={(e) => handleRulePointerDown(rule, index, selectedLabel, actionToneClass, e)}
                    >
                      <button
                        type="button"
                        data-rule-drag-handle=""
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
                        <strong>{t(rule.MatchLabel)}</strong>
                        <small>
                          {rule.Match === "ip_is_private" ? t(rule.Summary) : rule.Summary}
                          {rule.NoResolve && (
                            <>
                              {" · "}
                              <b>{t("No Resolve")}</b>
                            </>
                          )}
                        </small>
                      </div>
                      <span className={`subscription-action ${actionToneClass}`} title={selectedLabel}>
                        {selectedLabel}
                      </span>
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

                {(() => {
                  const defaultOpts = mapTargetOptions(policy.DefaultTargets);
                  const finalLabel =
                    defaultOpts.find((o) => o.value === defaultAction)?.label || defaultAction;
                  const finalToneClass =
                    defaultAction === "proxy"
                      ? "subscription-action--proxy"
                      : defaultAction === "direct"
                        ? "subscription-action--direct"
                        : defaultAction === "reject"
                          ? "subscription-action--reject"
                          : "subscription-action--group";
                  const finalMatchesSearch =
                    !searchLower ||
                    `FINAL ${t("All unmatched traffic")} ${finalLabel}`.toLocaleLowerCase().includes(searchLower);
                  if (!finalMatchesSearch) return null;
                  return (
                    <li className="subscription-rule--final">
                      <span className="subscription-rule__handle subscription-rule__handle--static" aria-hidden="true">
                        <svg viewBox="0 0 20 20">
                          <path
                            d="M10 4v10m0 0-3.5-3.5M10 14l3.5-3.5M5 16.5h10"
                            fill="none"
                            stroke="currentColor"
                            strokeWidth="1.6"
                            strokeLinecap="round"
                            strokeLinejoin="round"
                          />
                        </svg>
                      </span>
                      <span className="subscription-rule__order subscription-rule__order--final" aria-hidden="true">
                        *
                      </span>
                      <div className="subscription-rule__copy">
                        <strong>FINAL</strong>
                        <small>{t("All unmatched traffic")}</small>
                      </div>
                      <span className={`subscription-action ${finalToneClass}`} title={finalLabel}>
                        {finalLabel}
                      </span>
                      <div className="subscription-rule__actions">
                        <button
                          type="button"
                          className="button button--secondary button--small"
                          onClick={() => {
                            setFinalDraft(defaultAction);
                            setFinalError("");
                            setFinalModalOpen(true);
                          }}
                        >
                          {t("Edit")}
                        </button>
                      </div>
                    </li>
                  );
                })()}
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

              {ruleDrag && (
                <div
                  className="subscription-rule__drag-preview"
                  style={{
                    left: ruleDrag.x,
                    top: ruleDrag.y,
                    width: ruleDrag.width,
                  }}
                  aria-hidden="true"
                >
                  <span className="subscription-rule__handle">
                    <svg viewBox="0 0 20 20">
                      <circle cx="7" cy="5" r="1.2" />
                      <circle cx="13" cy="5" r="1.2" />
                      <circle cx="7" cy="10" r="1.2" />
                      <circle cx="13" cy="10" r="1.2" />
                      <circle cx="7" cy="15" r="1.2" />
                      <circle cx="13" cy="15" r="1.2" />
                    </svg>
                  </span>
                  <span className="subscription-rule__order">{ruleDrag.sourceIdx + 1}</span>
                  <div className="subscription-rule__copy">
                    <strong>{ruleDrag.matchLabel}</strong>
                    <small>
                      {ruleDrag.summary}
                      {ruleDrag.noResolve && (
                        <>
                          {" · "}
                          <b>{t("No Resolve")}</b>
                        </>
                      )}
                    </small>
                  </div>
                  <span className={`subscription-action ${ruleDrag.toneClass}`}>{ruleDrag.policyLabel}</span>
                  <div className="subscription-rule__actions">
                    <span className="button button--secondary button--small">{t("Edit")}</span>
                  </div>
                </div>
              )}
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
              open={finalModalOpen}
              onClose={() => setFinalModalOpen(false)}
              eyebrow={t("Fallback rule")}
              title={t("Edit FINAL policy")}
              size="compact"
            >
              <form onSubmit={(e) => void saveDefaultAction(e)} noValidate>
                <div className="modal__body stack">
                  {finalError && (
                    <div className="notice notice--error" role="alert">
                      {finalError}
                    </div>
                  )}
                  <p className="form-help">
                    {t("Applies to all traffic that does not match any rule above. This rule always stays last.")}
                  </p>
                  <label className="field">
                    <span>{t("Route")}</span>
                    <SelectBox
                      value={finalDraft}
                      onChange={setFinalDraft}
                      options={mapTargetOptions(policy.DefaultTargets)}
                    />
                  </label>
                </div>
                <footer className="modal__footer">
                  <button
                    type="button"
                    className="button button--secondary"
                    onClick={() => setFinalModalOpen(false)}
                  >
                    {t("Cancel")}
                  </button>
                  <button type="submit" className="button button--primary" disabled={busyKey === "default"}>
                    {busyKey === "default" ? t("Saving…") : t("Save")}
                  </button>
                </footer>
              </form>
            </Modal>

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
