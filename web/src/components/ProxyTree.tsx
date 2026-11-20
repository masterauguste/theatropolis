import React, { useState } from "react";
import type { LinkLatencyView, ProxyTreeBranchView, ProxyTreeHopView, ProxyTreeRouteView } from "../api/types";
import { useApp } from "../context/AppContext";

interface ProxyTreeProps {
  hop: ProxyTreeHopView;
  latencies: Record<string, LinkLatencyView>;
  locked: boolean;
  onOpenEntrance: () => void;
  onOpenInspector: (inspectorId: string) => void;
  onReorderHopRules: (hopId: string, allRuleIds: string, visibleRuleIds: string[]) => Promise<void>;
}

const LatencyBadge: React.FC<{ linkId: string; initial: LinkLatencyView; live?: LinkLatencyView }> = ({
  initial,
  live,
}) => {
  const { t } = useApp();
  const sample = live || initial;
  const status = sample?.status || "pending";
  const label =
    status === "unreachable" ? t("Unavailable") : status === "stale" ? t("Stale") : sample?.label || "—";
  return (
    <span className={`link-latency link-latency--${status}`}>
      <span aria-hidden="true" />
      <b>{label}</b>
    </span>
  );
};

const TerminalOutcome: React.FC<{ route: ProxyTreeRouteView; onOpenInspector: (id: string) => void }> = ({
  route,
  onOpenInspector,
}) => {
  const { t } = useApp();
  return (
    <div className="proxy-map__outcome">
      <div className={`proxy-map__route-label ${route.Uncertain ? "proxy-map__route-label--runtime" : ""}`}>
        <span className="proxy-map__condition">
          <b>{route.Label}</b>
          {(route.Match || route.Values) && (
            <span>
              {route.Match}
              {route.Values ? ` · ${route.Values}` : ""}
            </span>
          )}
        </span>
        {route.Uncertain && (
          <span
            className="proxy-map__runtime"
            title={t("Reachability depends on runtime DNS or Rule Set data")}
            aria-label={t("Runtime-dependent path")}
          >
            ?
          </span>
        )}
      </div>
      <button
        type="button"
        className={`proxy-map__node proxy-map__node--terminal proxy-map__node--${route.TargetKind}`}
        onClick={() => onOpenInspector(route.InspectorID)}
        aria-label={`${route.TargetLabel} · ${t("Exit")}`}
      >
        <span className="proxy-map__node-mark" aria-hidden="true">
          {route.TargetKind === "direct" ? (
            <svg viewBox="0 0 20 20">
              <path d="M6 14 14 6M8 6h6v6" />
            </svg>
          ) : (
            <svg viewBox="0 0 20 20">
              <circle cx="10" cy="10" r="6.5" />
              <path d="m5.5 5.5 9 9" />
            </svg>
          )}
        </span>
        <span className="proxy-map__node-copy">
          <strong>{route.TargetLabel}</strong>
          <small>{t("Exit")}</small>
        </span>
      </button>
    </div>
  );
};

export const ProxyTree: React.FC<ProxyTreeProps> = ({
  hop,
  latencies,
  locked,
  onOpenEntrance,
  onOpenInspector,
  onReorderHopRules,
}) => {
  const { t } = useApp();
  const branches = hop.Branches || [];
  const conditional = branches.filter((b) => !b.Fallback);
  const fallbacks = branches.filter((b) => b.Fallback);
  const [dragRuleId, setDragRuleId] = useState<string | null>(null);
  const [dropTargetRuleId, setDropTargetRuleId] = useState<string | null>(null);

  const handleDropOnBranch = (targetRuleId: string) => {
    if (!dragRuleId || dragRuleId === targetRuleId || locked) return;
    const ruleBranches = conditional.filter((b) => Boolean(b.RuleID));
    const currentOrder = ruleBranches.map((b) => b.RuleID);
    const fromIdx = currentOrder.indexOf(dragRuleId);
    const toIdx = currentOrder.indexOf(targetRuleId);
    if (fromIdx < 0 || toIdx < 0 || fromIdx === toIdx) return;
    const nextOrder = [...currentOrder];
    const [moved] = nextOrder.splice(fromIdx, 1);
    nextOrder.splice(toIdx, 0, moved);
    setDragRuleId(null);
    setDropTargetRuleId(null);
    void onReorderHopRules(hop.ID, hop.AllRuleIDs, nextOrder);
  };

  const renderBranch = (branch: ProxyTreeBranchView, idx: number) => {
    const inspectorId = branch.Block
      ? branch.InspectorID
      : branch.RuleID
        ? `rule-${branch.RuleID}`
        : `link-${branch.LinkID}`;
    const canDrag = Boolean(branch.RuleID) && !locked;

    return (
      <div
        key={`${branch.LinkID}-${branch.RuleID || idx}`}
        className={`proxy-map__outcome ${dropTargetRuleId === branch.RuleID ? "is-drop-target" : ""}`}
        draggable={canDrag}
        onDragStart={() => {
          if (canDrag) setDragRuleId(branch.RuleID);
        }}
        onDragOver={(e) => {
          if (!dragRuleId || !branch.RuleID || dragRuleId === branch.RuleID) return;
          e.preventDefault();
          setDropTargetRuleId(branch.RuleID);
        }}
        onDragLeave={() => {
          if (dropTargetRuleId === branch.RuleID) setDropTargetRuleId(null);
        }}
        onDrop={(e) => {
          if (!branch.RuleID) return;
          e.preventDefault();
          handleDropOnBranch(branch.RuleID);
        }}
        onDragEnd={() => {
          setDragRuleId(null);
          setDropTargetRuleId(null);
        }}
      >
        <button
          type="button"
          className={[
            "proxy-map__link",
            !branch.Block && branch.LinkID ? "proxy-map__link--with-latency" : "",
            !branch.Used ? "proxy-map__link--unused" : "",
            branch.Fallback ? "proxy-map__link--fallback" : "",
            branch.Uncertain ? "proxy-map__link--runtime" : "",
          ]
            .filter(Boolean)
            .join(" ")}
          onClick={() => onOpenInspector(inspectorId)}
        >
          {branch.RuleID && (
            <span className="proxy-map__drag-handle" aria-hidden="true" title={t("Drag to change priority")}>
              ⋮⋮
            </span>
          )}
          <span className="proxy-map__condition">
            <b>{branch.RuleLabel}</b>
            {branch.RuleValues && <span>{branch.RuleValues}</span>}
          </span>
          {branch.RuleID && (
            <span className="proxy-map__priority" aria-hidden="true">
              {branch.RulePosition}
            </span>
          )}
          {!branch.Block && branch.LinkID && (
            <LatencyBadge linkId={branch.LinkID} initial={branch.Latency} live={latencies[branch.LinkID]} />
          )}
          {branch.Uncertain && (
            <span
              className="proxy-map__runtime"
              title={t("Reachability depends on runtime DNS or Rule Set data")}
              aria-hidden="true"
            >
              ?
            </span>
          )}
        </button>

        {branch.Block ? (
          <button
            type="button"
            className="proxy-map__node proxy-map__node--terminal proxy-map__node--reject"
            onClick={() => onOpenInspector(branch.InspectorID)}
            aria-label={`${t("Reject")} · ${t("Rule")}`}
          >
            <span className="proxy-map__node-mark" aria-hidden="true">
              <svg viewBox="0 0 20 20">
                <circle cx="10" cy="10" r="6.5" />
                <path d="m5.5 5.5 9 9" />
              </svg>
            </span>
            <span className="proxy-map__node-copy">
              <strong>{t("Reject")}</strong>
              <small>{t("Rule")}</small>
            </span>
          </button>
        ) : branch.Child ? (
          <ProxyTree
            hop={branch.Child}
            latencies={latencies}
            locked={locked}
            onOpenEntrance={onOpenEntrance}
            onOpenInspector={onOpenInspector}
            onReorderHopRules={onReorderHopRules}
          />
        ) : null}
      </div>
    );
  };

  const showOutcomes = branches.length > 0 || (hop.ShowFallback && hop.Fallback?.TargetKind === "reject");

  return (
    <article className="proxy-map__subtree">
      <button
        type="button"
        className={`proxy-map__node proxy-map__node--hop ${hop.IsEntrance ? "proxy-map__node--entrance" : ""}`}
        onClick={() => (hop.IsEntrance ? onOpenEntrance() : onOpenInspector(`hop-${hop.ID}`))}
      >
        <span className="proxy-map__node-mark" aria-hidden="true">
          {hop.IsEntrance ? (
            <svg viewBox="0 0 20 20">
              <path d="M3.5 10h8.5m0 0-3-3m3 3-3 3" />
              <path d="M12.5 5.2a5.5 5.5 0 1 1 0 9.6" />
            </svg>
          ) : (
            <svg viewBox="0 0 20 20">
              <rect x="4" y="4.5" width="12" height="4.5" rx="1.4" />
              <rect x="4" y="11" width="12" height="4.5" rx="1.4" />
              <circle cx="7" cy="6.75" r=".75" fill="currentColor" stroke="none" />
              <circle cx="7" cy="13.25" r=".75" fill="currentColor" stroke="none" />
            </svg>
          )}
        </span>
        <span className="proxy-map__node-copy">
          <strong>{hop.Name}</strong>
          <small>{hop.IsEntrance ? t("Entrance") : t("Hop")}</small>
        </span>
        {hop.Deleted ? (
          <span className="proxy-map__node-status proxy-map__node-status--deleted">
            {hop.IsEntrance ? t("Entrance Server Deleted") : t("Relay Server Deleted")}
          </span>
        ) : hop.Offline ? (
          <span className={`proxy-map__node-status proxy-map__node-status--${hop.IsEntrance ? "entrance" : "relay"}`}>
            {hop.IsEntrance ? t("Entrance Offline") : t("Relay Offline")}
          </span>
        ) : null}
      </button>

      {showOutcomes && (
        <div className="proxy-map__outcomes">
          {conditional.map((b, i) => renderBranch(b, i))}
          {fallbacks.map((b, i) => renderBranch(b, i))}
          {hop.ShowFallback && (branches.length > 0 || hop.Fallback?.TargetKind === "reject") && (
            <TerminalOutcome route={hop.Fallback} onOpenInspector={onOpenInspector} />
          )}
        </div>
      )}
    </article>
  );
};
