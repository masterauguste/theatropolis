import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ApiError, fetchJSON } from "../api/client";
import type {
  LinkLatencyView,
  ListenerOptionView,
  ProxyBlockRuleView,
  ProxyDeploymentView,
  ProxyRuleView,
  ProxyTreeHopView,
  ProxyTreeLinkView,
  ProxyTreeRouteView,
} from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { LatencyChart } from "../components/LatencyChart";
import {
  endpointDraftToFields,
  endpointToDraft,
  ListenerEditor,
  type EndpointDraft,
} from "../components/ListenerEditor";
import { Modal } from "../components/Modal";
import { ProxyNodeUsersModal } from "../components/ProxyNodeUsersModal";
import { ProxyRuleMatchFields } from "../components/ProxyRuleMatchFields";
import { ProxyTree } from "../components/ProxyTree";
import { SelectBox } from "../components/SelectBox";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

interface TreeIndex {
  hops: Map<string, ProxyTreeHopView>;
  fallbacks: Map<string, ProxyTreeRouteView>;
  links: Map<string, ProxyTreeLinkView>;
  rules: Map<string, { rule: ProxyRuleView; link: ProxyTreeLinkView }>;
  blockRules: Map<string, { block: ProxyBlockRuleView; hop: ProxyTreeHopView }>;
}

function indexTree(root: ProxyTreeHopView | null | undefined): TreeIndex {
  const index: TreeIndex = {
    hops: new Map(),
    fallbacks: new Map(),
    links: new Map(),
    rules: new Map(),
    blockRules: new Map(),
  };
  const walk = (hop: ProxyTreeHopView | null | undefined) => {
    if (!hop) return;
    index.hops.set(hop.ID, hop);
    if (hop.Fallback?.InspectorID) {
      index.fallbacks.set(hop.Fallback.InspectorID, hop.Fallback);
    }
    for (const block of hop.BlockRules || []) {
      index.blockRules.set(`block-rule-${block.Rule.ID}`, { block, hop });
    }
    for (const link of hop.Children || []) {
      index.links.set(link.ID, link);
      for (const rule of link.Rules || []) {
        index.rules.set(`rule-${rule.ID}`, { rule, link });
      }
      walk(link.Child);
    }
  };
  walk(root);
  return index;
}

interface LinkProbePanelProps {
  probeUrl: string;
  agentId: string;
  endpoint: EndpointDraft;
}

const LinkProbePanel: React.FC<LinkProbePanelProps> = ({ probeUrl, agentId, endpoint }) => {
  const { t, session } = useApp();
  const [status, setStatus] = useState("idle");
  const [output, setOutput] = useState(t("Select a destination"));
  const abortRef = useRef<AbortController | null>(null);
  const family = endpoint.family || "auto";

  const runProbe = useCallback(async () => {
    if (!agentId) {
      setStatus("idle");
      setOutput(t("Select a destination"));
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    setStatus("loading");
    setOutput(t("Measuring…"));
    try {
      const body = new URLSearchParams({
        csrf_token: session.csrfToken || "",
        agent_id: agentId,
        family,
      });
      const res = await fetchJSON<{ status?: string; label?: string; detail?: string }>(probeUrl, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8" },
        body,
        signal: controller.signal,
      });
      setStatus(res.status || "idle");
      setOutput(`${t(res.label || "—")} · ${t(res.detail || "")}`);
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      setStatus("error");
      setOutput(err instanceof ApiError ? err.message : t("Path probe unavailable"));
    }
  }, [probeUrl, agentId, family, session.csrfToken, t]);

  useEffect(() => {
    const timer = window.setTimeout(() => void runProbe(), 250);
    return () => {
      window.clearTimeout(timer);
      abortRef.current?.abort();
    };
  }, [runProbe]);

  return (
    <section className="link-probe" data-status={status}>
      <div>
        <span>{t("Live TCP Probe")}</span>
        <output>{output}</output>
      </div>
      <button type="button" className="button button--secondary" onClick={() => void runProbe()}>
        {t("Probe Again")}
      </button>
    </section>
  );
};

export const ProxyNodeDetailPage: React.FC = () => {
  const { proxyId = "" } = useParams();
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { t, countLabel, submitMutation, setAppNotice } = useApp();

  const { data, loading, error, reload } = usePageData(`/proxy-nodes/${encodeURIComponent(proxyId)}/manage`);
  const node = data?.ProxyNode;
  const catalog: ListenerOptionView[] = data?.ListenerOptions || [];
  const treeIndex = useMemo(() => indexTree(node?.Tree), [node?.Tree]);

  const [deployment, setDeployment] = useState<ProxyDeploymentView | null>(null);
  const [latencies, setLatencies] = useState<Record<string, LinkLatencyView>>({});

  // Top-level dialogs
  const [renameOpen, setRenameOpen] = useState(false);
  const [renameValue, setRenameValue] = useState("");
  const [subAddrOpen, setSubAddrOpen] = useState(false);
  const [subAddrMode, setSubAddrMode] = useState("ipv4");
  const [deleteOpen, setDeleteOpen] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [usersOpen, setUsersOpen] = useState(false);
  const [entranceOpen, setEntranceOpen] = useState(false);

  // Inspector & child action dialogs
  const [inspectorId, setInspectorId] = useState<string | null>(null);
  const [addBranchDialog, setAddBranchDialog] = useState<{ hop: ProxyTreeHopView; defaultMatch: string } | null>(null);
  const [duplicateRuleLink, setDuplicateRuleLink] = useState<ProxyTreeLinkView | null>(null);
  const [editRelayLink, setEditRelayLink] = useState<ProxyTreeLinkView | null>(null);
  const [replaceDestLink, setReplaceDestLink] = useState<ProxyTreeLinkView | null>(null);
  const [monitorLink, setMonitorLink] = useState<ProxyTreeLinkView | null>(null);

  // Form states for active modal
  const [entranceEndpoint, setEntranceEndpoint] = useState<EndpointDraft>(() => endpointToDraft());
  const [entranceAgentId, setEntranceAgentId] = useState("");
  const [entranceFinal, setEntranceFinal] = useState("direct");

  const [hopMoveAgent, setHopMoveAgent] = useState("");
  const [hopFinalTarget, setHopFinalTarget] = useState("direct");
  const [linkMode, setLinkMode] = useState("conditional");
  const [linkChildFinal, setLinkChildFinal] = useState("direct");
  const [ruleMatch, setRuleMatch] = useState("domain");
  const [ruleValues, setRuleValues] = useState("");

  // Add branch form state
  const [branchMatch, setBranchMatch] = useState("protocol");
  const [branchValues, setBranchValues] = useState("");
  const [branchOutcome, setBranchOutcome] = useState<"relay" | "block">("relay");
  const [branchChildAgent, setBranchChildAgent] = useState("");
  const [branchEndpoint, setBranchEndpoint] = useState<EndpointDraft>(() => endpointToDraft());
  const [branchChildTerminal, setBranchChildTerminal] = useState("direct");

  // Edit/Replace relay state
  const [relayEndpoint, setRelayEndpoint] = useState<EndpointDraft>(() => endpointToDraft());
  const [replaceAgentId, setReplaceAgentId] = useState("");
  const [replaceTerminal, setReplaceTerminal] = useState("direct");

  const [listenerConflict, setListenerConflict] = useState("");
  const [modalError, setModalError] = useState("");
  const [busy, setBusy] = useState("");

  // Sync deployment & deep-link query params (?dialog=... / ?inspect=...)
  useEffect(() => {
    setDeployment(data?.ProxyDeployment || null);
  }, [data?.ProxyDeployment]);

  useEffect(() => {
    if (!node) return;
    const dialogParam = searchParams.get("dialog");
    const inspectParam = searchParams.get("inspect");
    if (dialogParam || inspectParam) {
      if (dialogParam === "proxy-node-users") setUsersOpen(true);
      else if (dialogParam === "proxy-entrance-dialog") openEntrance();
      if (inspectParam) openInspector(inspectParam);
      const next = new URLSearchParams(searchParams);
      next.delete("dialog");
      next.delete("inspect");
      setSearchParams(next, { replace: true });
    }
  }, [node]);

  // Deployment polling (fast while active, background watch while pending)
  useEffect(() => {
    const isActive = Boolean(deployment?.active);
    const isPending = Boolean(node?.OperationalStatus.TopologyPending || deployment?.status === "pending");
    if (!isActive && !isPending) return;
    const intervalMs = isActive ? 2000 : 10_000;
    const timer = window.setInterval(async () => {
      if (!isActive && document.hidden) return;
      try {
        const status = await fetchJSON<ProxyDeploymentView>("/proxy-nodes/deployment-status");
        setDeployment(status);
        if ((isActive && !status.active) || (!isActive && (status.active || status.status === "applied"))) {
          void reload();
        }
      } catch {
        // ignore transient errors
      }
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [deployment?.active, deployment?.status, node?.OperationalStatus.TopologyPending, reload]);

  // Live link latency polling
  useEffect(() => {
    if (!node) return;
    let active = true;
    const refreshLatencies = async () => {
      if (document.hidden) return;
      try {
        const res = await fetchJSON<{ links?: Record<string, LinkLatencyView> }>(
          `/proxy-nodes/${encodeURIComponent(node.ID)}/latencies`,
        );
        if (active && res.links) setLatencies(res.links);
      } catch {
        // advisory only
      }
    };
    const timer = window.setInterval(() => void refreshLatencies(), 20_000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [node?.ID]);

  const openEntrance = () => {
    if (!node?.Tree) return;
    setEntranceEndpoint(endpointToDraft(node.Entrance));
    setEntranceAgentId(node.Tree.AgentID);
    setEntranceFinal(node.Tree.Final || "direct");
    setModalError("");
    setListenerConflict("");
    setEntranceOpen(true);
  };

  const openInspector = (id: string) => {
    setModalError("");
    setInspectorId(id);
    if (id.startsWith("hop-")) {
      const hop = treeIndex.hops.get(id.slice(4));
      if (hop) {
        setHopMoveAgent(hop.AgentOptions?.find((a) => a.Selected && !a.Deleted)?.ID || "");
        setHopFinalTarget(hop.Final || "direct");
      }
    } else if (treeIndex.fallbacks.has(id)) {
      const fb = treeIndex.fallbacks.get(id)!;
      setHopFinalTarget(fb.TargetKind === "reject" ? "reject" : "direct");
    } else if (treeIndex.blockRules.has(id)) {
      const { block } = treeIndex.blockRules.get(id)!;
      setRuleMatch(block.Rule.Match || "domain");
      setRuleValues(block.Rule.FormValues || "");
    } else if (id.startsWith("link-")) {
      const link = treeIndex.links.get(id.slice(5));
      if (link) {
        setLinkMode(link.Fallback ? "fallback" : "conditional");
        setLinkChildFinal(link.Child?.Final || "direct");
      }
    } else if (treeIndex.rules.has(id)) {
      const { rule } = treeIndex.rules.get(id)!;
      setRuleMatch(rule.Match || "domain");
      setRuleValues(rule.FormValues || "");
    }
  };

  const openAddBranch = (hop: ProxyTreeHopView, defaultMatch: string) => {
    setInspectorId(null);
    setEntranceOpen(false);
    setBranchMatch(defaultMatch);
    setBranchValues("");
    setBranchOutcome("relay");
    setBranchChildAgent("");
    setBranchEndpoint(endpointToDraft(hop.NewLinkEndpoint));
    setBranchChildTerminal("direct");
    setModalError("");
    setListenerConflict("");
    setAddBranchDialog({ hop, defaultMatch });
  };

  const openEditRelay = (link: ProxyTreeLinkView) => {
    setInspectorId(null);
    setRelayEndpoint(endpointToDraft(link.Endpoint));
    setModalError("");
    setListenerConflict("");
    setEditRelayLink(link);
  };

  const openReplaceDest = (link: ProxyTreeLinkView) => {
    setInspectorId(null);
    setRelayEndpoint(endpointToDraft(link.Endpoint));
    setReplaceAgentId(link.DestinationAgentOptions?.find((a) => a.Selected && !a.Deleted)?.ID || "");
    setReplaceTerminal("direct");
    setModalError("");
    setListenerConflict("");
    setReplaceDestLink(link);
  };

  const openDuplicateRule = (link: ProxyTreeLinkView) => {
    setInspectorId(null);
    setRuleMatch(link.NewRule?.Match || "domain");
    setRuleValues(link.NewRule?.FormValues || "");
    setModalError("");
    setDuplicateRuleLink(link);
  };

  const runMutation = async (
    key: string,
    url: string,
    fields: Record<string, string>,
    options?: { closeAll?: boolean; followRedirect?: boolean },
  ) => {
    if (busy) return;
    setBusy(key);
    setModalError("");
    try {
      const res = await submitMutation(url, fields);
      if (options?.followRedirect && res.redirect) {
        navigate(res.redirect);
        return;
      }
      if (options?.closeAll !== false) {
        setRenameOpen(false);
        setSubAddrOpen(false);
        setDeleteOpen(false);
        setEntranceOpen(false);
        setInspectorId(null);
        setAddBranchDialog(null);
        setDuplicateRuleLink(null);
        setEditRelayLink(null);
        setReplaceDestLink(null);
      }
      await reload();
    } catch (err) {
      setModalError(err instanceof ApiError ? err.message : t("Request failed."));
    } finally {
      setBusy("");
    }
  };

  const handleReorderHopRules = async (hopId: string, allRuleIdsRaw: string, visibleOrder: string[]) => {
    if (!node) return;
    const allIds = allRuleIdsRaw ? allRuleIdsRaw.split(",").filter(Boolean) : [];
    const visibleSet = new Set(visibleOrder);
    let cursor = 0;
    const merged = allIds.length > 0
      ? allIds.map((id) => (visibleSet.has(id) ? visibleOrder[cursor++] : id))
      : visibleOrder;
    try {
      await submitMutation(`/proxy-nodes/${encodeURIComponent(node.ID)}/hops/${encodeURIComponent(hopId)}/rules/reorder`, {
        rule_ids: merged.join(","),
      });
      await reload();
    } catch {
      setAppNotice(t("The new branch order could not be saved. The previous order was restored."));
    }
  };

  const locked = Boolean(deployment?.active);

  const inspectedHop = inspectorId?.startsWith("hop-") ? treeIndex.hops.get(inspectorId.slice(4)) || null : null;
  const inspectedFallback = inspectorId ? treeIndex.fallbacks.get(inspectorId) || null : null;
  const inspectedBlock = inspectorId ? treeIndex.blockRules.get(inspectorId) || null : null;
  const inspectedLink = inspectorId?.startsWith("link-") ? treeIndex.links.get(inspectorId.slice(5)) || null : null;
  const inspectedRule = inspectorId ? treeIndex.rules.get(inspectorId) || null : null;

  const selectedBranchDestAgent = addBranchDialog?.hop.DestinationAgentOptions?.find(
    (a) => a.ID === branchChildAgent,
  );
  const selectedReplaceDestAgent = replaceDestLink?.DestinationAgentOptions?.find(
    (a) => a.ID === replaceAgentId,
  );

  return (
    <AppLayout activeNav="proxy-nodes" width="wide">
      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        {node && (
          <>
            <nav className="breadcrumbs" aria-label={t("Breadcrumb")}>
              <Link to="/proxy-nodes">{t("Proxy Nodes")}</Link>
              <span aria-hidden="true">/</span>
              <span>{node.Name}</span>
            </nav>

            <header className="page-header proxy-node-page-header">
              <div className="proxy-node-page-header__identity">
                <p className="eyebrow">{t("Proxy Node")}</p>
                <div className="proxy-node-page-header__title">
                  <h1>{node.Name}</h1>
                  <button
                    type="button"
                    className="button button--secondary button--icon-only proxy-node-title-edit"
                    aria-label={t("Rename Proxy Node")}
                    disabled={locked}
                    onClick={() => {
                      setRenameValue(node.Name);
                      setModalError("");
                      setRenameOpen(true);
                    }}
                  >
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <path d="M4 20h4l11-11a2.8 2.8 0 0 0-4-4L4 16v4Z" />
                      <path d="m13.5 6.5 4 4" />
                    </svg>
                  </button>
                </div>
                <p className="page-header__description">
                  {countLabel(node.HopCount, "hop")} · {countLabel(node.LinkCount, "link")} ·{" "}
                  {countLabel(node.MemberCount, "user")}
                </p>
              </div>
              <div className="page-header__actions proxy-node-page-header__actions">
                <button
                  type="button"
                  className="button button--secondary"
                  onClick={() => {
                    setSubAddrMode(node.SubscriptionAddressMode || "ipv4");
                    setModalError("");
                    setSubAddrOpen(true);
                  }}
                >
                  <span>{t("Subscription Addresses")}</span>
                </button>
                <button type="button" className="button button--secondary" onClick={() => setUsersOpen(true)}>
                  <span>{t("Users")}</span>
                  <span className="button__count">{node.MemberCount}</span>
                </button>
                <button
                  type="button"
                  className="button button--danger"
                  disabled={locked}
                  onClick={() => {
                    setConfirmDelete(false);
                    setModalError("");
                    setDeleteOpen(true);
                  }}
                >
                  {t("Delete Proxy Node")}
                </button>
              </div>
            </header>

            {deployment &&
              !(deployment.status === "pending" && !node.OperationalStatus.TopologyPending) && (
                <section
                  className={`notice proxy-deployment ${
                    deployment.class === "attention"
                      ? "notice--error"
                      : deployment.class === "pending"
                        ? "notice--warning"
                        : "notice--success"
                  }`}
                >
                  <strong>
                    {deployment.status === "pending"
                      ? t("Topology Pending")
                      : `${t("Topology change")}: ${deployment.label}`}
                  </strong>
                  {deployment.status === "pending" ? (
                    <p>{t("Saved changes are not yet active. The relay map shows the saved topology.")}</p>
                  ) : deployment.error ? (
                    <p>{deployment.error}</p>
                  ) : null}
                </section>
              )}

            {(node.OperationalStatus.EntranceDeleted?.length ||
              node.OperationalStatus.RelayDeleted?.length ||
              node.OperationalStatus.EntranceOffline?.length ||
              node.OperationalStatus.RelayOffline?.length) ? (
              <section className="proxy-node-health" aria-label={t("Proxy Node status")}>
                {node.OperationalStatus.EntranceDeleted && node.OperationalStatus.EntranceDeleted.length > 0 && (
                  <div className="proxy-node-health__item">
                    <span className="status status--failed">
                      <span aria-hidden="true" />
                      {t("Entrance Server Deleted")}
                    </span>
                    <small>
                      {node.OperationalStatus.EntranceDeleted.map((a) => a.Name).join(" · ")} ·{" "}
                      {t("Choose another server to remove this stale reference. The old server cannot be cleaned remotely.")}
                    </small>
                  </div>
                )}
                {node.OperationalStatus.RelayDeleted && node.OperationalStatus.RelayDeleted.length > 0 && (
                  <div className="proxy-node-health__item">
                    <span className="status status--failed">
                      <span aria-hidden="true" />
                      {t("Relay Server Deleted")}
                    </span>
                    <small>
                      {node.OperationalStatus.RelayDeleted.map((a) => a.Name).join(" · ")} ·{" "}
                      {t("Choose another server or delete its branch to remove this stale reference. The old server cannot be cleaned remotely.")}
                    </small>
                  </div>
                )}
                {node.OperationalStatus.EntranceOffline && node.OperationalStatus.EntranceOffline.length > 0 && (
                  <div className="proxy-node-health__item">
                    <span className="status status--failed">
                      <span aria-hidden="true" />
                      {t("Entrance Offline")}
                    </span>
                    <small>{node.OperationalStatus.EntranceOffline.map((a) => a.Name).join(" · ")}</small>
                  </div>
                )}
                {node.OperationalStatus.RelayOffline && node.OperationalStatus.RelayOffline.length > 0 && (
                  <div className="proxy-node-health__item">
                    <span className="status status--pending">
                      <span aria-hidden="true" />
                      {t("Relay Offline")}
                    </span>
                    <small>{node.OperationalStatus.RelayOffline.map((a) => a.Name).join(" · ")}</small>
                  </div>
                )}
              </section>
            ) : null}

            <section className="panel proxy-tree-panel">
              <div className="panel__header proxy-tree-panel__header">
                <h2>{t("Relay map")}</h2>
                <span className="panel__count">{countLabel(node.TerminalCount, "exit")}</span>
              </div>
              <div className="proxy-map" aria-label={t("Left-to-right relay tree")}>
                <span className="proxy-map__pan-hint">
                  {t("Swipe to explore")} <span aria-hidden="true">→</span>
                </span>
                <div className="proxy-map__canvas">
                  {node.Tree && (
                    <ProxyTree
                      hop={node.Tree}
                      latencies={latencies}
                      locked={locked}
                      onOpenEntrance={openEntrance}
                      onOpenInspector={openInspector}
                      onReorderHopRules={handleReorderHopRules}
                    />
                  )}
                </div>
              </div>
            </section>

            {/* Rename Proxy Node */}
            <Modal open={renameOpen} onClose={() => setRenameOpen(false)} eyebrow={t("Proxy Node")} title={t("Rename Proxy Node")}>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void runMutation("rename", `/proxy-nodes/${encodeURIComponent(node.ID)}/rename`, {
                    name: renameValue.trim(),
                  });
                }}
                noValidate
              >
                <div className="modal__body stack">
                  {modalError && <div className="notice notice--error">{modalError}</div>}
                  <label className="field">
                    <span>{t("Name")}</span>
                    <input value={renameValue} onChange={(e) => setRenameValue(e.target.value)} required autoFocus />
                  </label>
                </div>
                <footer className="modal__footer">
                  <button type="button" className="button button--secondary" onClick={() => setRenameOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button type="submit" className="button button--primary" disabled={Boolean(busy)}>
                    {t("Rename")}
                  </button>
                </footer>
              </form>
            </Modal>

            {/* Subscription Addresses */}
            <Modal
              open={subAddrOpen}
              onClose={() => setSubAddrOpen(false)}
              eyebrow={t("Configuration Subscription")}
              title={t("Subscription Addresses")}
            >
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  void runMutation("sub-addr", `/proxy-nodes/${encodeURIComponent(node.ID)}/subscription-addresses`, {
                    mode: subAddrMode,
                  });
                }}
                noValidate
              >
                <div className="modal__body stack">
                  {modalError && <div className="notice notice--error">{modalError}</div>}
                  <label className="field">
                    <span>{t("Address Families")}</span>
                    <SelectBox
                      searchable={false}
                      value={subAddrMode}
                      onChange={setSubAddrMode}
                      options={[
                        { value: "dual", label: t("IPv4 and IPv6") },
                        { value: "ipv4", label: t("IPv4 Only") },
                        { value: "ipv6", label: t("IPv6 Only") },
                      ]}
                    />
                  </label>
                </div>
                <footer className="modal__footer">
                  <button type="button" className="button button--secondary" onClick={() => setSubAddrOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button type="submit" className="button button--primary" disabled={Boolean(busy)}>
                    {t("Save")}
                  </button>
                </footer>
              </form>
            </Modal>

            {/* Delete Proxy Node */}
            <Modal open={deleteOpen} onClose={() => setDeleteOpen(false)} eyebrow={t("Proxy Node")} title={t("Delete Proxy Node?")}>
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (!confirmDelete) return;
                  void runMutation(
                    "delete-node",
                    `/proxy-nodes/${encodeURIComponent(node.ID)}/delete`,
                    { confirm_delete: "yes" },
                    { followRedirect: true },
                  );
                }}
                noValidate
              >
                <div className="modal__body stack">
                  {modalError && <div className="notice notice--error">{modalError}</div>}
                  <p>{t("Revokes memberships and immediately removes this Node's listeners and Links from the fleet.")}</p>
                  <label className="danger-confirm">
                    <input
                      type="checkbox"
                      checked={confirmDelete}
                      onChange={(e) => setConfirmDelete(e.target.checked)}
                      required
                    />
                    <span>{t("Delete this Proxy Node and all of its Links.")}</span>
                  </label>
                </div>
                <footer className="modal__footer">
                  <button type="button" className="button button--secondary" onClick={() => setDeleteOpen(false)}>
                    {t("Cancel")}
                  </button>
                  <button type="submit" className="button button--danger" disabled={!confirmDelete || Boolean(busy)}>
                    {t("Delete Proxy Node")}
                  </button>
                </footer>
              </form>
            </Modal>

            {/* Entrance Modal */}
            <Modal
              open={entranceOpen && Boolean(node.Tree)}
              onClose={() => setEntranceOpen(false)}
              eyebrow={t("Entrance")}
              title={node.Tree?.Name || ""}
              className="resource-modal proxy-entrance-modal"
              footer={
                <button type="button" className="button button--secondary" onClick={() => setEntranceOpen(false)}>
                  {t("Close")}
                </button>
              }
            >
              {node.Tree && (
                <div className="modal__body stack proxy-entrance-editor">
                  {modalError && <div className="notice notice--error">{modalError}</div>}
                  <dl className="proxy-inspector__facts">
                    <div>
                      <dt>{t("Protocol")}</dt>
                      <dd>{node.Entrance.ProtocolLabel}</dd>
                    </div>
                    <div>
                      <dt>{t("Listener")}</dt>
                      <dd>
                        {node.Entrance.Listen}:{node.Entrance.ListenPort}
                      </dd>
                    </div>
                    <div>
                      <dt>{t("Default route")}</dt>
                      <dd>{node.EntranceFallback}</dd>
                    </div>
                  </dl>

                  <section className="proxy-entrance-editor__listener">
                    <header>
                      <h3>{t("Listener and protocol")}</h3>
                    </header>
                    <form
                      className="stack"
                      onSubmit={(e) => {
                        e.preventDefault();
                        if (listenerConflict) {
                          setModalError(listenerConflict);
                          return;
                        }
                        void runMutation(
                          "save-entrance",
                          `/proxy-nodes/${encodeURIComponent(node.ID)}/entrance`,
                          endpointDraftToFields(entranceEndpoint),
                        );
                      }}
                      noValidate
                    >
                      <ListenerEditor
                        value={entranceEndpoint}
                        onChange={setEntranceEndpoint}
                        agentId={node.Entrance.AgentID}
                        currentListenerId={node.Entrance.ListenerID}
                        allowReverse={false}
                        showFamilyAndMux={false}
                        catalog={catalog}
                        onConflictChange={setListenerConflict}
                      />
                      <button type="submit" className="button button--primary" disabled={locked || Boolean(busy)}>
                        {t("Save Entrance")}
                      </button>
                    </form>
                  </section>

                  <div className="proxy-inspector__editor-grid">
                    <section className="proxy-inspector__editor-card">
                      <header>
                        <h3>{t("Entrance server")}</h3>
                      </header>
                      <form
                        className="stack"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void runMutation(
                            "move-entrance",
                            `/proxy-nodes/${encodeURIComponent(node.ID)}/hops/${encodeURIComponent(node.Tree!.ID)}`,
                            { agent_id: entranceAgentId },
                          );
                        }}
                        noValidate
                      >
                        <label className="field">
                          <span>{t("Agent")}</span>
                          <SelectBox
                            value={entranceAgentId}
                            onChange={setEntranceAgentId}
                            options={(node.Tree.AgentOptions || []).map((a) => ({
                              value: a.Deleted ? "" : a.ID,
                              label: `${a.Name}${a.Deleted ? ` — ${t("deleted")}` : !a.Online ? ` — ${t("offline")}` : ""}`,
                              disabled: a.Deleted,
                            }))}
                          />
                        </label>
                        <button type="submit" className="button button--secondary" disabled={locked || Boolean(busy)}>
                          {t("Move Hop")}
                        </button>
                      </form>
                    </section>

                    <section className="proxy-inspector__editor-card">
                      <header>
                        <h3>{t("Default route")}</h3>
                      </header>
                      <form
                        className="stack"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void runMutation(
                            "entrance-final",
                            `/proxy-nodes/${encodeURIComponent(node.ID)}/hops/${encodeURIComponent(node.Tree!.ID)}/final`,
                            { return_to: "", target: entranceFinal },
                          );
                        }}
                        noValidate
                      >
                        <label className="field">
                          <span>{t("Unmatched Traffic")}</span>
                          <SelectBox
                            searchable={false}
                            value={entranceFinal}
                            onChange={setEntranceFinal}
                            options={[
                              { value: "direct", label: t("Direct") },
                              { value: "reject", label: t("Reject") },
                            ]}
                          />
                        </label>
                        <button type="submit" className="button button--secondary" disabled={locked || Boolean(busy)}>
                          {t("Save Exit")}
                        </button>
                      </form>
                    </section>

                    <section className="proxy-inspector__editor-card">
                      <header>
                        <h3>{t("Branch")}</h3>
                      </header>
                      <div className="proxy-inspector__editor-card-body">
                        <button
                          type="button"
                          className="button button--primary"
                          disabled={locked}
                          onClick={() => openAddBranch(node.Tree!, "protocol")}
                        >
                          {t("Create Branch")}
                        </button>
                      </div>
                    </section>
                  </div>
                </div>
              )}
            </Modal>

            {/* Shared Inspector Modal */}
            <Modal
              open={Boolean(inspectorId)}
              onClose={() => setInspectorId(null)}
              eyebrow={t("Relay map")}
              title={t("Details")}
              className="proxy-inspector"
              footer={
                <button type="button" className="button button--secondary" onClick={() => setInspectorId(null)}>
                  {t("Close")}
                </button>
              }
            >
              <div className="modal__body">
                {modalError && <div className="notice notice--error">{modalError}</div>}

                {/* Relay Hop view */}
                {inspectedHop && (
                  <section className="proxy-inspector__view">
                    <p className="eyebrow">{t("Relay Hop")}</p>
                    <h2>{inspectedHop.Name}</h2>
                    <dl className="proxy-inspector__facts">
                      <div>
                        <dt>{t("Inbound")}</dt>
                        <dd>{inspectedHop.IngressProtocol}</dd>
                      </div>
                      <div>
                        <dt>{t("Listener")}</dt>
                        <dd>{inspectedHop.IngressLabel}</dd>
                      </div>
                      <div>
                        <dt>{t("Downstream")}</dt>
                        <dd>{countLabel(inspectedHop.BranchCount, "link")}</dd>
                      </div>
                    </dl>
                    <div className="proxy-inspector__editor-grid">
                      <section className="proxy-inspector__editor-card">
                        <header>
                          <h3>{t("Agent")}</h3>
                        </header>
                        <form
                          className="stack"
                          onSubmit={(e) => {
                            e.preventDefault();
                            void runMutation(
                              "move-hop",
                              `/proxy-nodes/${encodeURIComponent(inspectedHop.ProxyID)}/hops/${encodeURIComponent(inspectedHop.ID)}`,
                              { agent_id: hopMoveAgent },
                            );
                          }}
                          noValidate
                        >
                          <label className="field">
                            <span>{t("Agent")}</span>
                            <SelectBox
                              value={hopMoveAgent}
                              onChange={setHopMoveAgent}
                              options={(inspectedHop.AgentOptions || []).map((a) => ({
                                value: a.Deleted ? "" : a.ID,
                                label: `${a.Name}${a.Deleted ? ` — ${t("deleted")}` : !a.Online ? ` — ${t("offline")}` : ""}`,
                                disabled: a.Deleted,
                              }))}
                            />
                          </label>
                          <button type="submit" className="button button--secondary" disabled={locked || Boolean(busy)}>
                            {t("Move Hop")}
                          </button>
                        </form>
                      </section>

                      <section className="proxy-inspector__editor-card">
                        <header>
                          <h3>{t("Terminal Exit")}</h3>
                        </header>
                        <form
                          className="stack"
                          onSubmit={(e) => {
                            e.preventDefault();
                            void runMutation(
                              "hop-final",
                              `/proxy-nodes/${encodeURIComponent(inspectedHop.ProxyID)}/hops/${encodeURIComponent(inspectedHop.ID)}/final`,
                              { return_to: "hop", target: hopFinalTarget },
                            );
                          }}
                          noValidate
                        >
                          <label className="field">
                            <span>{t("Unmatched Traffic")}</span>
                            <SelectBox
                              searchable={false}
                              value={hopFinalTarget}
                              onChange={setHopFinalTarget}
                              options={[
                                { value: "direct", label: t("Direct") },
                                { value: "reject", label: t("Reject") },
                              ]}
                            />
                          </label>
                          <button type="submit" className="button button--secondary" disabled={locked || Boolean(busy)}>
                            {t("Save Exit")}
                          </button>
                        </form>
                      </section>

                      <section className="proxy-inspector__editor-card">
                        <header>
                          <h3>{t("Branch")}</h3>
                        </header>
                        <div className="proxy-inspector__editor-card-body">
                          <button
                            type="button"
                            className="button button--primary"
                            disabled={locked}
                            onClick={() => openAddBranch(inspectedHop, "protocol")}
                          >
                            {t("Create Branch")}
                          </button>
                        </div>
                      </section>
                    </div>
                  </section>
                )}

                {/* Fallback terminal view */}
                {inspectedFallback && (
                  <section className="proxy-inspector__view">
                    <p className="eyebrow">{t("Fallback")}</p>
                    <h2>{inspectedFallback.TargetLabel}</h2>
                    <dl className="proxy-inspector__facts">
                      <div>
                        <dt>{t("Agent")}</dt>
                        <dd>{inspectedFallback.TargetDetail}</dd>
                      </div>
                    </dl>
                    <div className="proxy-inspector__section">
                      <h3>{t("Exit")}</h3>
                      <form
                        className="inline-form"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void runMutation(
                            "fb-final",
                            `/proxy-nodes/${encodeURIComponent(inspectedFallback.ProxyID)}/hops/${encodeURIComponent(inspectedFallback.HopID)}/final`,
                            { return_to: "fallback", target: hopFinalTarget },
                          );
                        }}
                        noValidate
                      >
                        <SelectBox
                          searchable={false}
                          value={hopFinalTarget}
                          onChange={setHopFinalTarget}
                          options={[
                            { value: "direct", label: t("Direct") },
                            { value: "reject", label: t("Reject") },
                          ]}
                        />
                        <button type="submit" className="button button--secondary" disabled={locked || Boolean(busy)}>
                          {t("Save")}
                        </button>
                      </form>
                    </div>
                    <div className="proxy-inspector__section">
                      <h3>{t("Relay")}</h3>
                      <button
                        type="button"
                        className="button button--primary"
                        disabled={locked}
                        onClick={() => {
                          const hop = treeIndex.hops.get(inspectedFallback.HopID);
                          if (hop) openAddBranch(hop, "none");
                        }}
                      >
                        {t("Route ALL")}
                      </button>
                    </div>
                  </section>
                )}

                {/* Block rule view */}
                {inspectedBlock && (
                  <section className="proxy-inspector__view">
                    <p className="eyebrow">
                      {t("Reject branch")} {inspectedBlock.block.Rule.Position}
                    </p>
                    <h2>{inspectedBlock.block.Rule.MatchLabel}</h2>
                    <dl className="proxy-inspector__facts">
                      <div>
                        <dt>{t("Action")}</dt>
                        <dd>{t("Reject")}</dd>
                      </div>
                      <div>
                        <dt>{t("Agent")}</dt>
                        <dd>{inspectedBlock.block.Name}</dd>
                      </div>
                    </dl>
                    <form
                      className="stack proxy-rule-editor"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void runMutation(
                          "save-block",
                          `/proxy-nodes/${encodeURIComponent(inspectedBlock.hop.ProxyID)}/block-rules/${encodeURIComponent(inspectedBlock.block.Rule.ID)}`,
                          { match: ruleMatch, values: ruleValues },
                        );
                      }}
                      noValidate
                    >
                      <ProxyRuleMatchFields
                        match={ruleMatch}
                        values={ruleValues}
                        onMatchChange={setRuleMatch}
                        onValuesChange={setRuleValues}
                        allowAllFallback={false}
                        includeLegacyRuleSet
                      />
                      <button type="submit" className="button button--primary" disabled={locked || Boolean(busy)}>
                        {t("Save Rule")}
                      </button>
                    </form>
                    <div className="proxy-inspector__actions">
                      <button
                        type="button"
                        className="button button--secondary button--icon-only"
                        disabled={!inspectedBlock.block.Rule.CanMoveUp || locked || Boolean(busy)}
                        aria-label={t("Move Rule up")}
                        onClick={() =>
                          void runMutation(
                            "move-block-up",
                            `/proxy-nodes/${encodeURIComponent(inspectedBlock.hop.ProxyID)}/block-rules/${encodeURIComponent(inspectedBlock.block.Rule.ID)}/move`,
                            { direction: "up" },
                          )
                        }
                      >
                        ↑
                      </button>
                      <button
                        type="button"
                        className="button button--secondary button--icon-only"
                        disabled={!inspectedBlock.block.Rule.CanMoveDown || locked || Boolean(busy)}
                        aria-label={t("Move Rule down")}
                        onClick={() =>
                          void runMutation(
                            "move-block-down",
                            `/proxy-nodes/${encodeURIComponent(inspectedBlock.hop.ProxyID)}/block-rules/${encodeURIComponent(inspectedBlock.block.Rule.ID)}/move`,
                            { direction: "down" },
                          )
                        }
                      >
                        ↓
                      </button>
                      <button
                        type="button"
                        className="button-link button-link--danger"
                        disabled={locked || Boolean(busy)}
                        onClick={() =>
                          void runMutation(
                            "delete-block",
                            `/proxy-nodes/${encodeURIComponent(inspectedBlock.hop.ProxyID)}/block-rules/${encodeURIComponent(inspectedBlock.block.Rule.ID)}/delete`,
                            {},
                          )
                        }
                      >
                        {t("Delete rule")}
                      </button>
                    </div>
                  </section>
                )}

                {/* Link view */}
                {inspectedLink && inspectedLink.Child && (
                  <section className="proxy-inspector__view">
                    <p className="eyebrow">{t("Relay Branch")}</p>
                    <h2>{inspectedLink.Child.Name}</h2>
                    <dl className="proxy-inspector__facts">
                      <div>
                        <dt>{t("Protocol")}</dt>
                        <dd>{inspectedLink.Protocol}</dd>
                      </div>
                      <div>
                        <dt>{t("Destination")}</dt>
                        <dd>{inspectedLink.Child.Name}</dd>
                      </div>
                      <div>
                        <dt>{t("Listener")}</dt>
                        <dd>{inspectedLink.Listener}</dd>
                      </div>
                      <div>
                        <dt>{t("Address family")}</dt>
                        <dd>{inspectedLink.Family}</dd>
                      </div>
                      <div>
                        <dt>{t("Fallback")}</dt>
                        <dd>{inspectedLink.Fallback ? t("Yes") : t("No")}</dd>
                      </div>
                    </dl>
                    <div className="proxy-inspector__section">
                      <h3>{t("Routing mode")}</h3>
                      <form
                        className="inline-form"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void runMutation("link-mode", `${inspectedLink.EditURL}/fallback`, { mode: linkMode });
                        }}
                        noValidate
                      >
                        <SelectBox
                          searchable={false}
                          value={linkMode}
                          onChange={setLinkMode}
                          options={[
                            { value: "conditional", label: t("Conditional") },
                            { value: "fallback", label: t("Fallback") },
                          ]}
                        />
                        <button type="submit" className="button button--secondary" disabled={locked || Boolean(busy)}>
                          {t("Save")}
                        </button>
                      </form>
                    </div>
                    <div className="proxy-inspector__section">
                      <h3>{t("Child exit")}</h3>
                      <form
                        className="inline-form"
                        onSubmit={(e) => {
                          e.preventDefault();
                          void runMutation(
                            "child-final",
                            `/proxy-nodes/${encodeURIComponent(inspectedLink.Child!.ProxyID)}/hops/${encodeURIComponent(inspectedLink.Child!.ID)}/final`,
                            { return_to: "", target: linkChildFinal },
                          );
                        }}
                        noValidate
                      >
                        <SelectBox
                          searchable={false}
                          value={linkChildFinal}
                          onChange={setLinkChildFinal}
                          options={[
                            { value: "direct", label: t("Direct") },
                            { value: "reject", label: t("Reject") },
                          ]}
                        />
                        <button type="submit" className="button button--secondary" disabled={locked || Boolean(busy)}>
                          {t("Save")}
                        </button>
                      </form>
                    </div>
                    {inspectedLink.Rules && inspectedLink.Rules.length > 0 && (
                      <div className="proxy-inspector__section">
                        <h3>{t("Routing Rule")}</h3>
                        <div className="proxy-rule-branch-list">
                          {inspectedLink.Rules.map((r) => (
                            <button
                              key={r.ID}
                              type="button"
                              className="button button--secondary"
                              onClick={() => openInspector(`rule-${r.ID}`)}
                            >
                              <span>{r.Position}</span>
                              <strong>{r.MatchLabel}</strong>
                              <small>{r.Values}</small>
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="proxy-inspector__actions">
                      {!inspectedLink.Fallback && (
                        <button
                          type="button"
                          className="button button--primary"
                          disabled={locked}
                          onClick={() => openDuplicateRule(inspectedLink)}
                        >
                          {inspectedLink.Rules?.length ? t("Duplicate Branch") : t("Add Rule")}
                        </button>
                      )}
                      <button
                        type="button"
                        className="button button--secondary"
                        onClick={() => {
                          setInspectorId(null);
                          setMonitorLink(inspectedLink);
                        }}
                      >
                        {t("Link Monitor")}
                      </button>
                      <button
                        type="button"
                        className="button button--secondary"
                        disabled={locked}
                        onClick={() => openEditRelay(inspectedLink)}
                      >
                        {t("Edit Relay")}
                      </button>
                      <button
                        type="button"
                        className="button button--secondary"
                        disabled={locked}
                        onClick={() => openReplaceDest(inspectedLink)}
                      >
                        {t("Replace Destination")}
                      </button>
                      <button
                        type="button"
                        className="button-link button-link--danger"
                        disabled={locked || Boolean(busy)}
                        onClick={() =>
                          void runMutation(
                            "delete-link",
                            `/proxy-nodes/${encodeURIComponent(inspectedLink.Child!.ProxyID)}/hops/${encodeURIComponent(inspectedLink.ParentHopID)}/links/delete`,
                            { link_id: inspectedLink.ID, confirm_delete: "yes" },
                          )
                        }
                      >
                        {t("Delete Branch")}
                      </button>
                    </div>
                  </section>
                )}

                {/* Rule view */}
                {inspectedRule && inspectedRule.link.Child && (
                  <section className="proxy-inspector__view">
                    <p className="eyebrow">
                      {t("Rule branch")} {inspectedRule.rule.Position}
                    </p>
                    <h2>{inspectedRule.rule.MatchLabel}</h2>
                    <dl className="proxy-inspector__facts">
                      <div>
                        <dt>{t("Routes to")}</dt>
                        <dd>{inspectedRule.link.Child.Name}</dd>
                      </div>
                      <div>
                        <dt>{t("Relay")}</dt>
                        <dd>
                          {inspectedRule.link.Protocol} · {inspectedRule.link.Listener}
                        </dd>
                      </div>
                    </dl>
                    <form
                      className="stack proxy-rule-editor"
                      onSubmit={(e) => {
                        e.preventDefault();
                        void runMutation(
                          "save-rule",
                          `${inspectedRule.link.EditURL}/rules/${encodeURIComponent(inspectedRule.rule.ID)}`,
                          { match: ruleMatch, values: ruleValues },
                        );
                      }}
                      noValidate
                    >
                      <ProxyRuleMatchFields
                        match={ruleMatch}
                        values={ruleValues}
                        onMatchChange={setRuleMatch}
                        onValuesChange={setRuleValues}
                        allowAllFallback={false}
                        includeLegacyRuleSet
                      />
                      <button type="submit" className="button button--primary" disabled={locked || Boolean(busy)}>
                        {t("Save Rule")}
                      </button>
                    </form>
                    <div className="proxy-inspector__actions">
                      <button
                        type="button"
                        className="button button--secondary button--icon-only"
                        disabled={!inspectedRule.rule.CanMoveUp || locked || Boolean(busy)}
                        aria-label={t("Move Rule up")}
                        onClick={() =>
                          void runMutation("move-rule-up", `${inspectedRule.link.EditURL}/rules/move`, {
                            rule_id: inspectedRule.rule.ID,
                            direction: "up",
                          })
                        }
                      >
                        ↑
                      </button>
                      <button
                        type="button"
                        className="button button--secondary button--icon-only"
                        disabled={!inspectedRule.rule.CanMoveDown || locked || Boolean(busy)}
                        aria-label={t("Move Rule down")}
                        onClick={() =>
                          void runMutation("move-rule-down", `${inspectedRule.link.EditURL}/rules/move`, {
                            rule_id: inspectedRule.rule.ID,
                            direction: "down",
                          })
                        }
                      >
                        ↓
                      </button>
                      <button
                        type="button"
                        className="button button--secondary"
                        onClick={() => {
                          setInspectorId(null);
                          setMonitorLink(inspectedRule.link);
                        }}
                      >
                        {t("Link Monitor")}
                      </button>
                      <button
                        type="button"
                        className="button button--secondary"
                        disabled={locked}
                        onClick={() => openEditRelay(inspectedRule.link)}
                      >
                        {t("Edit Relay")}
                      </button>
                      <button
                        type="button"
                        className="button button--secondary"
                        disabled={locked}
                        onClick={() => openReplaceDest(inspectedRule.link)}
                      >
                        {t("Replace Destination")}
                      </button>
                      <button
                        type="button"
                        className="button-link button-link--danger"
                        disabled={locked || Boolean(busy)}
                        onClick={() =>
                          void runMutation("delete-rule", `${inspectedRule.link.EditURL}/rules/delete`, {
                            rule_id: inspectedRule.rule.ID,
                          })
                        }
                      >
                        {t("Delete branch")}
                      </button>
                    </div>
                  </section>
                )}
              </div>
            </Modal>

            {/* Create Branch Modal */}
            <Modal
              open={Boolean(addBranchDialog)}
              onClose={() => setAddBranchDialog(null)}
              eyebrow={addBranchDialog ? `${t("New Branch from")} ${addBranchDialog.hop.Name}` : ""}
              title={t("Create Branch")}
              className="resource-modal proxy-add-link"
            >
              {addBranchDialog && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    const isBlock = branchOutcome === "block" && branchMatch !== "none";
                    if (!isBlock && listenerConflict) {
                      setModalError(listenerConflict);
                      return;
                    }
                    const url = isBlock
                      ? `/proxy-nodes/${encodeURIComponent(addBranchDialog.hop.ProxyID)}/hops/${encodeURIComponent(addBranchDialog.hop.ID)}/block-rules`
                      : `/proxy-nodes/${encodeURIComponent(addBranchDialog.hop.ProxyID)}/hops/${encodeURIComponent(addBranchDialog.hop.ID)}/links`;
                    const fields: Record<string, string> = isBlock
                      ? { match: branchMatch, values: branchValues }
                      : {
                          match: branchMatch,
                          values: branchMatch === "none" ? "" : branchValues,
                          child_agent: branchChildAgent,
                          child_terminal: branchChildTerminal,
                          ...endpointDraftToFields(branchEndpoint),
                        };
                    void runMutation("create-branch", url, fields);
                  }}
                  noValidate
                >
                  <div className="modal__body stack">
                    {modalError && <div className="notice notice--error">{modalError}</div>}
                    <fieldset className="builder-subsection">
                      <legend>1. {t("Rule")}</legend>
                      <ProxyRuleMatchFields
                        match={branchMatch}
                        values={branchValues}
                        onMatchChange={(next) => {
                          setBranchMatch(next);
                          if (next === "none" && branchOutcome === "block") setBranchOutcome("relay");
                        }}
                        onValuesChange={setBranchValues}
                        allowAllFallback
                      />
                    </fieldset>

                    <fieldset className="builder-subsection">
                      <legend>2. {t("Action")}</legend>
                      <label className="field">
                        <span>{t("Destination")}</span>
                        <SelectBox
                          searchable={false}
                          value={branchMatch === "none" ? "relay" : branchOutcome}
                          onChange={(val) => setBranchOutcome(val === "block" ? "block" : "relay")}
                          options={[
                            { value: "relay", label: t("Hop") },
                            ...(branchMatch !== "none" ? [{ value: "block", label: t("Reject") }] : []),
                          ]}
                        />
                      </label>
                    </fieldset>

                    {(branchOutcome === "relay" || branchMatch === "none") && (
                      <>
                        <fieldset className="builder-subsection">
                          <legend>3. {t("Destination")}</legend>
                          <label className="field">
                            <span>{t("Agent")}</span>
                            <SelectBox
                              value={branchChildAgent}
                              onChange={setBranchChildAgent}
                              placeholder={t("Select Agent")}
                              options={[
                                { value: "", label: t("Select Agent"), disabled: true },
                                ...(addBranchDialog.hop.DestinationAgentOptions || []).map((a) => ({
                                  value: a.ID,
                                  label: a.Name,
                                  detail: t(a.LatencyDetail),
                                  status: a.LatencyStatus,
                                })),
                              ]}
                            />
                          </label>
                        </fieldset>

                        <fieldset className="builder-subsection">
                          <legend>4. {t("Relay")}</legend>
                          <ListenerEditor
                            value={branchEndpoint}
                            onChange={setBranchEndpoint}
                            agentId={branchChildAgent}
                            parentAgentId={addBranchDialog.hop.NewLinkEndpoint.ParentAgentID || addBranchDialog.hop.AgentID}
                            allowReverse={addBranchDialog.hop.NewLinkEndpoint.AllowReverse}
                            reverseOnlyDestination={Boolean(selectedBranchDestAgent?.ReverseOnly)}
                            catalog={catalog}
                            onConflictChange={setListenerConflict}
                          />
                          <LinkProbePanel
                            probeUrl={`/proxy-nodes/${encodeURIComponent(addBranchDialog.hop.ProxyID)}/hops/${encodeURIComponent(addBranchDialog.hop.ID)}/latency-probe`}
                            agentId={branchChildAgent}
                            endpoint={branchEndpoint}
                          />
                        </fieldset>

                        <fieldset className="builder-subsection">
                          <legend>5. {t("Exit")}</legend>
                          <label className="field">
                            <span>{t("Unmatched Traffic")}</span>
                            <SelectBox
                              searchable={false}
                              value={branchChildTerminal}
                              onChange={setBranchChildTerminal}
                              options={[
                                { value: "direct", label: t("Direct") },
                                { value: "reject", label: t("Reject") },
                              ]}
                            />
                          </label>
                        </fieldset>
                      </>
                    )}
                  </div>
                  <footer className="modal__footer">
                    <button type="button" className="button button--secondary" onClick={() => setAddBranchDialog(null)}>
                      {t("Cancel")}
                    </button>
                    <button type="submit" className="button button--primary" disabled={locked || Boolean(busy)}>
                      {t("Create Branch")}
                    </button>
                  </footer>
                </form>
              )}
            </Modal>

            {/* Duplicate Branch / Add Rule Modal */}
            <Modal
              open={Boolean(duplicateRuleLink)}
              onClose={() => setDuplicateRuleLink(null)}
              eyebrow={duplicateRuleLink?.Child ? `${t("Route")} to ${duplicateRuleLink.Child.Name}` : ""}
              title={duplicateRuleLink?.Rules?.length ? t("Duplicate Branch") : t("Add Rule")}
              className="resource-modal"
            >
              {duplicateRuleLink && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    void runMutation("dup-branch", `${duplicateRuleLink.EditURL}/rules`, {
                      match: ruleMatch,
                      values: ruleValues,
                    });
                  }}
                  noValidate
                >
                  <div className="modal__body stack">
                    {modalError && <div className="notice notice--error">{modalError}</div>}
                    <ProxyRuleMatchFields
                      match={ruleMatch}
                      values={ruleValues}
                      onMatchChange={setRuleMatch}
                      onValuesChange={setRuleValues}
                      allowAllFallback={false}
                    />
                  </div>
                  <footer className="modal__footer">
                    <button type="button" className="button button--secondary" onClick={() => setDuplicateRuleLink(null)}>
                      {t("Cancel")}
                    </button>
                    <button type="submit" className="button button--primary" disabled={locked || Boolean(busy)}>
                      {duplicateRuleLink.Rules?.length ? t("Duplicate Branch") : t("Add Rule")}
                    </button>
                  </footer>
                </form>
              )}
            </Modal>

            {/* Edit Relay Modal */}
            <Modal
              open={Boolean(editRelayLink)}
              onClose={() => setEditRelayLink(null)}
              eyebrow={editRelayLink?.Child ? `${t("Branch")} to ${editRelayLink.Child.Name}` : ""}
              title={t("Edit Relay")}
              className="resource-modal proxy-add-link"
            >
              {editRelayLink && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (listenerConflict) {
                      setModalError(listenerConflict);
                      return;
                    }
                    void runMutation("edit-relay", editRelayLink.EditURL, endpointDraftToFields(relayEndpoint));
                  }}
                  noValidate
                >
                  <div className="modal__body stack">
                    {modalError && <div className="notice notice--error">{modalError}</div>}
                    <ListenerEditor
                      value={relayEndpoint}
                      onChange={setRelayEndpoint}
                      agentId={editRelayLink.Endpoint.AgentID}
                      parentAgentId={editRelayLink.Endpoint.ParentAgentID}
                      allowReverse={editRelayLink.Endpoint.AllowReverse}
                      reverseOnlyDestination={editRelayLink.Endpoint.Protocol === "reverse_wireguard"}
                      currentListenerId={editRelayLink.Endpoint.ListenerID}
                      catalog={catalog}
                      onConflictChange={setListenerConflict}
                    />
                    <LinkProbePanel
                      probeUrl={editRelayLink.ProbeURL}
                      agentId={editRelayLink.Endpoint.AgentID}
                      endpoint={relayEndpoint}
                    />
                  </div>
                  <footer className="modal__footer">
                    <button type="button" className="button button--secondary" onClick={() => setEditRelayLink(null)}>
                      {t("Cancel")}
                    </button>
                    <button type="submit" className="button button--primary" disabled={locked || Boolean(busy)}>
                      {t("Save Relay")}
                    </button>
                  </footer>
                </form>
              )}
            </Modal>

            {/* Replace Destination Modal */}
            <Modal
              open={Boolean(replaceDestLink)}
              onClose={() => setReplaceDestLink(null)}
              eyebrow={replaceDestLink?.Child ? `${t("Branch")} to ${replaceDestLink.Child.Name}` : ""}
              title={t("Replace Destination")}
              className="resource-modal proxy-add-link"
            >
              {replaceDestLink && (
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (listenerConflict) {
                      setModalError(listenerConflict);
                      return;
                    }
                    void runMutation("replace-dest", `${replaceDestLink.EditURL}/destination`, {
                      confirm_replace: "yes",
                      agent_id: replaceAgentId,
                      terminal: replaceTerminal,
                      ...endpointDraftToFields(relayEndpoint),
                    });
                  }}
                  noValidate
                >
                  <div className="modal__body stack">
                    {modalError && <div className="notice notice--error">{modalError}</div>}
                    <div className="notice notice--error">
                      <strong>
                        {t("Replacing the destination deletes")} {replaceDestLink.Child?.Name}{" "}
                        {t("and its entire downstream subtree. To keep the subtree, move the child Hop instead.")}
                      </strong>
                    </div>
                    <label className="field">
                      <span>{t("Agent")}</span>
                      <SelectBox
                        value={replaceAgentId}
                        onChange={setReplaceAgentId}
                        options={(replaceDestLink.DestinationAgentOptions || []).map((a) => ({
                          value: a.Deleted ? "" : a.ID,
                          label: `${a.Name}${a.Deleted ? ` — ${t("deleted")}` : ""}`,
                          detail: t(a.LatencyDetail),
                          status: a.LatencyStatus,
                          disabled: a.Deleted,
                        }))}
                      />
                    </label>
                    <ListenerEditor
                      value={relayEndpoint}
                      onChange={setRelayEndpoint}
                      agentId={replaceAgentId}
                      parentAgentId={replaceDestLink.Endpoint.ParentAgentID}
                      allowReverse={replaceDestLink.Endpoint.AllowReverse}
                      reverseOnlyDestination={Boolean(selectedReplaceDestAgent?.ReverseOnly)}
                      catalog={catalog}
                      onConflictChange={setListenerConflict}
                    />
                    <LinkProbePanel
                      probeUrl={replaceDestLink.ProbeURL}
                      agentId={replaceAgentId}
                      endpoint={relayEndpoint}
                    />
                    <label className="field">
                      <span>{t("Terminal Exit")}</span>
                      <SelectBox
                        searchable={false}
                        value={replaceTerminal}
                        onChange={setReplaceTerminal}
                        options={[
                          { value: "direct", label: t("Direct") },
                          { value: "reject", label: t("Reject") },
                        ]}
                      />
                    </label>
                  </div>
                  <footer className="modal__footer">
                    <button type="button" className="button button--secondary" onClick={() => setReplaceDestLink(null)}>
                      {t("Cancel")}
                    </button>
                    <button type="submit" className="button button--danger" disabled={locked || Boolean(busy) || !replaceAgentId}>
                      {t("Replace Destination")}
                    </button>
                  </footer>
                </form>
              )}
            </Modal>

            {/* Link Monitor Modal */}
            <Modal
              open={Boolean(monitorLink)}
              onClose={() => setMonitorLink(null)}
              eyebrow={monitorLink?.Child?.Name}
              title={t("Link Monitor")}
              className="resource-modal link-monitor-modal"
              footer={
                <button type="button" className="button button--secondary" onClick={() => setMonitorLink(null)}>
                  {t("Close")}
                </button>
              }
            >
              {monitorLink && (
                <div className="modal__body">
                  <LatencyChart historyUrl={monitorLink.HistoryURL} />
                </div>
              )}
            </Modal>

            {/* Users Roster Modal */}
            <ProxyNodeUsersModal
              open={usersOpen}
              node={node}
              onClose={() => setUsersOpen(false)}
              onReload={reload}
            />
          </>
        )}
      </AsyncState>
    </AppLayout>
  );
};
