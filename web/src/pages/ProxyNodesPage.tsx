import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { fetchJSON } from "../api/client";
import type { ProxyDeploymentView } from "../api/types";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const ProxyNodesPage: React.FC = () => {
  const { t, countLabel } = useApp();
  const { data, loading, error, reload } = usePageData("/proxy-nodes");
  const [deployment, setDeployment] = useState<ProxyDeploymentView | null>(null);

  useEffect(() => {
    setDeployment(data?.ProxyDeployment || null);
  }, [data?.ProxyDeployment]);

  useEffect(() => {
    const isActive = Boolean(deployment?.active);
    const isPending = deployment?.status === "pending";
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
        // ignore transient polling failure
      }
    }, intervalMs);
    return () => window.clearInterval(timer);
  }, [deployment?.active, deployment?.status, reload]);

  const nodes = data?.ProxyNodes || [];
  const locked = Boolean(deployment?.active);

  return (
    <AppLayout activeNav="proxy-nodes">
      <header className="page-header">
        <div>
          <p className="eyebrow">{t("Logical services")}</p>
          <h1>{t("Proxy Nodes")}</h1>
        </div>
        <div className="page-header__actions">
          <Link
            className="button button--primary"
            to="/proxy-nodes/new"
            aria-disabled={locked || undefined}
            onClick={(e) => {
              if (locked) e.preventDefault();
            }}
          >
            <span aria-hidden="true">+</span> {t("New Proxy Node")}
          </Link>
        </div>
      </header>

      {deployment && (
        <section
          className={`notice proxy-deployment notice--${
            deployment.class === "attention" ? "error" : deployment.class === "pending" ? "warning" : "success"
          }`}
        >
          <strong>
            {deployment.status === "pending"
              ? t("Topology Pending")
              : `${t("Topology change")}: ${deployment.label}`}
          </strong>
          {deployment.status === "pending" ? (
            <p>{t("Saved changes are not yet active.")}</p>
          ) : deployment.error ? (
            <p>{deployment.error}</p>
          ) : null}
          {deployment.agents && deployment.agents.length > 0 && (
            <div className="deployment-agent-list">
              {deployment.agents.map((a) => (
                <span key={a.agent_id}>
                  {a.agent_name} — {a.status}
                </span>
              ))}
            </div>
          )}
        </section>
      )}

      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        <section className="panel">
          <div className="panel__header">
            <h2>{t("Routing trees")}</h2>
            <span className="panel__count">{countLabel(nodes.length, "total")}</span>
          </div>

          {nodes.length > 0 ? (
            <div className="resource-grid">
              {nodes.map((node) =>
                node.PendingRemoval ? (
                  <article
                    key={node.ID}
                    className="resource-card resource-card--static resource-card--pending-removal"
                  >
                    <span className="resource-card__eyebrow">{node.Entrance} {t("Entrance")}</span>
                    <div className="resource-card__heading">
                      <strong>{node.Name}</strong>
                      <span className="status status--pending">
                        <span aria-hidden="true" />
                        {t("Pending Removal")}
                      </span>
                    </div>
                    <span>{node.EntranceAgent}</span>
                    <dl>
                      <div>
                        <dt>{t("Hops")}</dt>
                        <dd>{node.HopCount}</dd>
                      </div>
                    </dl>
                    <small>{t("Old configuration is still running.")}</small>
                  </article>
                ) : (
                  <Link
                    key={node.ID}
                    className={`resource-card ${node.PendingApply ? "resource-card--pending-apply" : ""}`}
                    to={node.URL}
                  >
                    <span className="resource-card__eyebrow">{node.Entrance} {t("Entrance")}</span>
                    <div className="resource-card__heading">
                      <strong>{node.Name}</strong>
                      {node.EntranceDeleted ? (
                        <span className="status status--failed">
                          <span aria-hidden="true" />
                          {t("Entrance Server Deleted")}
                        </span>
                      ) : node.RelayDeleted ? (
                        <span className="status status--failed">
                          <span aria-hidden="true" />
                          {t("Relay Server Deleted")}
                        </span>
                      ) : node.EntranceOffline ? (
                        <span className="status status--failed">
                          <span aria-hidden="true" />
                          {t("Entrance Offline")}
                        </span>
                      ) : node.RelayOffline ? (
                        <span className="status status--pending">
                          <span aria-hidden="true" />
                          {t("Relay Offline")}
                        </span>
                      ) : node.PendingApply ? (
                        <span className="status status--pending">
                          <span aria-hidden="true" />
                          {t("Pending Apply")}
                        </span>
                      ) : null}
                    </div>
                    <span>{node.EntranceAgent}</span>
                    <dl>
                      <div>
                        <dt>{t("Hops")}</dt>
                        <dd>{node.HopCount}</dd>
                      </div>
                      <div>
                        <dt>{t("Users")}</dt>
                        <dd>{node.MemberCount}</dd>
                      </div>
                    </dl>
                    <small>
                      {t("Updated")} {node.UpdatedAt}
                    </small>
                  </Link>
                ),
              )}
            </div>
          ) : (
            <div className="empty-state">
              <h3>{t("No Proxy Nodes yet")}</h3>
              <p>{t("Create an entrance, then add relay branches and grant user access.")}</p>
              <Link className="button button--primary" to="/proxy-nodes/new">
                {t("Create your first Proxy Node")}
              </Link>
            </div>
          )}
        </section>
      </AsyncState>
    </AppLayout>
  );
};
