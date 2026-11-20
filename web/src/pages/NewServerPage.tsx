import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { AppLayout } from "../components/AppLayout";
import { SelectBox } from "../components/SelectBox";
import { useApp, useDirtyForm } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const NewServerPage: React.FC = () => {
  const navigate = useNavigate();
  const { t, submitMutation } = useApp();
  const { data } = usePageData("/servers/new");

  const [reverseOnly, setReverseOnly] = useState("0");
  const [displayName, setDisplayName] = useState("");
  const [ttlSeconds, setTtlSeconds] = useState("900");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  const dirty = displayName.trim().length > 0 || reverseOnly !== "0" || ttlSeconds !== "900";
  useDirtyForm("new-server", dirty && !submitting);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    setError("");
    setSubmitting(true);
    try {
      const res = await submitMutation("/servers", {
        reverse_only: reverseOnly,
        display_name: displayName.trim(),
        ttl_seconds: ttlSeconds,
      });
      if (res.redirect) {
        navigate(res.redirect, { replace: true });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t("Could not create server enrollment."));
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <AppLayout activeNav="servers" width="narrow">
      <nav className="breadcrumbs" aria-label={t("Breadcrumb")}>
        <Link to="/servers">{t("Servers")}</Link>
        <span aria-hidden="true">/</span>
        <span aria-current="page">{t("Add server")}</span>
      </nav>

      <header className="page-header page-header--compact">
        <div>
          <p className="eyebrow">{t("Secure enrollment")}</p>
          <h1>{t("Add a server")}</h1>
        </div>
      </header>

      <section className="form-layout">
        <form className="panel form-card" onSubmit={(e) => void handleSubmit(e)} noValidate>
          <div className="form-card__header">
            <span className="step-number">1</span>
            <h2>{t("Server identity")}</h2>
          </div>

          {error && (
            <div className="notice notice--error" role="alert">
              {error}
            </div>
          )}

          <div className="stack">
            <label className="field">
              <span>{t("Connectivity mode")}</span>
              <SelectBox
                searchable={false}
                value={reverseOnly}
                onChange={setReverseOnly}
                options={[
                  { value: "0", label: t("Publicly reachable") },
                  { value: "1", label: t("CGNAT / Reverse-only") },
                ]}
              />
              <small>
                {t("Reverse-only Servers cannot be entrances. Their parent must accept inbound WireGuard UDP.")}
              </small>
            </label>

            <label className="field">
              <span>{t("Server Name")}</span>
              <input
                type="text"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                placeholder="Paris Edge"
                autoComplete="off"
                spellCheck={false}
                required
                autoFocus
              />
            </label>

            <label className="field">
              <span>{t("Enrollment lifetime")}</span>
              <SelectBox
                searchable={false}
                value={ttlSeconds}
                onChange={setTtlSeconds}
                options={[
                  { value: "900", label: t("15 minutes · Recommended") },
                  { value: "3600", label: t("1 hour") },
                  { value: "86400", label: t("24 hours") },
                ]}
              />
              <small>{t("The credential becomes unusable after this period or immediately after enrollment.")}</small>
            </label>
          </div>

          <div className="form-card__actions">
            <Link className="button button--secondary" to="/servers">
              {t("Cancel")}
            </Link>
            <button className="button button--primary" type="submit" disabled={submitting}>
              {submitting ? t("Saving…") : t("Create install command")}
            </button>
          </div>
        </form>

        <aside className="context-card">
          <p className="eyebrow">{t("Connection target")}</p>
          <h2>{data?.MasterAddress || "—"}</h2>
          <p>{t("The command is generated from the master’s trusted public URL, not from browser request headers.")}</p>
          <dl>
            <div>
              <dt>{t("Transport")}</dt>
              <dd>{t("TLS-secured gRPC")}</dd>
            </div>
            <div>
              <dt>{t("Credential")}</dt>
              <dd>{t("Single use")}</dd>
            </div>
            <div>
              <dt>{t("Supported OS")}</dt>
              <dd>Debian / Ubuntu</dd>
            </div>
          </dl>
        </aside>
      </section>
    </AppLayout>
  );
};
