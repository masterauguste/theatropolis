import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import {
  endpointDraftToFields,
  endpointToDraft,
  ListenerEditor,
  type EndpointDraft,
} from "../components/ListenerEditor";
import { SelectBox } from "../components/SelectBox";
import { useApp, useDirtyForm } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const NewProxyNodePage: React.FC = () => {
  const navigate = useNavigate();
  const { t, submitMutation } = useApp();
  const { data, loading, error, reload } = usePageData("/proxy-nodes/new");

  const [name, setName] = useState("");
  const [agentId, setAgentId] = useState("");
  const [terminal, setTerminal] = useState("direct");
  const [endpoint, setEndpoint] = useState<EndpointDraft>(() => endpointToDraft());
  const [listenerConflict, setListenerConflict] = useState("");
  const [formError, setFormError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    if (data?.Endpoint) {
      setEndpoint(endpointToDraft(data.Endpoint));
    }
  }, [data?.Endpoint]);

  const dirty = Boolean(name.trim() || agentId);
  useDirtyForm("new-proxy-node", dirty && !submitting);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (submitting) return;
    if (listenerConflict) {
      setFormError(listenerConflict);
      return;
    }
    setSubmitting(true);
    setFormError("");
    try {
      const res = await submitMutation("/proxy-nodes", {
        name: name.trim(),
        agent_id: agentId,
        terminal,
        ...endpointDraftToFields(endpoint),
      });
      if (res.redirect) {
        navigate(res.redirect);
      } else {
        navigate("/proxy-nodes");
      }
    } catch (err) {
      setFormError(err instanceof ApiError ? err.message : t("Could not create Proxy Node."));
    } finally {
      setSubmitting(false);
    }
  };

  const agentOptions = (data?.AgentOptions || []).map((a) => ({
    value: a.ID,
    label: `${a.Name}${!a.Online ? ` — ${t("offline")}` : ""}`,
  }));

  return (
    <AppLayout activeNav="proxy-nodes">
      <nav className="breadcrumbs" aria-label={t("Breadcrumb")}>
        <Link to="/proxy-nodes">{t("Proxy Nodes")}</Link>
        <span aria-hidden="true">/</span>
        <span>{t("New")}</span>
      </nav>

      <header className="page-header">
        <div>
          <p className="eyebrow">{t("New logical service")}</p>
          <h1>{t("Create Proxy Node")}</h1>
        </div>
      </header>

      <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
        {data && (
          <form className="panel stack" onSubmit={(e) => void handleSubmit(e)} noValidate>
            {formError && (
              <div className="notice notice--error" role="alert">
                {formError}
              </div>
            )}

            <div className="builder-fields">
              <label className="field">
                <span>{t("Proxy Node name")}</span>
                <input
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="cinema"
                  required
                  autoFocus
                />
              </label>
              <label className="field">
                <span>{t("Entrance Agent")}</span>
                <SelectBox
                  value={agentId}
                  onChange={setAgentId}
                  placeholder={t("Select an enrolled Agent")}
                  options={[{ value: "", label: t("Select an enrolled Agent"), disabled: true }, ...agentOptions]}
                />
              </label>
            </div>

            <h2>{t("Entrance protocol")}</h2>
            <ListenerEditor
              value={endpoint}
              onChange={setEndpoint}
              agentId={agentId}
              allowReverse={false}
              showFamilyAndMux={false}
              catalog={data.ListenerOptions || []}
              onConflictChange={setListenerConflict}
            />

            <fieldset className="builder-subsection">
              <legend>{t("Exit")}</legend>
              <label className="field">
                <span>{t("Unmatched traffic")}</span>
                <SelectBox
                  searchable={false}
                  value={terminal}
                  onChange={setTerminal}
                  options={[
                    { value: "direct", label: t("Direct") },
                    { value: "reject", label: t("Reject") },
                  ]}
                />
              </label>
            </fieldset>

            <div className="configuration-form__actions">
              <Link className="button button--secondary" to="/proxy-nodes">
                {t("Cancel")}
              </Link>
              <button className="button button--primary" type="submit" disabled={submitting || !agentId}>
                {submitting ? t("Saving…") : t("Create Proxy Node")}
              </button>
            </div>
          </form>
        )}
      </AsyncState>
    </AppLayout>
  );
};
