import React, { useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { AppLayout } from "../components/AppLayout";
import { AsyncState } from "../components/AsyncState";
import { useApp, useDirtyForm } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const UsersPage: React.FC = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const navigate = useNavigate();
  const { t, countLabel, submitMutation } = useApp();

  const queryStr = searchParams.toString();
  const pageUrl = queryStr ? `/users?${queryStr}` : "/users";
  const { data, loading, error, reload } = usePageData(pageUrl);

  const [searchInput, setSearchInput] = useState(searchParams.get("q") || "");
  const [newName, setNewName] = useState("");
  const [createError, setCreateError] = useState("");
  const [creating, setCreating] = useState(false);

  useDirtyForm("create-user", newName.trim().length > 0 && !creating);

  useEffect(() => {
    setSearchInput(searchParams.get("q") || "");
  }, [searchParams]);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const q = searchInput.trim();
    if (q) setSearchParams({ q });
    else setSearchParams({});
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (creating) return;
    setCreateError("");
    setCreating(true);
    try {
      const res = await submitMutation("/users", { name: newName.trim() });
      setNewName("");
      if (res.redirect) {
        navigate(res.redirect);
      } else {
        await reload();
      }
    } catch (err) {
      setCreateError(err instanceof ApiError ? err.message : t("Could not create user."));
    } finally {
      setCreating(false);
    }
  };

  const users = data?.EndUsers || [];

  return (
    <AppLayout activeNav="users">
      <header className="page-header">
        <div>
          <p className="eyebrow">{t("Global identities")}</p>
          <h1>{t("Users")}</h1>
        </div>
      </header>

      <div className="split-panels">
        <section className="panel">
          <div className="panel__header">
            <div>
              <h2>{t("End users")}</h2>
            </div>
            {data && <span className="panel__count">{countLabel(data.UserTotal, "total")}</span>}
          </div>

          <form className="users-search-bar" role="search" onSubmit={handleSearch} noValidate>
            <label className="field users-search-bar__field">
              <span className="sr-only">{t("Search users")}</span>
              <input
                type="search"
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                placeholder={t("Search by management name or username")}
              />
            </label>
            <div className="users-search-bar__actions">
              <button className="button button--secondary" type="submit">
                {t("Search")}
              </button>
              {data?.UserSearch && (
                <button
                  type="button"
                  className="button button--quiet"
                  onClick={() => {
                    setSearchInput("");
                    setSearchParams({});
                  }}
                >
                  {t("Clear search")}
                </button>
              )}
            </div>
          </form>

          <AsyncState loading={loading} error={error} onRetry={() => void reload()}>
            {users.length > 0 ? (
              <div className="membership-list">
                {users.map((user) => (
                  <Link key={user.ID} to={user.URL}>
                    <span>
                      <strong>{user.Name}</strong>
                      <small>
                        {countLabel(user.Memberships, "proxy-access")}
                        {user.LoginUsername ? ` · ${user.LoginUsername}` : ""}
                      </small>
                    </span>
                    <span className={`membership-status membership-status--${user.LoginClass}`}>
                      {user.LoginStatus}
                    </span>
                    <span aria-hidden="true">→</span>
                  </Link>
                ))}
              </div>
            ) : (
              <div className="panel__empty">
                <p>{data?.UserSearch ? t("No users match your search.") : t("No users have been created.")}</p>
              </div>
            )}

            {data && data.UserTotal > 0 && (
              <nav className="configuration-form__actions" aria-label={t("User pages")}>
                <span>
                  {data.UserStart}–{data.UserEnd} / {data.UserTotal}
                </span>
                {data.UsersPreviousURL && (
                  <Link className="button button--secondary" to={data.UsersPreviousURL}>
                    {t("Previous")}
                  </Link>
                )}
                {data.UsersNextURL && (
                  <Link className="button button--secondary" to={data.UsersNextURL}>
                    {t("Next")}
                  </Link>
                )}
              </nav>
            )}
          </AsyncState>
        </section>

        <section className="panel">
          <div className="panel__header">
            <h2>{t("Create user")}</h2>
          </div>
          <form className="stack" onSubmit={(e) => void handleCreate(e)} noValidate>
            {createError && (
              <div className="notice notice--error" role="alert">
                {createError}
              </div>
            )}
            <label className="field">
              <span>{t("Management name")}</span>
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                placeholder="alice"
                required
              />
            </label>
            <button className="button button--primary" type="submit" disabled={creating}>
              {creating ? t("Saving…") : t("Create user")}
            </button>
          </form>
        </section>
      </div>
    </AppLayout>
  );
};
