import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { SecretInput } from "../components/SecretInput";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const LoginPage: React.FC = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const isPortalLogin = location.pathname === "/portal/login";
  const endpoint = isPortalLogin ? "/portal/login" : "/login";

  const { locale, changeLocale, t, submitMutation, refreshSession } = useApp();
  const { data, loading } = usePageData(endpoint);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [accessKey, setAccessKey] = useState("");
  const [error, setError] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    document.body.className = "auth-page";
    return () => {
      document.body.className = "";
    };
  }, []);

  useEffect(() => {
    if (data?.Username) setUsername(data.Username);
    else if (data?.EndUserLogin?.Username) setUsername(data.EndUserLogin.Username);
    if (data?.Error) setError(data.Error);
  }, [data]);

  const unified = Boolean(data?.UnifiedLogin);
  const legacyOnly = Boolean(data?.LegacyLogin && !unified && !isPortalLogin);

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting) return;
    setError("");
    setSubmitting(true);
    try {
      const fields: Record<string, string> = legacyOnly
        ? { access_key: accessKey }
        : { username, password };
      const res = await submitMutation(endpoint, fields, { skipCSRF: true, formAdapter: false });
      await refreshSession();
      navigate(res.redirect || (isPortalLogin ? "/portal" : "/servers"), { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError(t("Sign in failed."));
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <main className="auth-shell" id="main">
      <div className="auth-card">
        <div className="auth-card__topline">
          <div className="brand">
            <span className="brand__mark" aria-hidden="true">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="9" />
                <path d="M12 3v18M3 12h18" opacity="0.45" />
                <circle cx="12" cy="12" r="2.75" fill="currentColor" stroke="none" />
              </svg>
            </span>
            <span className="brand__text">
              <strong>Theatropolis</strong>
            </span>
          </div>
          <button
            type="button"
            className="language-switch"
            onClick={() => void changeLocale(locale === "zh-CN" ? "en" : "zh-CN")}
          >
            {locale === "zh-CN" ? "English" : "中文"}
          </button>
        </div>

        <div className="auth-card__heading">
          <p className="eyebrow">
            {isPortalLogin ? t("User portal") : unified ? t("Account access") : t("Operator access")}
          </p>
          <h1>{isPortalLogin || unified ? t("Sign in") : t("Sign in to continue")}</h1>
          {legacyOnly ? (
            <p>{t("Enter the access key shown when the master was installed.")}</p>
          ) : !unified && !isPortalLogin ? (
            <p>{t("Enter your operator username and password.")}</p>
          ) : null}
        </div>

        {legacyOnly && (
          <div className="notice notice--warning" role="status">
            <strong>{t("Legacy sign-in")}</strong>
            <br />
            {t("This master still uses its existing access key. Rerun the master installer with")}{" "}
            <code>--admin-username yourname</code> {t("when you are ready to migrate it.")}
          </div>
        )}

        {error && (
          <div className="notice notice--error" role="alert">
            {error}
          </div>
        )}

        {loading ? (
          <div className="loading-state" role="status">
            <span className="loading-spinner" aria-hidden="true" />
            <span>{t("Loading…")}</span>
          </div>
        ) : (
          <form className="stack" onSubmit={(e) => void onSubmit(e)} noValidate>
            {legacyOnly ? (
              <div className="field">
                <label htmlFor="access-key">{t("Access key")}</label>
                <SecretInput
                  id="access-key"
                  name="access_key"
                  secretLabel="access key"
                  autoComplete="current-password"
                  value={accessKey}
                  onChange={(e) => setAccessKey(e.target.value)}
                  required
                  minLength={43}
                  maxLength={128}
                  autoFocus
                />
                <small>{t("Use the 43-character value printed once by the installer.")}</small>
              </div>
            ) : (
              <>
                <div className="field">
                  <label htmlFor="username">{isPortalLogin ? t("Login username") : t("Username")}</label>
                  <input
                    id="username"
                    name="username"
                    type="text"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    autoComplete="username"
                    autoCapitalize="none"
                    spellCheck={false}
                    maxLength={64}
                    required={!data?.LegacyLogin}
                    autoFocus={!error}
                  />
                </div>
                <div className="field">
                  <label htmlFor="password">
                    {unified && data?.LegacyLogin ? t("Password or access key") : t("Password")}
                  </label>
                  <SecretInput
                    id="password"
                    name="password"
                    secretLabel="password"
                    autoComplete="current-password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    maxLength={512}
                    autoFocus={Boolean(error)}
                  />
                </div>
              </>
            )}
            <button className="button button--primary button--full" type="submit" disabled={submitting}>
              {submitting ? t("Signing in…") : t("Sign in")}
            </button>
          </form>
        )}

        {!isPortalLogin && !unified && (
          <p className="auth-help">
            {legacyOnly
              ? t("The master stores no plaintext copy. Keep the value printed by the installer in your password manager.")
              : t("Your credentials are verified locally. The master never stores your plaintext password.")}
          </p>
        )}
      </div>
    </main>
  );
};
