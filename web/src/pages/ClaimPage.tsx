import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { SecretInput } from "../components/SecretInput";
import { useApp } from "../context/AppContext";
import { usePageData } from "../hooks/usePageData";

export const ClaimPage: React.FC = () => {
  const navigate = useNavigate();
  const { locale, changeLocale, t, submitMutation, refreshSession } = useApp();
  const { data, loading, error: loadError } = usePageData("/claim");

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState("");
  const [unavailable, setUnavailable] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    document.body.className = "auth-page";
    return () => {
      document.body.className = "";
    };
  }, []);

  useEffect(() => {
    if (data?.EndUserLogin?.Username) setUsername(data.EndUserLogin.Username);
    if (data?.EndUserLogin?.Unavailable) setUnavailable(true);
    if (data?.Error) setError(data.Error);
  }, [data]);

  useEffect(() => {
    if (loadError) {
      setError(loadError);
      setUnavailable(true);
    }
  }, [loadError]);

  const onSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (submitting) return;
    setError("");
    setSubmitting(true);
    try {
      const res = await submitMutation(
        "/claim",
        {
          username,
          password,
          password_confirmation: confirmPassword,
        },
        { skipCSRF: true, formAdapter: false },
      );
      await refreshSession();
      navigate(res.redirect || "/portal", { replace: true });
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
        if (err.status === 410 || err.envelope?.data?.EndUserLogin?.Unavailable) {
          setUnavailable(true);
        }
      } else {
        setError(t("Account setup failed."));
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
          <p className="eyebrow">{t("User portal")}</p>
          <h1>{t("Set Up Account")}</h1>
        </div>

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
        ) : unavailable ? (
          <Link className="button button--secondary button--full" to="/login">
            {t("Go to Sign In")}
          </Link>
        ) : (
          <form className="stack" onSubmit={(e) => void onSubmit(e)} noValidate>
            <div className="field">
              <label htmlFor="claim-username">{t("Login username")}</label>
              <input
                id="claim-username"
                name="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                autoCapitalize="none"
                spellCheck={false}
                required
                maxLength={64}
                autoFocus
              />
            </div>
            <div className="field">
              <label htmlFor="claim-password">{t("Password")}</label>
              <SecretInput
                id="claim-password"
                name="password"
                autoComplete="new-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                minLength={12}
                maxLength={512}
              />
            </div>
            <div className="field">
              <label htmlFor="claim-password-confirm">{t("Confirm password")}</label>
              <SecretInput
                id="claim-password-confirm"
                name="password_confirmation"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                required
                minLength={12}
                maxLength={512}
              />
            </div>
            <button className="button button--primary button--full" type="submit" disabled={submitting}>
              {submitting ? t("Saving…") : t("Create Account")}
            </button>
          </form>
        )}
      </div>
    </main>
  );
};
