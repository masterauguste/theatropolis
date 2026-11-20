import React from "react";
import { useApp } from "../context/AppContext";

interface AsyncStateProps {
  loading: boolean;
  error?: string;
  onRetry?: () => void;
  loadingLabel?: string;
  children: React.ReactNode;
}

export const AsyncState: React.FC<AsyncStateProps> = ({
  loading,
  error,
  onRetry,
  loadingLabel,
  children,
}) => {
  const { t } = useApp();

  if (loading) {
    return (
      <div className="loading-state" role="status">
        <span className="loading-spinner" aria-hidden="true" />
        <span>{loadingLabel || t("Loading…")}</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="notice notice--error" role="alert">
        <p>{error}</p>
        {onRetry && (
          <button type="button" className="button button--secondary button--small" onClick={onRetry}>
            {t("Retry")}
          </button>
        )}
      </div>
    );
  }

  return <>{children}</>;
};
