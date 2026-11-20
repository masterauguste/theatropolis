import { useCallback, useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, fetchPage } from "../api/client";
import type { PageData, SpaEnvelope } from "../api/types";
import { useApp } from "../context/AppContext";

export interface UsePageResult {
  envelope: SpaEnvelope | null;
  data: PageData | null;
  loading: boolean;
  error: string;
  reload: () => Promise<void>;
  setData: React.Dispatch<React.SetStateAction<PageData | null>>;
}

export function usePageData(url: string, options?: { skip?: boolean }): UsePageResult {
  const { localeVersion, updateCSRFToken, handleUnauthorized, hasUnsavedChanges, t } = useApp();
  const navigate = useNavigate();
  const [envelope, setEnvelope] = useState<SpaEnvelope | null>(null);
  const [data, setData] = useState<PageData | null>(null);
  const [loading, setLoading] = useState(!options?.skip);
  const [error, setError] = useState("");
  const [reloadTick, setReloadTick] = useState(0);

  const reload = useCallback(async () => {
    setReloadTick((v) => v + 1);
  }, []);

  useEffect(() => {
    if (options?.skip) return;
    const controller = new AbortController();
    let active = true;
    setLoading(true);
    setError("");
    fetchPage(url, controller.signal)
      .then((res) => {
        if (!active) return;
        if (res.redirect) {
          navigate(res.redirect, { replace: true });
          return;
        }
        setEnvelope(res);
        setData(res.data);
        if (res.data?.CSRFToken) {
          updateCSRFToken(res.data.CSRFToken);
        }
        if (res.data?.Title) {
          document.title = `${t(res.data.Title)} · Theatropolis`;
        }
      })
      .catch((err) => {
        if (!active || (err instanceof DOMException && err.name === "AbortError")) return;
        if (err instanceof ApiError && (err.status === 401 || err.unauthorized)) {
          handleUnauthorized(err.redirect || "/login");
          if (!hasUnsavedChanges()) {
            navigate(err.redirect || "/login", { replace: true });
          }
          return;
        }
        if (err instanceof ApiError && err.envelope) {
          setEnvelope(err.envelope);
          setData(err.envelope.data);
          setError(err.message);
          return;
        }
        setError(err instanceof Error ? err.message : t("Request failed."));
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
      controller.abort();
    };
  }, [url, localeVersion, reloadTick, options?.skip, navigate, updateCSRFToken, handleUnauthorized, hasUnsavedChanges, t]);

  return { envelope, data, loading, error, reload, setData };
}
