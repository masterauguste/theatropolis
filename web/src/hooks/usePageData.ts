import { useCallback, useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ApiError, fetchPage } from "../api/client";
import type { PageData, SpaEnvelope } from "../api/types";
import { useApp } from "../context/AppContext";

export interface UsePageResult {
  envelope: SpaEnvelope | null;
  data: PageData | null;
  loading: boolean;
  refreshing: boolean;
  error: string;
  reload: () => Promise<void>;
  setData: React.Dispatch<React.SetStateAction<PageData | null>>;
}

function pathnameOf(url: string): string {
  const queryIdx = url.indexOf("?");
  return queryIdx >= 0 ? url.slice(0, queryIdx) : url;
}

export function usePageData(url: string, options?: { skip?: boolean }): UsePageResult {
  const { localeVersion, updateCSRFToken, handleUnauthorized, hasUnsavedChanges, t } = useApp();
  const navigate = useNavigate();
  const [envelope, setEnvelope] = useState<SpaEnvelope | null>(null);
  const [data, setData] = useState<PageData | null>(null);
  const [loading, setLoading] = useState(!options?.skip);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const mountedRef = useRef(true);
  const seqRef = useRef(0);
  const controllerRef = useRef<AbortController | null>(null);
  const hasDataRef = useRef(false);
  const lastPathnameRef = useRef("");

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      controllerRef.current?.abort();
    };
  }, []);

  const performFetch = useCallback(
    async (blocking: boolean) => {
      if (options?.skip) return;
      controllerRef.current?.abort();
      const controller = new AbortController();
      controllerRef.current = controller;
      const seq = ++seqRef.current;

      if (blocking) {
        setLoading(true);
      } else {
        setRefreshing(true);
      }
      setError("");

      try {
        const res = await fetchPage(url, controller.signal);
        if (!mountedRef.current || seq !== seqRef.current) return;
        if (res.redirect) {
          navigate(res.redirect, { replace: true });
          return;
        }
        hasDataRef.current = true;
        lastPathnameRef.current = pathnameOf(url);
        setEnvelope(res);
        setData(res.data);
        if (res.data?.CSRFToken) {
          updateCSRFToken(res.data.CSRFToken);
        }
        if (res.data?.Title) {
          document.title = `${t(res.data.Title)} · Theatropolis`;
        }
      } catch (err) {
        if (!mountedRef.current || seq !== seqRef.current || (err instanceof DOMException && err.name === "AbortError")) {
          return;
        }
        if (err instanceof ApiError && (err.status === 401 || err.unauthorized)) {
          handleUnauthorized(err.redirect || "/login");
          if (!hasUnsavedChanges()) {
            navigate(err.redirect || "/login", { replace: true });
          }
          return;
        }
        if (err instanceof ApiError && err.envelope) {
          hasDataRef.current = true;
          lastPathnameRef.current = pathnameOf(url);
          setEnvelope(err.envelope);
          setData(err.envelope.data);
          setError(err.message);
          return;
        }
        if (blocking || !hasDataRef.current) {
          setError(err instanceof Error ? err.message : t("Request failed."));
        }
      } finally {
        if (mountedRef.current && seq === seqRef.current) {
          setLoading(false);
          setRefreshing(false);
        }
      }
    },
    [url, options?.skip, navigate, updateCSRFToken, handleUnauthorized, hasUnsavedChanges, t],
  );

  const reload = useCallback(async () => {
    await performFetch(!hasDataRef.current);
  }, [performFetch]);

  useEffect(() => {
    if (options?.skip) return;
    const nextPathname = pathnameOf(url);
    const samePathname = hasDataRef.current && lastPathnameRef.current === nextPathname;
    if (!samePathname) {
      hasDataRef.current = false;
      setData(null);
      setEnvelope(null);
    }
    void performFetch(!samePathname);
  }, [url, localeVersion, options?.skip, performFetch]);

  return { envelope, data, loading, refreshing, error, reload, setData };
}
