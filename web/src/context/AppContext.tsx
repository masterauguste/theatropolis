import React, { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import {
  ApiError,
  fetchFreshCSRFToken,
  fetchMessages,
  fetchSession,
  submitForm as rawSubmitForm,
  switchLanguage,
  type SubmitResult,
} from "../api/client";
import type { SessionInfo } from "../api/types";

interface RefreshBanner {
  message: string;
  url: string;
  signInTab?: boolean;
}

interface AppContextValue {
  ready: boolean;
  locale: "en" | "zh-CN";
  session: SessionInfo;
  t: (key: string) => string;
  countLabel: (count: number, kind: string) => string;
  changeLocale: (locale: "en" | "zh-CN") => Promise<void>;
  refreshSession: () => Promise<SessionInfo>;
  updateCSRFToken: (token: string) => void;
  submitMutation: (
    action: string,
    fields: Record<string, string | string[] | undefined> | URLSearchParams,
    options?: { skipCSRF?: boolean; formAdapter?: boolean },
  ) => Promise<SubmitResult>;
  handleUnauthorized: (redirect?: string) => void;
  setFormDirty: (key: string, dirty: boolean) => void;
  hasUnsavedChanges: () => boolean;
  refreshBanner: RefreshBanner | null;
  clearRefreshBanner: () => void;
  offerRefresh: (message: string, url?: string, signInTab?: boolean) => void;
  appNotice: string;
  setAppNotice: (msg: string) => void;
  localeVersion: number;
}

const defaultSession: SessionInfo = {
  authenticated: false,
  role: "",
  locale: "en",
  publicURL: "",
  masterAddress: "",
  masterVersion: "",
  unifiedLogin: false,
  legacyLogin: false,
};

const AppContext = createContext<AppContextValue | null>(null);

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [ready, setReady] = useState(false);
  const [locale, setLocale] = useState<"en" | "zh-CN">("en");
  const [messages, setMessages] = useState<Record<string, string>>({});
  const [session, setSession] = useState<SessionInfo>(defaultSession);
  const [refreshBanner, setRefreshBanner] = useState<RefreshBanner | null>(null);
  const [appNotice, setAppNotice] = useState("");
  const [localeVersion, setLocaleVersion] = useState(0);

  const dirtyKeysRef = useRef<Set<string>>(new Set());
  const inFlightRef = useRef(0);
  const needsCSRFRefreshRef = useRef(false);
  const csrfRef = useRef("");

  const updateCSRFToken = useCallback((token: string) => {
    if (!token) return;
    csrfRef.current = token;
    setSession((prev) => (prev.csrfToken === token ? prev : { ...prev, csrfToken: token }));
  }, []);

  const refreshSession = useCallback(async () => {
    const info = await fetchSession();
    setSession(info);
    if (info.csrfToken) csrfRef.current = info.csrfToken;
    const normalized = info.locale === "zh-CN" ? "zh-CN" : "en";
    setLocale(normalized);
    document.documentElement.lang = normalized;
    return info;
  }, []);

  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const [sessionInfo, msgCatalog] = await Promise.all([fetchSession(), fetchMessages()]);
        if (!active) return;
        const normalized = (msgCatalog.locale || sessionInfo.locale) === "zh-CN" ? "zh-CN" : "en";
        setLocale(normalized);
        document.documentElement.lang = normalized;
        setMessages(msgCatalog.messages || {});
        setSession(sessionInfo);
        if (sessionInfo.csrfToken) csrfRef.current = sessionInfo.csrfToken;
      } catch {
        // Fallback to English defaults on transient failure.
      } finally {
        if (active) setReady(true);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const t = useCallback(
    (key: string) => messages[key] || key,
    [messages],
  );

  const countLabel = useCallback(
    (count: number, kind: string): string => {
      if (locale === "zh-CN") {
        switch (kind) {
          case "hop":
          case "node":
            return `${count} 个节点`;
          case "relay-hop":
            return `${count} 个中继节点`;
          case "link":
            return `${count} 条链路`;
          case "user":
            return `${count} 位用户`;
          case "exit":
            return `${count} 个出口`;
          case "available-node":
            return `${count} 个可用节点`;
          case "proxy-access":
            return `已授权 ${count} 个代理节点`;
          case "reference":
            return `${count} 个配置`;
          default:
            return `共 ${count} 项`;
        }
      }
      const nouns: Record<string, string> = {
        hop: "Hop",
        node: "Node",
        "relay-hop": "Relay Hop",
        link: "Link",
        user: "user",
        exit: "exit",
        "available-node": "Node available",
        "proxy-access": "Proxy Node access grant",
        reference: "reference",
      };
      let noun = nouns[kind];
      if (!noun) return `${count} total`;
      if (count !== 1) {
        noun = kind === "available-node" ? "Nodes available" : `${noun}s`;
      }
      return `${count} ${noun}`;
    },
    [locale],
  );

  const setFormDirty = useCallback((key: string, dirty: boolean) => {
    if (dirty) dirtyKeysRef.current.add(key);
    else dirtyKeysRef.current.delete(key);
  }, []);

  const hasUnsavedChanges = useCallback(() => {
    return dirtyKeysRef.current.size > 0 || inFlightRef.current > 0;
  }, []);

  useEffect(() => {
    const onBeforeUnload = (event: BeforeUnloadEvent) => {
      if (dirtyKeysRef.current.size > 0 || inFlightRef.current > 0) {
        event.preventDefault();
        event.returnValue = "";
      }
    };
    window.addEventListener("beforeunload", onBeforeUnload);
    return () => window.removeEventListener("beforeunload", onBeforeUnload);
  }, []);

  const offerRefresh = useCallback((message: string, url = window.location.href, signInTab = false) => {
    setRefreshBanner({ message, url, signInTab });
  }, []);

  const clearRefreshBanner = useCallback(() => setRefreshBanner(null), []);

  const handleUnauthorized = useCallback(
    (redirect = "/login") => {
      needsCSRFRefreshRef.current = true;
      if (dirtyKeysRef.current.size > 0 || inFlightRef.current > 0) {
        offerRefresh(
          t("Your session expired. Your input is still on this page. Sign in in another tab, then try again."),
          redirect,
          true,
        );
        return;
      }
      setSession((prev) => ({ ...prev, authenticated: false, role: "", csrfToken: "" }));
      csrfRef.current = "";
    },
    [offerRefresh, t],
  );

  const submitMutation = useCallback(
    async (
      action: string,
      fields: Record<string, string | string[] | undefined> | URLSearchParams,
      options?: { skipCSRF?: boolean; formAdapter?: boolean },
    ): Promise<SubmitResult> => {
      inFlightRef.current += 1;
      try {
        let token = csrfRef.current;
        if (!options?.skipCSRF && needsCSRFRefreshRef.current) {
          try {
            token = await fetchFreshCSRFToken();
            updateCSRFToken(token);
            needsCSRFRefreshRef.current = false;
            setRefreshBanner(null);
          } catch {
            offerRefresh(
              t("Your session expired. Your input is still on this page. Sign in in another tab, then try again."),
              "/login",
              true,
            );
            throw new ApiError(
              t("Your session expired. Your input is still on this page. Sign in in another tab, then try again."),
              401,
              { unauthorized: true, redirect: "/login" },
            );
          }
        }
        const result = await rawSubmitForm(action, fields, {
          csrfToken: options?.skipCSRF ? undefined : token,
          formAdapter: options?.formAdapter,
        });
        return result;
      } catch (err) {
        if (err instanceof ApiError) {
          if (err.status === 401 || err.unauthorized) {
            handleUnauthorized(err.redirect || "/login");
            throw new ApiError(
              t("Your session expired. Your input is still on this page. Sign in in another tab, then try again."),
              401,
              { unauthorized: true, redirect: err.redirect || "/login" },
            );
          }
          if (err.status === 403 && !options?.skipCSRF) {
            try {
              const freshToken = await fetchFreshCSRFToken();
              updateCSRFToken(freshToken);
              needsCSRFRefreshRef.current = false;
              setRefreshBanner(null);
              return await rawSubmitForm(action, fields, {
                csrfToken: freshToken,
                formAdapter: options?.formAdapter,
              });
            } catch (refreshErr) {
              if (refreshErr instanceof ApiError && (refreshErr.status === 401 || refreshErr.unauthorized)) {
                handleUnauthorized(refreshErr.redirect || "/login");
                throw new ApiError(
                  t("Your session expired. Your input is still on this page. Sign in in another tab, then try again."),
                  401,
                  { unauthorized: true, redirect: refreshErr.redirect || "/login" },
                );
              }
              needsCSRFRefreshRef.current = true;
              throw refreshErr;
            }
          }
          throw err;
        }
        if (err instanceof TypeError) {
          throw new ApiError(
            t("Connection lost. Your input has been kept, but the request may have reached the Master. Check the current state before submitting again."),
            0,
          );
        }
        throw err;
      } finally {
        inFlightRef.current = Math.max(0, inFlightRef.current - 1);
      }
    },
    [handleUnauthorized, offerRefresh, t, updateCSRFToken],
  );

  const changeLocale = useCallback(async (next: "en" | "zh-CN") => {
    const res = await switchLanguage(next);
    const normalized = res.locale === "zh-CN" ? "zh-CN" : "en";
    setLocale(normalized);
    document.documentElement.lang = normalized;
    setMessages(res.messages || {});
    setLocaleVersion((v) => v + 1);
  }, []);

  const value = useMemo<AppContextValue>(
    () => ({
      ready,
      locale,
      session,
      t,
      countLabel,
      changeLocale,
      refreshSession,
      updateCSRFToken,
      submitMutation,
      handleUnauthorized,
      setFormDirty,
      hasUnsavedChanges,
      refreshBanner,
      clearRefreshBanner,
      offerRefresh,
      appNotice,
      setAppNotice,
      localeVersion,
    }),
    [
      ready,
      locale,
      session,
      t,
      countLabel,
      changeLocale,
      refreshSession,
      updateCSRFToken,
      submitMutation,
      handleUnauthorized,
      setFormDirty,
      hasUnsavedChanges,
      refreshBanner,
      clearRefreshBanner,
      offerRefresh,
      appNotice,
      localeVersion,
    ],
  );

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};

export function useApp(): AppContextValue {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("useApp must be used inside AppProvider");
  return ctx;
}

export function useDirtyForm(key: string, dirty: boolean): void {
  const { setFormDirty } = useApp();
  useEffect(() => {
    setFormDirty(key, dirty);
    return () => setFormDirty(key, false);
  }, [key, dirty, setFormDirty]);
}
