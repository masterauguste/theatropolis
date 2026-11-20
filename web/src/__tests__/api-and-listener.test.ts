import { describe, expect, it, vi } from "vitest";
import { ApiError, fetchPage, submitForm } from "../api/client";
import { endpointDraftToFields, endpointToDraft } from "../components/ListenerEditor";
import { planDraftToFields, planToDraft } from "../components/MembershipPlanFields";

describe("SPA API client", () => {
  it("sends X-Theatropolis-SPA and Accept JSON headers for page loads", async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      const headers = init?.headers as Record<string, string>;
      expect(headers["X-Theatropolis-SPA"]).toBe("1");
      expect(headers.Accept).toBe("application/json");
      return new Response(JSON.stringify({ view: "servers", status: 200, locale: "en", data: { Title: "Servers" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const res = await fetchPage("/servers");
    expect(res.view).toBe("servers");
    expect(res.data.Title).toBe("Servers");
    vi.unstubAllGlobals();
  });

  it("handles 204 X-Theatropolis-Redirect without consuming one-time enrollment result", async () => {
    const fetchMock = vi.fn(async (_url: string, init?: RequestInit) => {
      const headers = init?.headers as Record<string, string>;
      expect(headers["X-Theatropolis-Form"]).toBe("1");
      return new Response(null, {
        status: 204,
        headers: { "X-Theatropolis-Redirect": "/servers/enrollment-result?id=one-time" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const res = await submitForm("/servers", { display_name: "edge" }, { csrfToken: "tok" });
    expect(res.status).toBe(204);
    expect(res.redirect).toBe("/servers/enrollment-result?id=one-time");
    vi.unstubAllGlobals();
  });

  it("propagates 401 unauthorized responses with redirect target", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ error: "unauthorized", redirect: "/login" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(fetchPage("/servers")).rejects.toMatchObject({
      name: "ApiError",
      status: 401,
      unauthorized: true,
      redirect: "/login",
    } satisfies Partial<ApiError>);
    vi.unstubAllGlobals();
  });

  it("propagates 409 validation errors with errorField", async () => {
    const fetchMock = vi.fn(async () =>
      new Response(JSON.stringify({ error: "Choose a different name.", errorField: "name", data: {} }), {
        status: 409,
        headers: { "Content-Type": "application/json" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await expect(submitForm("/users", { name: "alice" }, { csrfToken: "tok" })).rejects.toMatchObject({
      status: 409,
      message: "Choose a different name.",
      errorField: "name",
    });
    vi.unstubAllGlobals();
  });
});

describe("Endpoint and membership plan serialization", () => {
  it("maps EndpointView cleanly to exact Go form field names", () => {
    const draft = endpointToDraft({
      AllowReverse: true,
      ParentAgentID: "parent-1",
      AgentID: "child-1",
      ListenerID: "lst_1",
      Protocol: "reverse_wireguard",
      ProtocolLabel: "Reverse WireGuard",
      Listen: "::",
      ListenPort: 51820,
      Family: "ipv4",
      Method: "2022-blake3-aes-128-gcm",
      MuxEnabled: false,
      MuxPadding: false,
      MuxBrutal: false,
      MuxBrutalUpMbps: 0,
      MuxBrutalDownMbps: 0,
      TLSMode: "self_signed",
      ServerName: "",
      Email: "",
      CertificatePath: "",
      KeyPath: "",
      UpMbps: 0,
      DownMbps: 0,
      ObfsType: "",
    });
    const fields = endpointDraftToFields(draft);
    expect(fields.protocol).toBe("reverse_wireguard");
    expect(fields.listen).toBe("::");
    expect(fields.listen_port).toBe("51820");
    expect(fields.family).toBe("ipv4");
    expect(fields.mux_enabled).toBe("0");
  });

  it("maps membership plan drafts to exact Go field names", () => {
    const fields = planDraftToFields(
      planToDraft({
        QuotaMode: "limited",
        QuotaGiB: "100",
        ExpirationMode: "finite",
        SubscriptionValue: "30",
        SubscriptionUnit: "days",
        CanExtend: true,
        QuotaLabel: "100 GiB",
        UsageLabel: "0 B",
        ResetLabel: "",
        ResetAt: "",
        ExpirationLabel: "",
        ExpirationAt: "",
        StatusLabel: "Active",
        StatusClass: "active",
      }),
    );
    expect(fields).toEqual({
      quota_mode: "limited",
      monthly_quota_gib: "100",
      expiration_mode: "finite",
      subscription_value: "30",
      subscription_unit: "days",
    });
  });
});
