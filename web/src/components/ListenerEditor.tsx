import React, { useEffect, useMemo, useState } from "react";
import type { EndpointView, ListenerOptionView } from "../api/types";
import { useApp } from "../context/AppContext";
import { SelectBox } from "./SelectBox";

export interface EndpointDraft {
  protocol: string;
  listen: string;
  listen_port: string;
  family: string;
  method: string;
  mux_enabled: string;
  mux_padding: string;
  mux_brutal: string;
  mux_brutal_up_mbps: string;
  mux_brutal_down_mbps: string;
  tls_mode: string;
  server_name: string;
  email: string;
  certificate_path: string;
  key_path: string;
  up_mbps: string;
  down_mbps: string;
  obfs_type: string;
}

export function endpointToDraft(ep?: EndpointView | null): EndpointDraft {
  return {
    protocol: ep?.Protocol || "anytls",
    listen: ep?.Listen || "::",
    listen_port: ep?.ListenPort ? String(ep.ListenPort) : "443",
    family: ep?.Family || "auto",
    method: ep?.Method || "2022-blake3-aes-128-gcm",
    mux_enabled: ep?.MuxEnabled ? "1" : "0",
    mux_padding: ep?.MuxPadding ? "1" : "0",
    mux_brutal: ep?.MuxBrutal ? "1" : "0",
    mux_brutal_up_mbps: ep?.MuxBrutalUpMbps ? String(ep.MuxBrutalUpMbps) : "",
    mux_brutal_down_mbps: ep?.MuxBrutalDownMbps ? String(ep.MuxBrutalDownMbps) : "",
    tls_mode: ep?.TLSMode || "self_signed",
    server_name: ep?.ServerName || "",
    email: ep?.Email || "",
    certificate_path: ep?.CertificatePath || "",
    key_path: ep?.KeyPath || "",
    up_mbps: ep?.UpMbps ? String(ep.UpMbps) : "",
    down_mbps: ep?.DownMbps ? String(ep.DownMbps) : "",
    obfs_type: ep?.ObfsType || "",
  };
}

export function endpointDraftToFields(d: EndpointDraft): Record<string, string> {
  return {
    protocol: d.protocol,
    listen: d.listen,
    listen_port: d.listen_port,
    family: d.family,
    method: d.method,
    mux_enabled: d.mux_enabled,
    mux_padding: d.mux_padding,
    mux_brutal: d.mux_brutal,
    mux_brutal_up_mbps: d.mux_brutal_up_mbps,
    mux_brutal_down_mbps: d.mux_brutal_down_mbps,
    tls_mode: d.tls_mode,
    server_name: d.server_name,
    email: d.email,
    certificate_path: d.certificate_path,
    key_path: d.key_path,
    up_mbps: d.up_mbps,
    down_mbps: d.down_mbps,
    obfs_type: d.obfs_type,
  };
}

function compatibilityFields(protocol: string): string[] {
  const fields = ["protocol", "listen", "port"];
  if (protocol === "reverse_wireguard") return fields;
  if (protocol === "shadowsocks") {
    return [...fields, "method", "muxPadding", "muxBrutal", "muxBrutalUp", "muxBrutalDown"];
  }
  fields.push("tlsMode", "serverName", "email", "certificatePath", "keyPath");
  if (protocol === "hysteria2") fields.push("upMbps", "downMbps", "obfsType");
  return fields;
}

function listenerClaims(agent: string, protocol: string, listen: string, port: number): string[] {
  const networks =
    protocol === "shadowsocks"
      ? ["TCP", "UDP"]
      : protocol === "hysteria2" || protocol === "reverse_wireguard"
        ? ["UDP"]
        : ["TCP"];
  return networks.map((network) => `${agent}/${network}/${listen}:${port}`);
}

function normalizeCandidate(d: EndpointDraft) {
  const tlsMode = d.tls_mode;
  return {
    protocol: d.protocol,
    listen: d.listen.trim(),
    port: Number(d.listen_port || 0),
    method: d.method,
    muxPadding: d.mux_padding === "1",
    muxBrutal: d.mux_brutal === "1",
    muxBrutalUp: Number(d.mux_brutal_up_mbps || 0),
    muxBrutalDown: Number(d.mux_brutal_down_mbps || 0),
    tlsMode,
    serverName: d.server_name.trim(),
    email: tlsMode === "acme" ? d.email.trim() : "",
    certificatePath: tlsMode === "files" ? d.certificate_path.trim() : "",
    keyPath: tlsMode === "files" ? d.key_path.trim() : "",
    upMbps: Number(d.up_mbps || 0),
    downMbps: Number(d.down_mbps || 0),
    obfsType: d.obfs_type,
  };
}

function listenerToNormalized(item: ListenerOptionView) {
  return {
    protocol: item.Protocol,
    listen: item.Listen,
    port: item.ListenPort,
    method: item.Method,
    muxPadding: item.MuxPadding,
    muxBrutal: item.MuxBrutal,
    muxBrutalUp: item.MuxBrutalUp,
    muxBrutalDown: item.MuxBrutalDown,
    tlsMode: item.TLSMode,
    serverName: item.ServerName,
    email: item.TLSMode === "acme" ? item.Email : "",
    certificatePath: item.TLSMode === "files" ? item.CertificatePath : "",
    keyPath: item.TLSMode === "files" ? item.KeyPath : "",
    upMbps: item.UpMbps,
    downMbps: item.DownMbps,
    obfsType: item.ObfsType,
  };
}

const FIELD_LABELS: Record<string, string> = {
  protocol: "protocol",
  method: "Shadowsocks method",
  muxPadding: "multiplex padding",
  muxBrutal: "TCP Brutal",
  muxBrutalUp: "TCP Brutal upload rate",
  muxBrutalDown: "TCP Brutal download rate",
  tlsMode: "certificate mode",
  serverName: "TLS certificate domain/IP",
  email: "ACME email",
  certificatePath: "certificate path",
  keyPath: "private-key path",
  upMbps: "Hysteria2 upload rate",
  downMbps: "Hysteria2 download rate",
  obfsType: "Hysteria2 obfuscation",
};

interface ListenerEditorProps {
  value: EndpointDraft;
  onChange: (next: EndpointDraft) => void;
  agentId: string;
  parentAgentId?: string;
  allowReverse?: boolean;
  reverseOnlyDestination?: boolean;
  currentListenerId?: string;
  catalog: ListenerOptionView[];
  showFamilyAndMux?: boolean;
  onConflictChange?: (conflict: string) => void;
}

export const ListenerEditor: React.FC<ListenerEditorProps> = ({
  value,
  onChange,
  agentId,
  parentAgentId = "",
  allowReverse = false,
  reverseOnlyDestination = false,
  currentListenerId = "",
  catalog,
  showFamilyAndMux = true,
  onConflictChange,
}) => {
  const { t, locale } = useApp();
  const isReverse = allowReverse ? reverseOnlyDestination : value.protocol === "reverse_wireguard";

  // Automatically enforce reverse_wireguard when destination is reverse-only.
  useEffect(() => {
    if (!allowReverse) return;
    if (reverseOnlyDestination && value.protocol !== "reverse_wireguard") {
      onChange({
        ...value,
        protocol: "reverse_wireguard",
        listen: "::",
        listen_port: Number(value.listen_port) < 1024 ? "51820" : value.listen_port,
      });
    } else if (!reverseOnlyDestination && value.protocol === "reverse_wireguard") {
      onChange({
        ...value,
        protocol: "anytls",
      });
    }
  }, [allowReverse, reverseOnlyDestination]);

  const ownerAgent = value.protocol === "reverse_wireguard" ? parentAgentId || agentId : agentId;

  const availablePresets = useMemo(
    () =>
      catalog.filter(
        (item) =>
          item.AgentID === ownerAgent &&
          (item.Protocol === "reverse_wireguard") === isReverse &&
          (item.TLSMode !== "files" || item.ID === currentListenerId),
      ),
    [catalog, ownerAgent, isReverse, currentListenerId],
  );

  const [selectedPresetId, setSelectedPresetId] = useState<string>("manual");

  // Keep preset selection aligned when ownerAgent or reverse mode changes.
  useEffect(() => {
    if (selectedPresetId !== "manual" && !availablePresets.some((p) => p.ID === selectedPresetId)) {
      setSelectedPresetId("manual");
    }
  }, [availablePresets, selectedPresetId]);

  const selectedPreset = useMemo(
    () => availablePresets.find((p) => p.ID === selectedPresetId) || null,
    [availablePresets, selectedPresetId],
  );

  const applyPreset = (presetId: string) => {
    setSelectedPresetId(presetId);
    const preset = availablePresets.find((p) => p.ID === presetId);
    if (!preset) return;
    onChange({
      ...value,
      protocol: preset.Protocol,
      listen: preset.Listen,
      listen_port: String(preset.ListenPort),
      method: preset.Method || value.method,
      mux_padding: preset.MuxPadding ? "1" : "0",
      mux_brutal: preset.MuxBrutal ? "1" : "0",
      mux_brutal_up_mbps: preset.MuxBrutalUp ? String(preset.MuxBrutalUp) : "",
      mux_brutal_down_mbps: preset.MuxBrutalDown ? String(preset.MuxBrutalDown) : "",
      tls_mode: preset.TLSMode || value.tls_mode,
      server_name: preset.ServerName || "",
      email: preset.Email || "",
      certificate_path: preset.CertificatePath || "",
      key_path: preset.KeyPath || "",
      up_mbps: preset.UpMbps ? String(preset.UpMbps) : "",
      down_mbps: preset.DownMbps ? String(preset.DownMbps) : "",
      obfs_type: preset.ObfsType || "",
    });
  };

  const statusInfo = useMemo(() => {
    if (selectedPreset) {
      return {
        kind: "compatible" as const,
        title: "",
        message: t("Using the existing physical listener keeps all shared settings consistent."),
        conflict: "",
      };
    }
    const candidate = normalizeCandidate(value);
    if (!ownerAgent || !candidate.listen || !candidate.port) {
      return {
        kind: "" as const,
        title: "",
        message: t("Select an Agent and complete the socket to check availability."),
        conflict: "",
      };
    }
    const claims = new Set(listenerClaims(ownerAgent, candidate.protocol, candidate.listen, candidate.port));
    const others = catalog.filter((preset) => preset.AgentID === ownerAgent && preset.ID !== currentListenerId);
    const fields = compatibilityFields(candidate.protocol);

    const compatible = others.find((preset) => {
      const other = listenerToNormalized(preset);
      if (other.protocol !== candidate.protocol) return false;
      return fields.every(
        (field) => String((candidate as Record<string, unknown>)[field] ?? "") === String((other as Record<string, unknown>)[field] ?? ""),
      );
    });
    if (compatible) {
      return {
        kind: "compatible" as const,
        title: t("Listener available"),
        message:
          locale === "zh-CN"
            ? `与“${compatible.Label}”完全兼容，可直接在上方选择并复用。`
            : `Fully compatible with “${compatible.Label}”. Select it above to reuse the listener.`,
        conflict: "",
      };
    }

    const conflict = others.find(
      (preset) =>
        listenerClaims(ownerAgent, preset.Protocol, preset.Listen, preset.ListenPort).some((c) => claims.has(c)) ||
        (candidate.port === preset.ListenPort &&
          (candidate.protocol === "reverse_wireguard" || preset.Protocol === "reverse_wireguard") &&
          candidate.protocol !== "anytls" &&
          preset.Protocol !== "anytls"),
    );
    if (conflict) {
      const other = listenerToNormalized(conflict);
      const diffs =
        candidate.protocol === other.protocol
          ? fields
              .filter(
                (field) =>
                  field !== "listen" &&
                  field !== "port" &&
                  String((candidate as Record<string, unknown>)[field] ?? "") !==
                    String((other as Record<string, unknown>)[field] ?? ""),
              )
              .map((field) => t(FIELD_LABELS[field] || field))
          : [t("protocol")];
      const fieldList = diffs.join(locale === "zh-CN" ? "、" : ", ");
      const msg =
        locale === "zh-CN"
          ? `“${conflict.Label}”已使用同一监听地址与端口，但${fieldList}不同。请复用该监听器，或更换地址/端口。`
          : `“${conflict.Label}” uses the same socket, but these settings differ: ${fieldList}. Reuse that listener or choose another address or port.`;
      return {
        kind: "conflict" as const,
        title: t("Listener conflict"),
        message: msg,
        conflict: msg,
      };
    }

    const current = catalog.find((preset) => preset.ID === currentListenerId && preset.AgentID === ownerAgent);
    if (current && current.ReferenceCount > 1) {
      return {
        kind: "warning" as const,
        title: t("Shared listener"),
        message:
          locale === "zh-CN"
            ? `该监听器由 ${current.ReferenceCount} 个配置共享；保存后会同步更新全部引用。`
            : `This listener is shared by ${current.ReferenceCount} configurations. Saving updates every reference together.`,
        conflict: "",
      };
    }
    if (current) {
      return {
        kind: "compatible" as const,
        title: t("Listener ready"),
        message: t("Saving will update this physical listener atomically."),
        conflict: "",
      };
    }
    return {
      kind: "compatible" as const,
      title: t("Listener ready"),
      message: t("This socket is available for a new physical listener."),
      conflict: "",
    };
  }, [selectedPreset, value, ownerAgent, catalog, currentListenerId, locale, t]);

  useEffect(() => {
    onConflictChange?.(statusInfo.conflict);
  }, [statusInfo.conflict, onConflictChange]);

  const protocolOptions = useMemo(() => {
    const opts = [
      { value: "shadowsocks", label: "Shadowsocks 2022", disabled: allowReverse && isReverse, hidden: allowReverse && isReverse },
      { value: "anytls", label: "AnyTLS", disabled: allowReverse && isReverse, hidden: allowReverse && isReverse },
      { value: "hysteria2", label: "Hysteria2", disabled: allowReverse && isReverse, hidden: allowReverse && isReverse },
    ];
    if (allowReverse || value.protocol === "reverse_wireguard") {
      opts.push({
        value: "reverse_wireguard",
        label: t("Reverse WireGuard + SOCKS5"),
        disabled: allowReverse && !isReverse,
        hidden: allowReverse && !isReverse,
      });
    }
    return opts;
  }, [allowReverse, isReverse, value.protocol, t]);

  const showTLS = value.protocol === "anytls" || value.protocol === "hysteria2";
  const showSS = value.protocol === "shadowsocks";
  const showHy2 = value.protocol === "hysteria2";
  const showRevWG = value.protocol === "reverse_wireguard";

  return (
    <>
      <div className="proxy-listener-editor">
        <div className="proxy-listener-picker">
          <label className="field">
            <span>{t("Physical listener")}</span>
            <SelectBox
              value={selectedPresetId}
              onChange={applyPreset}
              options={[
                { value: "manual", label: t("Configure manually") },
                ...availablePresets.map((p) => ({ value: p.ID, label: p.Label })),
              ]}
            />
          </label>
          <div
            className={`proxy-listener-status ${statusInfo.kind ? `is-${statusInfo.kind}` : ""}`}
            role="status"
            aria-live="polite"
          >
            <span className="proxy-listener-status__copy">
              {statusInfo.title && <strong>{statusInfo.title}</strong>}
              <span>{statusInfo.message}</span>
            </span>
          </div>
        </div>

        {selectedPreset && (
          <div className="proxy-listener-summary">
            <strong>
              {selectedPreset.ProtocolLabel} {t("on")} {selectedPreset.Listen}:{selectedPreset.ListenPort}
            </strong>
            <span>
              {selectedPreset.Protocol === "reverse_wireguard"
                ? t("Parent WireGuard UDP port")
                : selectedPreset.Protocol === "shadowsocks"
                  ? selectedPreset.Method.replace("2022-blake3-", "")
                  : `${selectedPreset.TLSMode.replace("_", "-")} · ${selectedPreset.ServerName || t("TLS certificate domain/IP pending")}`}
              {" · "}
              {locale === "zh-CN"
                ? `由 ${selectedPreset.ReferenceCount} 个逻辑引用共享`
                : `shared by ${selectedPreset.ReferenceCount} logical reference${selectedPreset.ReferenceCount === 1 ? "" : "s"}`}
            </span>
          </div>
        )}

        {!selectedPreset && (
          <div className="stack" data-proxy-listener-fields="">
            <div className="builder-fields">
              <label className="field">
                <span>{t("Protocol")}</span>
                <SelectBox
                  searchable={false}
                  value={value.protocol}
                  onChange={(protocol) => onChange({ ...value, protocol })}
                  options={protocolOptions}
                />
              </label>
              <label className="field">
                <span>{t("Listen address")}</span>
                <input
                  value={value.listen}
                  readOnly={showRevWG}
                  onChange={(e) => onChange({ ...value, listen: e.target.value })}
                  placeholder="::"
                  required
                />
              </label>
              <label className="field">
                <span>{t(showRevWG ? "Parent WireGuard UDP port" : "Listen port")}</span>
                <input
                  type="number"
                  min={showRevWG ? 1024 : 1}
                  max={65535}
                  value={value.listen_port}
                  onChange={(e) => onChange({ ...value, listen_port: e.target.value })}
                  required
                />
                <small>{t("Port 80 remains reserved for ACME.")}</small>
              </label>
            </div>

            {showRevWG && (
              <p className="help-text">
                {t("WireGuard listens on the parent Server's UDP port. SOCKS5 stays private on the child. UDP traffic uses UDP-over-TCP.")}
              </p>
            )}

            {showSS && (
              <fieldset className="builder-subsection">
                <legend>Shadowsocks 2022 listener</legend>
                <label className="field">
                  <span>{t("Method")}</span>
                  <SelectBox
                    searchable={false}
                    value={value.method}
                    onChange={(method) => onChange({ ...value, method })}
                    options={[
                      { value: "2022-blake3-aes-128-gcm", label: "AES-128-GCM" },
                      { value: "2022-blake3-aes-256-gcm", label: "AES-256-GCM" },
                      { value: "2022-blake3-chacha20-poly1305", label: "ChaCha20-Poly1305" },
                    ]}
                  />
                </label>
              </fieldset>
            )}

            {showTLS && (
              <fieldset className="builder-subsection">
                <legend>{t("TLS listener")}</legend>
                <div className="builder-fields">
                  <label className="field">
                    <span>{t("Certificate mode")}</span>
                    <SelectBox
                      searchable={false}
                      value={value.tls_mode}
                      onChange={(tls_mode) => onChange({ ...value, tls_mode })}
                      options={[
                        { value: "acme", label: "ACME (Let's Encrypt)" },
                        { value: "self_signed", label: t("Self-signed by Agent") },
                        ...(value.tls_mode === "files"
                          ? [{ value: "files", label: t("Legacy file certificate"), hidden: true }]
                          : []),
                      ]}
                    />
                  </label>
                  <label className="field">
                    <span>{t("TLS Certificate Domain/IP")}</span>
                    <input
                      value={value.server_name}
                      onChange={(e) => onChange({ ...value, server_name: e.target.value })}
                      placeholder="proxy.example.com"
                      required={value.tls_mode === "acme" || value.tls_mode === "self_signed"}
                    />
                  </label>
                  {value.tls_mode === "acme" && (
                    <label className="field">
                      <span>{t("ACME email")}</span>
                      <input
                        type="email"
                        value={value.email}
                        onChange={(e) => onChange({ ...value, email: e.target.value })}
                        placeholder="admin@example.com"
                        required
                      />
                    </label>
                  )}
                </div>
              </fieldset>
            )}

            {showHy2 && (
              <fieldset className="builder-subsection">
                <legend>Hysteria2 listener</legend>
                <div className="builder-fields">
                  <label className="field">
                    <span>
                      {t("Upload Mbps")} <span className="field__optional">{t("Optional")}</span>
                    </span>
                    <input
                      type="number"
                      min={0}
                      max={1000000}
                      value={value.up_mbps}
                      onChange={(e) => onChange({ ...value, up_mbps: e.target.value })}
                    />
                  </label>
                  <label className="field">
                    <span>
                      {t("Download Mbps")} <span className="field__optional">{t("Optional")}</span>
                    </span>
                    <input
                      type="number"
                      min={0}
                      max={1000000}
                      value={value.down_mbps}
                      onChange={(e) => onChange({ ...value, down_mbps: e.target.value })}
                    />
                  </label>
                  <label className="field">
                    <span>{t("Obfuscation")}</span>
                    <SelectBox
                      searchable={false}
                      value={value.obfs_type}
                      onChange={(obfs_type) => onChange({ ...value, obfs_type })}
                      options={[
                        { value: "", label: t("Disabled") },
                        { value: "salamander", label: "Salamander" },
                        { value: "gecko", label: "Gecko" },
                      ]}
                    />
                  </label>
                </div>
              </fieldset>
            )}
          </div>
        )}
      </div>

      {showFamilyAndMux && (
        <div className="builder-fields proxy-link-options">
          <label className="field">
            <span>{t("Relay address family")}</span>
            <SelectBox
              searchable={false}
              value={value.family}
              onChange={(family) => onChange({ ...value, family })}
              options={[
                { value: "auto", label: t("Automatic") },
                { value: "ipv4", label: "IPv4" },
                { value: "ipv6", label: "IPv6" },
              ]}
            />
          </label>
          {showSS && (
            <fieldset className="builder-subsection proxy-link-options__mux">
              <legend>{t("Link multiplex")}</legend>
              <label className="field">
                <span>{t("Multiplex")}</span>
                <SelectBox
                  searchable={false}
                  value={value.mux_enabled}
                  onChange={(mux_enabled) => onChange({ ...value, mux_enabled })}
                  options={[
                    { value: "0", label: t("Disabled") },
                    { value: "1", label: t("Enabled (smux)") },
                  ]}
                />
              </label>
            </fieldset>
          )}
        </div>
      )}
    </>
  );
};
