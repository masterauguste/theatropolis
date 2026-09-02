"use strict";

const t = (text) => window.theatropolisText?.(text) || text;

const configTextarea = document.getElementById("config-json");
const configurationForm = configTextarea?.closest("form");
const configurationEditor = configurationForm?.closest(".configuration-panel");

if (configTextarea && configurationForm && configurationEditor) {
  const editable = !configTextarea.readOnly;
  const guidedPanel = configurationForm.querySelector('[data-config-panel="guided"]');
  const advancedPanel = configurationForm.querySelector('[data-config-panel="advanced"]');
  const warning = configurationForm.querySelector("[data-guided-warning]");
  const summary = configurationForm.querySelector("[data-config-summary]");
  const inboundList = configurationEditor.querySelector("[data-inbound-list]");
  const routeRuleList = configurationEditor.querySelector("[data-route-rule-list]");
  const routeFinal = configurationEditor.querySelector("[data-route-final]");
  const poolRoutingWarning = configurationEditor.querySelector("[data-pool-routing-warning]");
  const inboundTemplate = document.getElementById("inbound-card-template");
  const userTemplate = document.getElementById("user-row-template");
  const routeRuleTemplate = document.getElementById("route-rule-card-template");
  const originals = new WeakMap();
  const supportedInboundTypes = new Set(["shadowsocks", "anytls", "hysteria2"]);
  const managedSelfSignedPrefix = "certificates/theatropolis-self-signed/";
  const routeMatchFields = [
    "protocol",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "domain_regex",
    "ip_cidr",
    "rule_set",
    "network",
  ];
  let documentModel = {};
  // Every rule stores its match values independently of the combobox input.
  // Geo catalogs are fetched once per page and shared between rule cards.
  const matchSelections = new WeakMap();
  const geoOptionState = new Map();
  const geoOptionValues = new Map();
  const GEO_OPTION_RENDER_LIMIT = 50;
  const ruleSetOptionsBase = (configurationForm.getAttribute("action") || "")
    .replace(/\/configuration$/, "/rule-set-options");
  // Pool import picker state: the entry catalog is fetched lazily, once per
  // page load, and shared by every pool outbound card.
  const poolOptionsBase = (configurationForm.getAttribute("action") || "")
    .replace(/\/configuration$/, "/pool-options");
  const POOL_FAMILIES = ["ipv4", "ipv6"];
  let poolOptionState = ""; // "" | "loading" | "ok" | "error"
  let poolOptionValues = [];
  let draggedRule = null;

  function updateResourceCounts() {
    const counts = {
      inbound: inboundList.querySelectorAll("[data-inbound-card]").length,
      "route-rule": routeRuleList.querySelectorAll("[data-route-rule-card]").length,
    };
    for (const [name, count] of Object.entries(counts)) {
      const output = configurationEditor.querySelector(`[data-resource-count="${name}"]`);
      if (output) {
        output.textContent = window.theatropolisLocale === "zh-CN" ? `已配置 ${count} 项` : `${count} configured`;
      }
    }
  }

  function reportInvalidManagedResource() {
    const controls = configurationEditor.querySelectorAll(
      ".resource-modal input, .resource-modal select, .resource-modal textarea",
    );
    for (const control of controls) {
      if (control.disabled || control.checkValidity()) {
        continue;
      }
      const dialog = control.closest("dialog");
      const card = control.closest(".builder-card");
      if (card) setCardEditing(card, true);
      if (dialog instanceof HTMLDialogElement && !dialog.open) {
        dialog.showModal();
      }
      window.theatropolisShowValidation?.(control);
      return true;
    }
    return false;
  }

  const clone = (value) => JSON.parse(JSON.stringify(value));
  const objectValue = (value) => value && typeof value === "object" && !Array.isArray(value);
  const listValue = (value) => Array.isArray(value) ? value : [];
  const field = (card, group, name) => card.querySelector(`[data-${group}-field="${name}"]`);
  const splitValues = (value) => value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
  const setWarning = (message) => {
    warning.hidden = !message;
    warning.textContent = message || "";
  };
  const setValue = (element, value) => {
    if (element) {
      element.value = value === undefined || value === null ? "" : String(value);
    }
  };
  const randomSecret = (length, urlSafe = false) => {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    let encoded = btoa(String.fromCharCode(...bytes));
    if (urlSafe) {
      encoded = encoded.replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    }
    return encoded;
  };
  const base64url = (value) => btoa(value).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
  // Decoded byte length of a base64 key, accepting url-safe alphabets and
  // missing padding; -1 when the value is not valid base64 at all.
  const base64ByteLength = (value) => {
    const normalized = value.trim().replaceAll("-", "+").replaceAll("_", "/");
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) return -1;
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    try {
      return atob(padded).length;
    } catch {
      return -1;
    }
  };
  const safeTagPart = (value) => value.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/^-+|-+$/g, "") || "inbound";
  const selfSignedID = (tag, serverName) => {
    const text = `${String(tag || "inbound")}\u0000${String(serverName || "")}`;
    let hash = 2166136261;
    for (let index = 0; index < text.length; index += 1) {
      hash ^= text.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return `${safeTagPart(tag || "inbound").slice(0, 64)}-${(hash >>> 0).toString(16).padStart(8, "0")}`;
  };
  const selfSignedPaths = (tag, serverName) => {
    const id = selfSignedID(tag, serverName);
    return {
      certificate: `${managedSelfSignedPrefix}${id}/certificate.pem`,
      key: `${managedSelfSignedPrefix}${id}/private-key.pem`,
    };
  };
  const isManagedSelfSignedTLS = (tls) => {
    if (!objectValue(tls)) return false;
    const certificatePath = String(tls.certificate_path || "");
    const keyPath = String(tls.key_path || "");
    return certificatePath.startsWith(managedSelfSignedPrefix) &&
      keyPath.startsWith(managedSelfSignedPrefix);
  };

  function disableWhenReadonly(root) {
    if (editable) {
      return;
    }
    for (const control of root.querySelectorAll("input, select, textarea, button")) {
      if (control.matches("[data-copy-uri], [data-edit-card]")) {
        continue;
      }
      control.disabled = true;
    }
  }

  function addUser(card, user = {}) {
    const row = userTemplate.content.firstElementChild.cloneNode(true);
    setValue(field(row, "user", "name"), user.name);
    setValue(field(row, "user", "password"), user.password);
    card.querySelector("[data-user-list]").append(row);
    disableWhenReadonly(row);
    return row;
  }

  function buildShareURI(card, row) {
    const type = field(card, "inbound", "type").value;
    const port = field(card, "inbound", "listen_port").value;
    const tag = field(card, "inbound", "tag").value || "inbound";
    const userName = field(row, "user", "name").value || "user";
    const password = field(row, "user", "password").value;
    const tlsMode = field(card, "inbound", "tls_mode").value;
    const tlsDomain = field(card, "inbound", "tls_domain").value;
    const address = row.querySelector("[data-share-family]")?.value || "";
    if (!address) return null;
    const host = address.includes(":") ? `[${address}]` : address;
    const insecure = tlsMode === "acme" ? "0" : "1";
    const label = encodeURIComponent(tag + " - " + userName);
    if (type === "anytls") {
      const params = (tlsDomain ? "sni=" + encodeURIComponent(tlsDomain) + "&" : "") + "insecure=" + insecure;
      return "anytls://" + encodeURIComponent(password) + "@" + host + ":" + port + "?" + params + "#" + label;
    }
    if (type === "hysteria2") {
      var params = "insecure=" + insecure;
      if (tlsDomain) params += "&sni=" + encodeURIComponent(tlsDomain);
      const obfsType = field(card, "inbound", "obfs_type").value;
      const obfsPassword = field(card, "inbound", "obfs_password").value;
      if (obfsType) {
        params += "&obfs=" + encodeURIComponent(obfsType) + "&obfs-password=" + encodeURIComponent(obfsPassword);
      }
      return "hysteria2://" + encodeURIComponent(password) + "@" + host + ":" + port + "?" + params + "#" + label;
    }
    if (type === "shadowsocks") {
      const method = field(card, "inbound", "method").value;
      const serverKey = field(card, "inbound", "password").value;
      // SIP022 multi-user format: base64url(method:serverPSK:userPSK).
      const credentials = serverKey ? method + ":" + serverKey + ":" + password : method + ":" + password;
      return "ss://" + base64url(credentials) + "@" + host + ":" + port + "#" + label;
    }
    return null;
  }

  function fallbackCopyText(value) {
    const textarea = document.createElement("textarea");
    textarea.value = value;
    textarea.setAttribute("readonly", "");
    textarea.style.position = "fixed";
    textarea.style.inset = "0 auto auto -9999px";
    document.body.append(textarea);
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    let copied = false;
    try {
      copied = document.execCommand("copy");
    } finally {
      textarea.remove();
    }
    return copied;
  }

  async function copyText(value) {
    if (window.isSecureContext && navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(value);
        return true;
      } catch (_) {
        // Some browsers expose Clipboard API but deny it by policy.
      }
    }
    return fallbackCopyText(value);
  }

  // The copy button holds an SVG icon, so swap the whole content and
  // restore it afterwards rather than touching textContent.
  function showCopyResult(button, copied) {
    const original = button.innerHTML;
    button.textContent = copied ? "✓" : "✗";
    window.setTimeout(() => {
      button.innerHTML = original;
    }, 1500);
  }

  function setCardEditing(card, editing) {
    const editor = card.querySelector("[data-card-editor]");
    const button = card.querySelector("[data-edit-card]");
    if (!editor || !button) return;
    card.classList.toggle("is-editing", editing);
    editor.hidden = !editing;
    button.textContent = editing ? t("Done") : t("Edit");
    button.setAttribute("aria-expanded", editing ? "true" : "false");
  }

  function updateCardSummary(card, title, meta) {
    card.querySelector("[data-card-title]").textContent = title;
    card.querySelector("[data-card-meta]").textContent = meta;
  }

  function findACMEProvider(inbound) {
    const providerTag = inbound?.tls?.certificate_provider;
    if (!providerTag) {
      return null;
    }
    return listValue(documentModel.certificate_providers).find(
      (provider) => provider?.tag === providerTag && provider?.type === "acme",
    ) || null;
  }

  // Shadowsocks 2022 keys are base64 PSKs whose decoded length must match the
  // method (16 bytes for aes-128, 32 otherwise). Flag mismatches via
  // setCustomValidity so the native form validation surfaces them.
  function validateSSKeys(card) {
    const serverKey = field(card, "inbound", "password");
    const userKeys = Array.from(card.querySelectorAll('[data-user-field="password"]'));
    if (field(card, "inbound", "type").value !== "shadowsocks") {
      serverKey.setCustomValidity("");
      for (const input of userKeys) input.setCustomValidity("");
      return;
    }
    const method = field(card, "inbound", "method").value;
    const expected = method === "2022-blake3-aes-128-gcm" ? 16 : 32;
    const hint = "2022-blake3-aes-128-gcm requires a 16-byte base64 key (32 for other methods).";
    const check = (input, label) => {
      const value = input.value.trim();
      // Empty values are left to the required attribute, if any.
      input.setCustomValidity(!value || base64ByteLength(value) === expected ? "" : `${label}: ${hint}`);
    };
    check(serverKey, t("Server key"));
    for (const input of userKeys) check(input, t("User key"));
  }

  function updateInboundVisibility(card) {
    const type = field(card, "inbound", "type").value;
    const tlsMode = field(card, "inbound", "tls_mode").value;
    // Each protocol has its own section in the card; only the active one is
    // shown, so protocol-foreign fields are never exposed.
    for (const section of card.querySelectorAll("[data-inbound-section]")) {
      section.hidden = section.dataset.inboundSection !== type;
    }
    // sing-box requires obfs.password whenever obfs is configured, so the
    // field is only shown (and required) once an obfs type is picked.
    const obfsEnabled = type === "hysteria2" && field(card, "inbound", "obfs_type").value !== "";
    card.querySelector("[data-obfs-password-field]").hidden = !obfsEnabled;
    field(card, "inbound", "obfs_password").required = obfsEnabled;
    card.querySelector("[data-users-hint]").textContent = type === "shadowsocks"
      ? t("Optional — the server key alone accepts one user. Keys are base64 PSKs sized to the method.")
      : t("At least one user is required.");
    const tlsFields = card.querySelector("[data-tls-fields]");
    tlsFields.hidden = type === "shadowsocks";
    for (const element of card.querySelectorAll("[data-acme-field]")) {
      element.hidden = type === "shadowsocks" || tlsMode !== "acme";
    }
    for (const element of card.querySelectorAll("[data-tls-domain-field]")) {
      element.hidden = type === "shadowsocks" ||
        (tlsMode !== "acme" && tlsMode !== "self_signed");
    }
    for (const element of card.querySelectorAll("[data-certificate-file-field]")) {
      element.hidden = type === "shadowsocks" || tlsMode !== "files";
    }
    for (const element of card.querySelectorAll("[data-self-signed-field]")) {
      element.hidden = type === "shadowsocks" || tlsMode !== "self_signed";
    }
    field(card, "inbound", "tls_domain").required =
      type !== "shadowsocks" && (tlsMode === "acme" || tlsMode === "self_signed");
    for (const input of card.querySelectorAll("[data-certificate-file-field] input")) {
      input.required = type !== "shadowsocks" && tlsMode === "files";
    }
    const serverPassword = field(card, "inbound", "password");
    serverPassword.required = type === "shadowsocks";
    const title = field(card, "inbound", "tag").value || t("New inbound");
    const port = field(card, "inbound", "listen_port").value || "no port";
    const users = card.querySelectorAll("[data-user-row]").length;
    updateCardSummary(card, title, `${type} · ${port} · ${users} user${users === 1 ? "" : "s"}`);
  }

  function addInbound(inbound = {}) {
    const card = inboundTemplate.content.firstElementChild.cloneNode(true);
    originals.set(card, clone(inbound));
    const type = supportedInboundTypes.has(inbound.type) ? inbound.type : "shadowsocks";
    setValue(field(card, "inbound", "type"), type);
    setValue(field(card, "inbound", "tag"), inbound.tag);
    setValue(field(card, "inbound", "listen"), inbound.listen || "::");
    setValue(field(card, "inbound", "listen_port"), inbound.listen_port);
    setValue(field(card, "inbound", "method"), inbound.method || "2022-blake3-aes-128-gcm");
    setValue(field(card, "inbound", "password"), inbound.password);
    setValue(field(card, "inbound", "up_mbps"), inbound.up_mbps);
    setValue(field(card, "inbound", "down_mbps"), inbound.down_mbps);
    setValue(field(card, "inbound", "obfs_type"), inbound.obfs?.type);
    setValue(field(card, "inbound", "obfs_password"), inbound.obfs?.password);
    const acme = findACMEProvider(inbound);
    const selfSigned = isManagedSelfSignedTLS(inbound.tls);
    setValue(
      field(card, "inbound", "tls_mode"),
      acme ? "acme" : selfSigned ? "self_signed" : "files",
    );
    setValue(
      field(card, "inbound", "tls_domain"),
      acme?.domain?.[0] || (selfSigned ? inbound.tls?.server_name : ""),
    );
    setValue(field(card, "inbound", "tls_email"), acme?.email);
    setValue(field(card, "inbound", "certificate_path"), inbound.tls?.certificate_path);
    setValue(field(card, "inbound", "key_path"), inbound.tls?.key_path);
    for (const user of listValue(inbound.users)) {
      addUser(card, user);
    }
    if (listValue(inbound.users).length === 0) {
      addUser(card);
    }
    inboundList.append(card);
    updateInboundVisibility(card);
    validateSSKeys(card);
    setCardEditing(card, !inbound.tag);
    disableWhenReadonly(card);
    refreshRoutingOptions();
    updateResourceCounts();
    return card;
  }

  function poolOptionLabel(entry) {
    if (entry.manual) {
      const name = entry.ref.replace(/^manual\//, "");
      return entry.remark ? `External · ${entry.remark} (${name})` : `External · ${name}`;
    }
    return `${entry.agent_name || entry.agent_id} · ${entry.inbound_tag} · ${entry.user || "unnamed user"}`;
  }

  function destinationKey(ref, family = "", server = "") {
    if (server) {
      return `pool/tls/${encodeURIComponent(server)}/${ref}`;
    }
    return `pool/${family || "manual"}/${ref}`;
  }

  function parseDestinationKey(value) {
    if (!value.startsWith("pool/")) return null;
    const remainder = value.slice(5);
    const separator = remainder.indexOf("/");
    if (separator < 0) return null;
    const family = remainder.slice(0, separator);
    let ref = remainder.slice(separator + 1);
    if (!ref) return null;
    let server = "";
    if (family === "tls") {
      const serverSeparator = ref.indexOf("/");
      if (serverSeparator < 0) return null;
      try {
        server = decodeURIComponent(ref.slice(0, serverSeparator));
      } catch {
        return null;
      }
      ref = ref.slice(serverSeparator + 1);
      if (!server || !ref) return null;
    }
    return {
      ref,
      family: POOL_FAMILIES.includes(family) ? family : "",
      server,
    };
  }

  function destinationOptions() {
    const options = [
      { value: "builtin/direct", label: t("Direct") },
      { value: "builtin/reject", label: t("Reject") },
    ];
    for (const entry of poolOptionValues) {
      const detail = [entry.type, entry.port ? `port ${entry.port}` : ""].filter(Boolean).join(" · ");
      if (entry.manual) {
        options.push({
          value: destinationKey(entry.ref),
          label: `${poolOptionLabel(entry)}${detail ? ` · ${detail}` : ""}`,
        });
        continue;
      }
      for (const family of POOL_FAMILIES) {
        const address = entry[family];
        options.push({
          value: destinationKey(entry.ref, family),
          label: `${poolOptionLabel(entry)} · ${family === "ipv4" ? "IPv4" : "IPv6"}${address ? ` ${address}` : " unavailable"}${detail ? ` · ${detail}` : ""}`,
          disabled: !address,
        });
      }
    }
    return options;
  }

  function replaceSelectOptions(select, options, selectedValue) {
    select.replaceChildren();
    for (const entry of options) {
      const option = document.createElement("option");
      option.value = entry.value;
      option.textContent = entry.label;
      option.disabled = Boolean(entry.disabled);
      select.append(option);
    }
    if (selectedValue && !options.some((entry) => entry.value === selectedValue)) {
      const saved = document.createElement("option");
      saved.value = selectedValue;
      saved.textContent = t("Saved pool destination");
      select.append(saved);
    }
    select.value = selectedValue || options[0]?.value || "";
  }

  function refreshDestinationOptions() {
    const options = destinationOptions();
    for (const select of configurationEditor.querySelectorAll(
      "[data-route-final], [data-route-field=\"destination\"]",
    )) {
      replaceSelectOptions(select, options, select.value);
    }
  }

  function ensurePoolOptions() {
    if (poolOptionState) return;
    poolOptionState = "loading";
    fetch(poolOptionsBase, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(async (response) => {
        if (!response.ok) throw new Error(`pool-options HTTP ${response.status}`);
        const body = await response.json();
        if (!body || !Array.isArray(body.options)) {
          throw new Error(body?.error || "pool-options returned no options");
        }
        poolOptionValues = body.options;
        poolOptionState = "ok";
        poolRoutingWarning.hidden = !body.warning;
        poolRoutingWarning.textContent = body.warning || "";
      })
      .catch(() => {
        poolOptionState = "error";
        poolRoutingWarning.hidden = false;
        poolRoutingWarning.textContent =
          t("The fleet outbound pool is unavailable. Direct and Reject remain usable.");
      })
      .finally(refreshDestinationOptions);
  }

  function matchSelection(card) {
    let selection = matchSelections.get(card);
    if (!selection) {
      selection = [];
      matchSelections.set(card, selection);
    }
    return selection;
  }

  // "geosite" when every rule_set tag is geosite-*, "geoip" likewise, else
  // null (mixed kinds, custom tags, or no rule_set at all).
  function inferGeoMatchKind(ruleSet) {
    if (!Array.isArray(ruleSet) || ruleSet.length === 0) return null;
    let kind = null;
    for (const tag of ruleSet) {
      const match = typeof tag === "string" && tag.match(/^(geosite|geoip)-(.+)$/);
      if (!match || (kind && match[1] !== kind)) return null;
      kind = match[1];
    }
    return kind;
  }

  function ensureGeoOptions(kind) {
    if (geoOptionState.has(kind)) return;
    geoOptionState.set(kind, "loading");
    fetch(`${ruleSetOptionsBase}?kind=${encodeURIComponent(kind)}`, {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
      .then(async (response) => {
        if (!response.ok) throw new Error(`rule-set-options HTTP ${response.status}`);
        const body = await response.json();
        if (!body || !Array.isArray(body.options)) {
          throw new Error(body?.error || "rule-set-options returned no options");
        }
        geoOptionValues.set(kind, body.options);
        geoOptionState.set(kind, "ok");
      })
      .catch(() => {
        geoOptionState.set(kind, "error");
      })
      .finally(() => {
        for (const card of routeRuleList.querySelectorAll("[data-route-rule-card]")) {
          if (field(card, "route", "match_type").value !== kind) continue;
          updateMatchHint(card);
          renderMatchOptions(card);
        }
      });
  }

  const matchPresets = {
    protocol: ["bittorrent", "dns", "dtls", "http", "quic", "rdp", "ssh", "stun", "tls"],
    network: ["tcp", "udp", "icmp"],
  };

  const matchLabels = {
    protocol: [t("Protocols"), t("Filter protocols or type a value…")],
    network: [t("Networks"), t("Filter networks…")],
    domain: [t("Exact domains"), t("Type a domain and press Enter…")],
    domain_suffix: [t("Domain suffixes"), t("Type a suffix and press Enter…")],
    domain_keyword: [t("Domain keywords"), t("Type a keyword and press Enter…")],
    domain_regex: [t("Domain expressions"), t("Type an expression and press Enter…")],
    ip_cidr: [t("IP addresses or CIDRs"), t("Type an IP or CIDR and press Enter…")],
    geosite: [t("Geosite rule sets"), t("Filter geosite rule sets…")],
    geoip: [t("GeoIP rule sets"), t("Filter GeoIP rule sets…")],
    rule_set: [t("Custom rule-set tags"), t("Type a rule-set tag and press Enter…")],
  };

  function updateMatchHint(card) {
    const type = field(card, "route", "match_type").value;
    const hint = card.querySelector("[data-route-match-hint]");
    if ((type === "geosite" || type === "geoip") && geoOptionState.get(type) === "error") {
      hint.textContent = t("The cached catalog is unavailable; type a valid rule-set name manually.");
      return;
    }
    hint.textContent = type === "domain" || type === "domain_suffix" ||
      type === "domain_keyword" || type === "domain_regex" || type === "ip_cidr" ||
      type === "rule_set"
      ? t("Press Enter after each value. Multiple values in one rule use OR semantics.")
      : type === "geosite" || type === "geoip"
        ? t("Choose one rule set.")
        : t("Choose one or more values. Multiple values in one rule use OR semantics.");
  }

  function renderMatchChips(card) {
    const container = card.querySelector("[data-route-match-chips]");
    container.replaceChildren();
    const type = field(card, "route", "match_type").value;
    if (type === "geosite" || type === "geoip") return;
    for (const value of matchSelection(card)) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "geo-chip";
      chip.dataset.routeMatchChip = value;
      chip.title = `Remove ${value}`;
      chip.append(document.createTextNode(value));
      const marker = document.createElement("span");
      marker.setAttribute("aria-hidden", "true");
      marker.textContent = "×";
      chip.append(marker);
      container.append(chip);
    }
  }

  function matchOptionValues(card) {
    const type = field(card, "route", "match_type").value;
    if (type === "geosite" || type === "geoip") {
      return geoOptionValues.get(type) || [];
    }
    return matchPresets[type] || [];
  }

  function renderMatchOptions(card) {
    const list = card.querySelector("[data-route-match-options]");
    if (list.hidden) return;
    const selection = matchSelection(card);
    const type = field(card, "route", "match_type").value;
    const inputValue = card.querySelector("[data-route-match-filter]").value.trim().toLowerCase();
    const filterValue = (type === "geosite" || type === "geoip") &&
      selection.length === 1 && inputValue === selection[0].toLowerCase()
      ? ""
      : inputValue;
    list.replaceChildren();
    const matches = matchOptionValues(card).filter(
      (value) => !filterValue || value.toLowerCase().includes(filterValue),
    );
    for (const value of matches.slice(0, GEO_OPTION_RENDER_LIMIT)) {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "geo-option";
      option.dataset.routeMatchOption = value;
      option.setAttribute("role", "option");
      option.setAttribute("aria-selected", String(selection.includes(value)));
      option.textContent = value;
      if (selection.includes(value)) option.classList.add("is-selected");
      const selectOption = (event) => {
        event.preventDefault();
        event.stopPropagation();
        addMatchChip(card, value);
        const selectedType = field(card, "route", "match_type").value;
        if (selectedType === "geosite" || selectedType === "geoip") {
          setMatchOptionsOpen(card, false);
        } else {
          const filter = card.querySelector("[data-route-match-filter]");
          filter.value = "";
          renderMatchOptions(card);
          filter.focus();
        }
      };
      // Commit on pointerdown, before focusing or scrolling a top-layer
      // popover can close it and cancel the later click. Click remains the
      // keyboard activation path for a focused option.
      option.addEventListener("pointerdown", selectOption);
      option.addEventListener("click", selectOption);
      list.append(option);
    }
    if (matches.length === 0 && filterValue) {
      const empty = document.createElement("span");
      empty.className = "geo-option geo-option--empty";
      empty.textContent = t("Press Enter to add this value");
      list.append(empty);
    }
  }

  function setMatchOptionsOpen(card, open) {
    const list = card.querySelector("[data-route-match-options]");
    const input = card.querySelector("[data-route-match-filter]");
    const control = card.querySelector(".route-match-control");
    if (open) {
      list.hidden = false;
      if (typeof list.showPopover === "function" && !list.matches(":popover-open")) {
        list.showPopover();
      }
      positionMatchOptions(card);
    } else {
      if (typeof list.hidePopover === "function" && list.matches(":popover-open")) {
        list.hidePopover();
      }
      list.hidden = true;
    }
    input.setAttribute("aria-expanded", String(open));
    control.classList.toggle("is-open", open);
  }

  function positionMatchOptions(card) {
    const list = card.querySelector("[data-route-match-options]");
    const trigger = card.querySelector(".route-match-trigger");
    const bounds = trigger.getBoundingClientRect();
    const viewportWidth = document.documentElement.clientWidth;
    const margin = 8;
    const gap = Number.parseFloat(
      getComputedStyle(document.documentElement).getPropertyValue("--select-menu-gap"),
    ) || 6;
    const width = Math.max(0, Math.min(bounds.width, viewportWidth - margin * 2));
    const availableBelow = window.innerHeight - bounds.bottom - margin;
    const availableAbove = bounds.top - margin;
    const maxHeight = Math.max(0, Math.min(224, Math.max(availableBelow, availableAbove)));
    list.style.width = `${width}px`;
    list.style.maxHeight = `${maxHeight}px`;
    list.style.left = `${Math.max(
      margin,
      Math.min(bounds.left, viewportWidth - width - margin),
    )}px`;
    if (availableBelow >= 144 || availableBelow >= availableAbove) {
      list.style.top = `${bounds.bottom + gap}px`;
      list.style.bottom = "auto";
    } else {
      list.style.top = "auto";
      list.style.bottom = `${window.innerHeight - bounds.top + gap}px`;
    }
  }

  function openMatchOptions(card) {
    setMatchOptionsOpen(card, true);
    renderMatchOptions(card);
  }

  function closeOpenMatchOptions() {
    for (const list of routeRuleList.querySelectorAll(
      "[data-route-match-options]:not([hidden])",
    )) {
      const card = list.closest("[data-route-rule-card]");
      if (card) setMatchOptionsOpen(card, false);
    }
  }

  function addMatchChip(card, rawValue) {
    const type = field(card, "route", "match_type").value;
    const value = rawValue.trim();
    const normalized = type === "geosite" || type === "geoip" ||
      type === "protocol" || type === "network"
      ? value.toLowerCase()
      : value;
    if (!normalized || normalized.length > 1024) return;
    if (type === "geosite" || type === "geoip") {
      const catalogValue = matchOptionValues(card).some(
        (option) => option.toLowerCase() === normalized,
      );
      if (!catalogValue && !/^[a-z0-9_-]+$/.test(normalized)) return;
    }
    const selection = matchSelection(card);
    if (type === "geosite" || type === "geoip") {
      selection.splice(0, selection.length, normalized);
      card.querySelector("[data-route-match-filter]").value = normalized;
    } else {
      if (selection.includes(normalized)) return;
      selection.push(normalized);
    }
    renderMatchChips(card);
    renderMatchOptions(card);
    updateRouteRuleVisibility(card);
  }

  function removeMatchChip(card, value) {
    const type = field(card, "route", "match_type").value;
    const selection = matchSelection(card);
    const index = selection.indexOf(value);
    if (index === -1) return;
    selection.splice(index, 1);
    if (type === "geosite" || type === "geoip") {
      card.querySelector("[data-route-match-filter]").value = "";
    }
    renderMatchChips(card);
    renderMatchOptions(card);
    updateRouteRuleVisibility(card);
  }

  function destinationFromOutbound(outbound) {
    if (!outbound) return "builtin/direct";
    if (outbound.type === "direct") return "builtin/direct";
    if (outbound.type === "block") return "builtin/reject";
    if (outbound.type === "theatropolis-pool-ref" && outbound.ref) {
      return destinationKey(
        outbound.ref,
        POOL_FAMILIES.includes(outbound.family) ? outbound.family : "",
        typeof outbound.server === "string" ? outbound.server : "",
      );
    }
    return "builtin/direct";
  }

  function replaceScopeOptions(card, preferred = "") {
    const type = field(card, "route", "scope_type").value;
    const wrapper = card.querySelector("[data-route-scope-value]");
    const select = field(card, "route", "scope_value");
    wrapper.hidden = type === "all";
    select.required = type !== "all";
    if (type === "all") return;
    card.querySelector("[data-route-scope-label]").textContent =
      type === "inbound" ? t("Inbound") : t("User");
    const values = new Set();
    for (const inbound of inboundList.querySelectorAll("[data-inbound-card]")) {
      if (type === "inbound") {
        const tag = field(inbound, "inbound", "tag").value.trim();
        if (tag) values.add(tag);
      } else {
        for (const row of inbound.querySelectorAll("[data-user-row]")) {
          const name = field(row, "user", "name").value.trim();
          if (name) values.add(name);
        }
      }
    }
    const options = Array.from(values).sort().map((value) => ({ value, label: value }));
    replaceSelectOptions(select, options, preferred || select.value);
  }

  function refreshRoutingOptions() {
    for (const card of routeRuleList.querySelectorAll("[data-route-rule-card]")) {
      replaceScopeOptions(card);
    }
    refreshDestinationOptions();
  }

  function addRouteRule(rule = {}, outboundByTag = new Map()) {
    const card = routeRuleTemplate.content.firstElementChild.cloneNode(true);
    originals.set(card, clone(rule));
    const scopeType = listValue(rule.auth_user).length
      ? "auth_user"
      : listValue(rule.inbound).length ? "inbound" : "all";
    const scopeValue = scopeType === "auth_user"
      ? listValue(rule.auth_user)[0]
      : scopeType === "inbound" ? listValue(rule.inbound)[0] : "";
    setValue(field(card, "route", "scope_type"), scopeType);
    const geoKind = inferGeoMatchKind(rule.rule_set);
    const configuredMatchType = routeMatchFields.find((name) => rule[name] !== undefined);
    const matchType = geoKind || configuredMatchType || (Object.keys(rule).length ? "none" : "protocol");
    setValue(field(card, "route", "match_type"), matchType);
    if (geoKind) {
      const tag = rule.rule_set[0];
      if (tag) matchSelection(card).push(tag.slice(geoKind.length + 1));
    } else {
      const values = Array.isArray(rule[matchType]) ? rule[matchType] : [rule[matchType]].filter(Boolean);
      matchSelection(card).push(...values.map(String));
    }
    routeRuleList.append(card);
    replaceScopeOptions(card, scopeValue);
    const destination = rule.action === "reject"
      ? "builtin/reject"
      : destinationFromOutbound(outboundByTag.get(rule.outbound));
    replaceSelectOptions(field(card, "route", "destination"), destinationOptions(), destination);
    if (geoKind) {
      card.querySelector("[data-route-match-filter]").value = matchSelection(card)[0] || "";
    }
    renderMatchChips(card);
    updateRouteRuleVisibility(card);
    disableWhenReadonly(card);
    updateResourceCounts();
    return card;
  }

  function updateRouteRuleVisibility(card) {
    const type = field(card, "route", "match_type").value;
    if (card.dataset.routeMatchType && card.dataset.routeMatchType !== type) {
      matchSelections.set(card, []);
      renderMatchChips(card);
      card.querySelector("[data-route-match-filter]").value = "";
    }
    card.dataset.routeMatchType = type;
    const matchControl = card.querySelector(".route-match-combobox");
    matchControl.hidden = type === "none";
    if (type === "none") {
      setMatchOptionsOpen(card, false);
    }
    const labels = matchLabels[type] || [t("Match values"), t("Type a value and press Enter…")];
    card.querySelector("[data-route-match-label]").textContent = labels[0];
    card.querySelector("[data-route-match-filter]").placeholder = labels[1];
    if (type === "geosite" || type === "geoip") {
      ensureGeoOptions(type);
    }
    replaceScopeOptions(card);
    if (type !== "none") {
      updateMatchHint(card);
      renderMatchOptions(card);
    }
    const values = matchSelection(card);
    const scopeType = field(card, "route", "scope_type").value;
    const scopeValue = field(card, "route", "scope_value").value;
    const scope = scopeType === "all" ? "all traffic" : `${scopeType.replace("_", " ")} ${scopeValue}`;
    const outbound = field(card, "route", "destination").selectedOptions[0]?.textContent ||
      "no outbound";
    updateCardSummary(
      card,
      type === "none" ? "All scoped traffic" : values[0] || `${type.replaceAll("_", " ")} rule`,
      type === "none"
        ? `${scope} · ${outbound}`
        : `${scope} · ${type.replaceAll("_", " ")} · ${outbound}`,
    );
  }

  function serializeUsers(card) {
    const users = [];
    for (const row of card.querySelectorAll("[data-user-row]")) {
      const name = field(row, "user", "name").value.trim();
      const password = field(row, "user", "password").value.trim();
      if (name || password) {
        users.push({ name, password });
      }
    }
    return users;
  }

  function serializeInbound(card, providers) {
    const inbound = clone(originals.get(card) || {});
    const type = field(card, "inbound", "type").value;
    inbound.type = type;
    inbound.tag = field(card, "inbound", "tag").value.trim();
    inbound.listen = field(card, "inbound", "listen").value.trim() || "::";
    inbound.listen_port = Number(field(card, "inbound", "listen_port").value);
    inbound.users = serializeUsers(card);
    for (const key of ["method", "password", "up_mbps", "down_mbps", "obfs", "tls"]) {
      delete inbound[key];
    }
    if (inbound.listen_port === 80) {
      throw new Error(t("Port 80 is reserved for ACME HTTP-01 and cannot be used by a proxy inbound."));
    }
    if ((type === "anytls" || type === "hysteria2") && inbound.users.length === 0) {
      throw new Error(`${inbound.tag || type} requires at least one user.`);
    }
    if (type === "shadowsocks") {
      inbound.method = field(card, "inbound", "method").value;
      inbound.password = field(card, "inbound", "password").value.trim();
      return inbound;
    }
    if (type === "hysteria2") {
      const up = Number(field(card, "inbound", "up_mbps").value);
      const down = Number(field(card, "inbound", "down_mbps").value);
      if (up > 0) inbound.up_mbps = up;
      if (down > 0) inbound.down_mbps = down;
      const obfsType = field(card, "inbound", "obfs_type").value;
      if (obfsType) {
        inbound.obfs = {
          type: obfsType,
          password: field(card, "inbound", "obfs_password").value,
        };
      }
    }
    const tlsMode = field(card, "inbound", "tls_mode").value;
    if (tlsMode === "acme") {
      const providerTag = `theatropolis-acme-${safeTagPart(inbound.tag)}`;
      providers.push({
        type: "acme",
        tag: providerTag,
        domain: [field(card, "inbound", "tls_domain").value.trim()],
        email: field(card, "inbound", "tls_email").value.trim(),
        provider: "letsencrypt",
        disable_tls_alpn_challenge: true,
      });
      inbound.tls = { enabled: true, certificate_provider: providerTag };
    } else if (tlsMode === "self_signed") {
      const serverName = field(card, "inbound", "tls_domain").value.trim();
      const paths = selfSignedPaths(inbound.tag, serverName);
      inbound.tls = {
        enabled: true,
        server_name: serverName,
        certificate_path: paths.certificate,
        key_path: paths.key,
      };
    } else {
      inbound.tls = {
        enabled: true,
        certificate_path: field(card, "inbound", "certificate_path").value.trim(),
        key_path: field(card, "inbound", "key_path").value.trim(),
      };
    }
    return inbound;
  }

  function buildManagedOutbounds(destinationKeys) {
    const outbounds = [
      { type: "direct", tag: "theatropolis-direct" },
      { type: "block", tag: "theatropolis-reject" },
    ];
    const tags = new Map([
      ["builtin/direct", "theatropolis-direct"],
      ["builtin/reject", "theatropolis-reject"],
    ]);
    let poolIndex = 0;
    for (const key of destinationKeys) {
      if (tags.has(key)) continue;
      const destination = parseDestinationKey(key);
      if (!destination) continue;
      const tag = `theatropolis-pool-${++poolIndex}`;
      const outbound = {
        type: "theatropolis-pool-ref",
        tag,
        ref: destination.ref,
      };
      if (destination.family) outbound.family = destination.family;
      if (destination.server) outbound.server = destination.server;
      outbounds.push(outbound);
      tags.set(key, tag);
    }
    return { outbounds, tags };
  }

  function serializeRouteRule(card, outboundTags) {
    const rule = clone(originals.get(card) || {});
    const matchType = field(card, "route", "match_type").value;
    for (const name of routeMatchFields) {
      delete rule[name];
    }
    delete rule.inbound;
    delete rule.auth_user;
    const scopeType = field(card, "route", "scope_type").value;
    const scopeValue = field(card, "route", "scope_value").value;
    if (scopeType === "inbound" && scopeValue) rule.inbound = [scopeValue];
    if (scopeType === "auth_user" && scopeValue) rule.auth_user = [scopeValue];
    const values = matchSelection(card);
    if (matchType !== "none" && values.length === 0) {
      throw new Error(t("Every routing rule needs at least one match value."));
    }
    if (matchType === "geosite" || matchType === "geoip") {
      // geosite/geoip are UI-level match types; the JSON field stays rule_set.
      rule.rule_set = values.map((name) => `${matchType}-${name}`);
    } else if (matchType !== "none") {
      rule[matchType] = values;
    }
    rule.action = "route";
    const destination = field(card, "route", "destination").value;
    rule.outbound = outboundTags.get(destination) || "theatropolis-direct";
    return rule;
  }

  function routeRuleNeedsSniff(rule) {
    if (["protocol", "client", "domain", "domain_suffix", "domain_keyword", "domain_regex"]
      .some((name) => rule[name] !== undefined)) {
      return true;
    }
    const ruleSets = listValue(rule.rule_set);
    return ruleSets.some((tag) => !String(tag).startsWith("geoip-"));
  }

  function routeRuleNeedsResolve(rule) {
    if (["ip_version", "ip_is_private", "ip_cidr", "geoip"]
      .some((name) => rule[name] !== undefined)) {
      return true;
    }
    const ruleSets = listValue(rule.rule_set);
    return ruleSets.some((tag) => !String(tag).startsWith("geosite-"));
  }

  function insertRouteMetadataActions(rules, templates = new Map()) {
    const normalized = [];
    let seenSniff = false;
    let seenResolve = false;
    for (const rule of rules) {
      if (routeRuleNeedsResolve(rule) && !seenResolve) {
        normalized.push(clone(templates.get("resolve") || { action: "resolve" }));
        seenResolve = true;
      }
      if (routeRuleNeedsSniff(rule) && !seenSniff) {
        normalized.push(clone(templates.get("sniff") || { action: "sniff" }));
        seenSniff = true;
      }
      normalized.push(rule);
    }
    return normalized;
  }

  function syncGuidedConfiguration() {
    const next = clone(documentModel);
    const unsupportedInbounds = listValue(next.inbounds).filter(
      (inbound) => !supportedInboundTypes.has(inbound?.type),
    );
    const providers = listValue(next.certificate_providers).filter(
      (provider) => !String(provider?.tag || "").startsWith("theatropolis-acme-"),
    );
    next.inbounds = [
      ...unsupportedInbounds,
      ...Array.from(inboundList.querySelectorAll("[data-inbound-card]"), (card) =>
        serializeInbound(card, providers)),
    ];
    if (providers.length) next.certificate_providers = providers;
    else delete next.certificate_providers;
    const route = objectValue(next.route) ? clone(next.route) : {};
    const destinationKeys = [
      routeFinal.value,
      ...Array.from(
        routeRuleList.querySelectorAll("[data-route-rule-card]"),
        (card) => field(card, "route", "destination").value,
      ),
    ];
    const managed = buildManagedOutbounds(destinationKeys);
    next.outbounds = managed.outbounds;
    const managedRules = Array.from(
      routeRuleList.querySelectorAll("[data-route-rule-card]"),
      (card) => serializeRouteRule(card, managed.tags),
    );
    const metadataActionTemplates = new Map();
    for (const rule of listValue(route.rules)) {
      if ((rule?.action === "sniff" || rule?.action === "resolve") &&
          !metadataActionTemplates.has(rule.action)) {
        metadataActionTemplates.set(rule.action, rule);
      }
    }
    route.rules = insertRouteMetadataActions(managedRules, metadataActionTemplates);
    // Rule sets are derived from the routing rules: every referenced
    // geosite-*/geoip-* tag gets a remote binary SRS entry (spreading the
    // original entry first so extras like download_detour survive), custom
    // non-SagerNet entries pass through, and unreferenced SagerNet entries
    // are dropped.
    const sagerNetURL = /SagerNet\/sing-geo(?:site|ip)\/rule-set\//;
    const referencedTags = new Set();
    for (const rule of route.rules) {
      for (const tag of listValue(rule.rule_set)) {
        if (/^(?:geosite|geoip)-.+$/.test(tag)) referencedTags.add(tag);
      }
    }
    const originalRuleSets = listValue(route.rule_set);
    const ruleSets = [];
    for (const tag of referencedTags) {
      const prefix = tag.startsWith("geoip-") ? "geoip" : "geosite";
      const original = originalRuleSets.find((entry) => entry?.tag === tag);
      ruleSets.push({
        ...(objectValue(original) ? original : {}),
        type: "remote",
        format: "binary",
        tag,
        url: `https://raw.githubusercontent.com/SagerNet/sing-${prefix}/rule-set/${tag}.srs`,
        update_interval: "1d",
      });
    }
    for (const entry of originalRuleSets) {
      if (!sagerNetURL.test(String(entry?.url || ""))) ruleSets.push(entry);
    }
    if (ruleSets.length) route.rule_set = ruleSets;
    else delete route.rule_set;
    route.final = managed.tags.get(routeFinal.value) || "theatropolis-direct";
    next.route = route;
    configTextarea.value = `${JSON.stringify(next, null, 2)}\n`;
    configTextarea.setCustomValidity("");
    documentModel = next;
    summary.textContent = window.theatropolisLocale === "zh-CN"
      ? `${next.inbounds.length} 个入站，${next.outbounds.length} 个出口，${managedRules.length} 条规则`
      : `${next.inbounds.length} inbound(s), ${next.outbounds.length} outbound(s), ${managedRules.length} rule(s)`;
    return next;
  }

  function renderModel(model) {
    if (!objectValue(model)) {
      throw new Error(t("The configuration root must be a JSON object."));
    }
    documentModel = clone(model);
    inboundList.replaceChildren();
    routeRuleList.replaceChildren();
    const unsupported = [];
    for (const inbound of listValue(documentModel.inbounds)) {
      if (supportedInboundTypes.has(inbound?.type)) {
        addInbound(inbound);
      } else {
        unsupported.push(inbound?.tag || inbound?.type || "unnamed");
      }
    }
    const outboundByTag = new Map(
      listValue(documentModel.outbounds).map((outbound) => [outbound?.tag, outbound]),
    );
    const route = objectValue(documentModel.route) ? documentModel.route : {};
    for (const rule of listValue(route.rules)) {
      if (rule?.action === "sniff" || rule?.action === "resolve") continue;
      addRouteRule(rule, outboundByTag);
    }
    replaceSelectOptions(
      routeFinal,
      destinationOptions(),
      destinationFromOutbound(outboundByTag.get(route.final)),
    );
    refreshRoutingOptions();
    ensurePoolOptions();
    if (unsupported.length) {
      setWarning(
        `Advanced-only inbounds are preserved unchanged: ${unsupported.join(", ")}. Edit them in Advanced JSON.`,
      );
    } else {
      setWarning("");
    }
    const visibleRouteRules = listValue(route.rules).filter(
      (rule) => rule?.action !== "sniff" && rule?.action !== "resolve",
    ).length;
    summary.textContent = window.theatropolisLocale === "zh-CN"
      ? `${listValue(documentModel.inbounds).length} 个入站，${listValue(documentModel.outbounds).length} 个出口，${visibleRouteRules} 条规则`
      : `${listValue(documentModel.inbounds).length} inbound(s), ${listValue(documentModel.outbounds).length} outbound(s), ${visibleRouteRules} rule(s)`;
    updateResourceCounts();
  }

  function switchMode(mode) {
    if ((mode === "advanced" && !advancedPanel.hidden) ||
        (mode === "guided" && !guidedPanel.hidden)) {
      return;
    }
    if (mode === "advanced") {
      try {
        syncGuidedConfiguration();
      } catch (error) {
        setWarning(error.message);
        return;
      }
    } else {
      try {
        renderModel(JSON.parse(configTextarea.value));
        configTextarea.setCustomValidity("");
      } catch (error) {
        configTextarea.setCustomValidity(error.message);
        advancedPanel.hidden = false;
        guidedPanel.hidden = true;
        for (const tab of configurationForm.querySelectorAll("[data-config-tab]")) {
          const active = tab.dataset.configTab === "advanced";
          tab.classList.toggle("is-active", active);
          tab.setAttribute("aria-selected", String(active));
        }
        configTextarea.focus();
        return;
      }
    }
    guidedPanel.hidden = mode !== "guided";
    advancedPanel.hidden = mode !== "advanced";
    for (const tab of configurationForm.querySelectorAll("[data-config-tab]")) {
      const active = tab.dataset.configTab === mode;
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    }
  }

  configurationEditor.addEventListener("click", (event) => {
    const matchTrigger = event.target.closest(".route-match-trigger");
    if (matchTrigger) {
      const card = matchTrigger.closest("[data-route-rule-card]");
      if (card) {
        card.querySelector("[data-route-match-filter]").focus();
        openMatchOptions(card);
      }
      return;
    }
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.configTab) {
      switchMode(button.dataset.configTab);
      return;
    }
    if (button.matches("[data-add-inbound]")) {
      addInbound({ type: "shadowsocks", listen: "::" });
    } else if (button.matches("[data-add-route-rule]")) {
      addRouteRule({});
      refreshRoutingOptions();
    } else if (button.matches("[data-route-match-chip]")) {
      const card = button.closest("[data-route-rule-card]");
      if (card) removeMatchChip(card, button.dataset.routeMatchChip);
    } else if (button.matches("[data-move-rule]")) {
      const card = button.closest("[data-route-rule-card]");
      if (!card) return;
      const sibling = button.dataset.moveRule === "up"
        ? card.previousElementSibling
        : card.nextElementSibling;
      if (!sibling) return;
      if (button.dataset.moveRule === "up") routeRuleList.insertBefore(card, sibling);
      else routeRuleList.insertBefore(sibling, card);
      card.focus({ preventScroll: true });
    } else if (button.matches("[data-remove-card]")) {
      const card = button.closest(".builder-card");
      const removedInbound = card?.matches("[data-inbound-card]");
      card?.remove();
      if (removedInbound) refreshRoutingOptions();
      updateResourceCounts();
    } else if (button.matches("[data-edit-card]")) {
      const card = button.closest(".builder-card");
      if (card) setCardEditing(card, !card.classList.contains("is-editing"));
    } else if (button.matches("[data-add-user]")) {
      const card = button.closest("[data-inbound-card]");
      addUser(card);
      updateInboundVisibility(card);
      refreshRoutingOptions();
    } else if (button.matches("[data-remove-user]")) {
      const card = button.closest("[data-inbound-card]");
      button.closest("[data-user-row]")?.remove();
      if (card) updateInboundVisibility(card);
      refreshRoutingOptions();
    } else if (button.matches("[data-generate-secret]")) {
      const card = button.closest("[data-inbound-card]");
      const name = button.dataset.generateSecret === "obfs" ? "obfs_password" : "password";
      const method = field(card, "inbound", "method").value;
      const length = name === "password" && method === "2022-blake3-aes-128-gcm" ? 16 : 32;
      field(card, "inbound", name).value = randomSecret(length);
    } else if (button.matches("[data-generate-user-secret]")) {
      const card = button.closest("[data-inbound-card]");
      const row = button.closest("[data-user-row]");
      const type = field(card, "inbound", "type").value;
      const method = field(card, "inbound", "method").value;
      const length = type === "shadowsocks" && method === "2022-blake3-aes-128-gcm" ? 16 : 32;
      field(row, "user", "password").value = randomSecret(length, type !== "shadowsocks");
    } else if (button.matches("[data-copy-uri]")) {
      const card = button.closest("[data-inbound-card]");
      const row = button.closest("[data-user-row]");
      const uri = buildShareURI(card, row);
      if (uri) {
        copyText(uri).then((copied) => showCopyResult(button, copied));
      }
    }
  });

  configurationEditor.addEventListener("input", (event) => {
    const card = event.target.closest("[data-inbound-card], [data-route-rule-card]");
    if (card?.matches("[data-inbound-card]")) {
      updateInboundVisibility(card);
      validateSSKeys(card);
      if (event.target.matches('[data-inbound-field="tag"], [data-user-field="name"]')) {
        refreshRoutingOptions();
      }
    }
    if (event.target.matches("[data-route-match-filter]") && card) {
      const type = field(card, "route", "match_type").value;
      if (type === "geosite" || type === "geoip") {
        const selection = matchSelection(card);
        if (
          selection.length &&
          event.target.value.trim().toLowerCase() !== selection[0].toLowerCase()
        ) {
          selection.splice(0, selection.length);
        }
      }
      updateRouteRuleVisibility(card);
      openMatchOptions(card);
    } else if (card?.matches("[data-route-rule-card]")) {
      updateRouteRuleVisibility(card);
    }
  });

  configurationEditor.addEventListener("change", (event) => {
    const inbound = event.target.closest("[data-inbound-card]");
    if (inbound) {
      updateInboundVisibility(inbound);
      validateSSKeys(inbound);
    }
    const routeRule = event.target.closest("[data-route-rule-card]");
    if (routeRule) updateRouteRuleVisibility(routeRule);
  });

  configurationEditor.addEventListener("focusin", (event) => {
    if (event.target.matches("[data-route-match-filter]")) {
      const card = event.target.closest("[data-route-rule-card]");
      if (card) openMatchOptions(card);
    }
  });

  configurationEditor.addEventListener("keydown", (event) => {
    if (!event.target.matches("[data-route-match-filter]")) return;
    const card = event.target.closest("[data-route-rule-card]");
    if (!card) return;
    if (event.key === "Enter") {
      event.preventDefault();
      addMatchChip(card, event.target.value);
      const type = field(card, "route", "match_type").value;
      if (type === "geosite" || type === "geoip") {
        setMatchOptionsOpen(card, false);
      } else {
        event.target.value = "";
        renderMatchOptions(card);
      }
    } else if (event.key === "Backspace" && event.target.value === "") {
      const selection = matchSelection(card);
      if (selection.length) removeMatchChip(card, selection[selection.length - 1]);
    } else if (event.key === "Escape") {
      event.preventDefault();
      setMatchOptionsOpen(card, false);
    }
  });

  document.addEventListener("click", (event) => {
    for (const list of routeRuleList.querySelectorAll("[data-route-match-options]:not([hidden])")) {
      const combobox = list.closest(".route-match-combobox");
      if (combobox && !combobox.contains(event.target)) {
        const card = combobox.closest("[data-route-rule-card]");
        if (card) setMatchOptionsOpen(card, false);
      }
    }
  });
  window.addEventListener("resize", closeOpenMatchOptions);
  document.addEventListener("scroll", (event) => {
    if (
      event.target instanceof Element &&
      event.target.matches("[data-route-match-options]")
    ) {
      return;
    }
    closeOpenMatchOptions();
  }, true);
  routeRuleList.closest("dialog")?.addEventListener("close", closeOpenMatchOptions);

  routeRuleList.addEventListener("dragstart", (event) => {
    const card = event.target.closest("[data-route-rule-card]");
    if (!editable || !card) {
      event.preventDefault();
      return;
    }
    draggedRule = card;
    card.classList.add("is-dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", "routing-rule");
  });

  routeRuleList.addEventListener("dragover", (event) => {
    if (!draggedRule) return;
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
    const target = event.target.closest("[data-route-rule-card]");
    if (!target || target === draggedRule) return;
    const bounds = target.getBoundingClientRect();
    const after = event.clientY > bounds.top + bounds.height / 2;
    routeRuleList.insertBefore(draggedRule, after ? target.nextElementSibling : target);
  });

  routeRuleList.addEventListener("drop", (event) => {
    if (draggedRule) event.preventDefault();
  });

  routeRuleList.addEventListener("dragend", () => {
    draggedRule?.classList.remove("is-dragging");
    draggedRule = null;
  });

  configurationForm.addEventListener("submit", (event) => {
    if (!advancedPanel.hidden) {
      try {
        const parsed = JSON.parse(configTextarea.value);
        if (!objectValue(parsed)) throw new Error(t("The configuration root must be a JSON object."));
        configTextarea.setCustomValidity("");
      } catch (error) {
        event.preventDefault();
        configTextarea.setCustomValidity(error.message);
        window.theatropolisShowValidation?.(configTextarea);
      }
      return;
    }
    if (reportInvalidManagedResource()) {
      event.preventDefault();
      return;
    }
    try {
      syncGuidedConfiguration();
    } catch (error) {
      event.preventDefault();
      setWarning(error.message);
      warning.scrollIntoView({ behavior: "smooth", block: "center" });
      window.setTimeout(() => {
        const submit = configurationForm.querySelector('[data-submit-label="Deploying…"]');
        if (submit) submit.disabled = false;
      }, 0);
    }
  });

  try {
    renderModel(JSON.parse(configTextarea.value));
  } catch (error) {
    setWarning(`Guided editing is unavailable for this JSON: ${error.message}`);
    guidedPanel.hidden = true;
    advancedPanel.hidden = false;
    for (const tab of configurationForm.querySelectorAll("[data-config-tab]")) {
      const active = tab.dataset.configTab === "advanced";
      tab.classList.toggle("is-active", active);
      tab.setAttribute("aria-selected", String(active));
    }
  }
}
