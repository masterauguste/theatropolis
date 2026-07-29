"use strict";

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
  const outboundList = configurationEditor.querySelector("[data-outbound-list]");
  const routeRuleList = configurationEditor.querySelector("[data-route-rule-list]");
  const routeFinal = configurationEditor.querySelector("[data-route-final]");
  const outboundTags = configurationForm.querySelector("[data-outbound-tags]");
  const inboundTemplate = document.getElementById("inbound-card-template");
  const userTemplate = document.getElementById("user-row-template");
  const outboundTemplate = document.getElementById("outbound-card-template");
  const routeRuleTemplate = document.getElementById("route-rule-card-template");
  const originals = new WeakMap();
  const supportedInboundTypes = new Set(["shadowsocks", "anytls", "hysteria2"]);
  const routeMatchFields = [
    "protocol",
    "domain",
    "domain_suffix",
    "domain_keyword",
    "ip_cidr",
    "rule_set",
    "network",
    "auth_user",
  ];
  let documentModel = {};
  // Per-card geo rule set selections (geosite/geoip match types) and the
  // lazily fetched option catalogs, keyed by kind ("geosite" / "geoip").
  const geoSelections = new WeakMap();
  const geoOptionState = new Map();
  const geoOptionValues = new Map();
  const GEO_OPTION_RENDER_LIMIT = 50;
  const ruleSetOptionsBase = (configurationForm.getAttribute("action") || "")
    .replace(/\/configuration$/, "/rule-set-options");
  // Pool import picker state: the entry catalog is fetched lazily, once per
  // page load, and shared by every pool outbound card.
  const poolOptionsBase = (configurationForm.getAttribute("action") || "")
    .replace(/\/configuration$/, "/pool-options");
  const POOL_REF_PATTERN = /^(?:agent\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/[A-Za-z0-9][A-Za-z0-9._-]{0,127}\/[A-Za-z0-9_][A-Za-z0-9._-]{0,127}|manual\/[A-Za-z0-9][A-Za-z0-9._-]{0,127})$/;
  // Address families a pool ref may pin. The guided editor is explicit-only
  // (IPv4 default); the master still accepts "auto"/absent on the wire for
  // backward compatibility with older saved configs.
  const POOL_FAMILIES = ["ipv4", "ipv6"];
  let poolOptionState = ""; // "" | "loading" | "ok" | "error"
  let poolOptionValues = [];

  function updateResourceCounts() {
    const counts = {
      inbound: inboundList.querySelectorAll("[data-inbound-card]").length,
      outbound: outboundList.querySelectorAll("[data-outbound-card]").length,
      "route-rule": routeRuleList.querySelectorAll("[data-route-rule-card]").length,
    };
    for (const [name, count] of Object.entries(counts)) {
      const output = configurationEditor.querySelector(`[data-resource-count="${name}"]`);
      if (output) {
        output.textContent = `${count} configured`;
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
      control.focus();
      control.reportValidity();
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
    const host = tlsMode === "acme" && tlsDomain ? tlsDomain : window.location.hostname;
    const insecure = tlsMode === "files" ? "1" : "0";
    const label = encodeURIComponent(tag + " - " + userName);
    if (type === "anytls") {
      return "anytls://" + encodeURIComponent(password) + "@" + host + ":" + port + "?sni=" + encodeURIComponent(host) + "&insecure=" + insecure + "#" + label;
    }
    if (type === "hysteria2") {
      var params = "insecure=" + insecure + "&sni=" + encodeURIComponent(host);
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
    button.textContent = editing ? "Done" : "Edit";
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
    check(serverKey, "Server key");
    for (const input of userKeys) check(input, "User key");
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
      ? "Optional — the server key alone accepts one user. Keys are base64 PSKs sized to the method."
      : "At least one user is required.";
    const tlsFields = card.querySelector("[data-tls-fields]");
    tlsFields.hidden = type === "shadowsocks";
    for (const element of card.querySelectorAll("[data-acme-field]")) {
      element.hidden = type === "shadowsocks" || tlsMode !== "acme";
    }
    for (const element of card.querySelectorAll("[data-certificate-file-field]")) {
      element.hidden = type === "shadowsocks" || tlsMode !== "files";
    }
    for (const input of card.querySelectorAll("[data-acme-field] input")) {
      input.required = type !== "shadowsocks" && tlsMode === "acme" && input.dataset.inboundField === "tls_domain";
    }
    for (const input of card.querySelectorAll("[data-certificate-file-field] input")) {
      input.required = type !== "shadowsocks" && tlsMode === "files";
    }
    const serverPassword = field(card, "inbound", "password");
    serverPassword.required = type === "shadowsocks";
    const title = field(card, "inbound", "tag").value || "New inbound";
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
    setValue(field(card, "inbound", "tls_mode"), acme ? "acme" : "files");
    setValue(field(card, "inbound", "tls_domain"), acme?.domain?.[0]);
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
    updateResourceCounts();
    return card;
  }

  function updateOutboundVisibility(card) {
    const kind = field(card, "outbound", "kind").value;
    card.querySelector("[data-external-outbound-field]").hidden = kind !== "external";
    card.querySelector("[data-pool-field]").hidden = kind !== "pool";
    card.querySelector("[data-pool-family]").hidden = kind !== "pool";
    field(card, "outbound", "json").required = kind === "external";
    let meta = kind === "external" ? "External JSON" : kind;
    if (kind === "pool") {
      ensurePoolOptions();
      updatePoolHint(card);
      syncPoolFamily(card);
      const ref = field(card, "outbound", "ref").value.trim();
      meta = "pool · " + (ref ? ref.replace(/^agent\//, "") : "no entry selected");
    }
    updateCardSummary(
      card,
      field(card, "outbound", "tag").value || "New outbound",
      meta,
    );
  }

  function addOutbound(outbound = {}) {
    const card = outboundTemplate.content.firstElementChild.cloneNode(true);
    originals.set(card, clone(outbound));
    const kind = outbound.type === "direct" || outbound.type === "block"
      ? outbound.type
      : outbound.type === "theatropolis-pool-ref" ? "pool" : "external";
    setValue(field(card, "outbound", "kind"), kind);
    setValue(field(card, "outbound", "tag"), outbound.tag);
    if (kind === "external") {
      setValue(field(card, "outbound", "json"), JSON.stringify(outbound, null, 2));
    }
    if (kind === "pool") {
      setValue(field(card, "outbound", "ref"), outbound.ref);
      // Explicit ipv4/ipv6 only. Anything else (legacy "auto", absent,
      // invalid) is resolved to a concrete default by syncPoolFamily once
      // the pool catalog knows the entry's families.
      const family = POOL_FAMILIES.includes(outbound.family) ? outbound.family : "";
      setValue(field(card, "outbound", "family"), family);
    }
    outboundList.append(card);
    updateOutboundVisibility(card);
    setCardEditing(card, !outbound.tag);
    disableWhenReadonly(card);
    updateOutboundTagOptions();
    updateResourceCounts();
    return card;
  }

  // Fetch the pool entry catalog once; failures are remembered so the hint
  // shows on every pool combobox and a free-text reference still works.
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
      })
      .catch(() => {
        poolOptionState = "error";
      })
      .finally(() => {
        for (const card of outboundList.querySelectorAll("[data-outbound-card]")) {
          if (field(card, "outbound", "kind").value !== "pool") continue;
          updatePoolHint(card);
          renderPoolOptions(card);
          syncPoolFamily(card);
        }
      });
  }

  // poolOptionByRef finds the catalog entry for a typed/picked reference.
  function poolOptionByRef(ref) {
    return poolOptionValues.find((entry) => entry.ref === ref) || null;
  }

  // syncPoolFamily reflects the hidden family input onto the segmented
  // control, disables families the selected entry has no address for,
  // defaults to IPv4 when available, and shows the probe button when the
  // wanted family is unknown. Manual entries resolve address-free, so the
  // whole control is hidden for them.
  function syncPoolFamily(card) {
    const input = field(card, "outbound", "family");
    if (!input) return;
    const probe = card.querySelector("[data-pool-probe]");
    const probeHint = card.querySelector("[data-pool-probe-hint]");
    const ref = field(card, "outbound", "ref").value.trim();
    const entry = poolOptionByRef(ref);
    if (entry && entry.manual) {
      card.querySelector("[data-pool-family]").hidden = true;
      probe.hidden = true;
      probeHint.hidden = true;
      probeHint.textContent = "";
      return;
    }
    card.querySelector("[data-pool-family]").hidden = false;
    let family = input.value;
    const known = {
      ipv4: !entry || Boolean(entry.ipv4),
      ipv6: !entry || Boolean(entry.ipv6),
    };
    if (!POOL_FAMILIES.includes(family) || !known[family]) {
      // Default to IPv4 when available, IPv6 when it is the only known
      // family, IPv4 (greyed) when nothing is known yet.
      family = known.ipv4 ? "ipv4" : known.ipv6 ? "ipv6" : "ipv4";
      input.value = family;
    }
    for (const option of card.querySelectorAll("[data-pool-family-option]")) {
      const value = option.dataset.poolFamilyOption;
      option.setAttribute("aria-pressed", String(value === family));
      option.disabled = !known[value];
      if (option.disabled) {
        option.title = "address family unknown";
      } else {
        option.removeAttribute("title");
      }
    }
    const canProbe = entry && !known[family];
    probe.hidden = !canProbe;
    if (canProbe) {
      probe.dataset.probeFamily = family;
    } else {
      probeHint.hidden = true;
      probeHint.textContent = "";
    }
  }

  function requestPoolProbe(card, button) {
    const entry = poolOptionByRef(field(card, "outbound", "ref").value.trim());
    const family = button.dataset.probeFamily;
    const hint = card.querySelector("[data-pool-probe-hint]");
    if (!entry || entry.manual || !family) return;
    const csrfToken = configurationForm.querySelector('input[name="csrf_token"]')?.value || "";
    button.disabled = true;
    fetch(`/servers/${encodeURIComponent(entry.agent_id)}/probe-address`, {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
      },
      body: new URLSearchParams({ family, csrf_token: csrfToken }),
    })
      .then(async (response) => {
        if (response.status === 202) {
          hint.hidden = false;
          hint.textContent = "probe requested — refresh in a few seconds";
          window.setTimeout(() => {
            // Bypass the once-per-load cache so the probed address shows up.
            poolOptionState = "";
            ensurePoolOptions();
          }, 5000);
          return;
        }
        const message = (await response.text()).trim();
        throw new Error(message || `probe request failed (HTTP ${response.status})`);
      })
      .catch((error) => {
        hint.hidden = false;
        hint.textContent = error.message;
      })
      .finally(() => {
        button.disabled = false;
      });
  }

  function updatePoolHint(card) {
    const hint = card.querySelector("[data-pool-hint]");
    const failed = poolOptionState === "error";
    hint.hidden = !failed;
    hint.textContent = failed
      ? "List unavailable — type a reference manually: agent/<id>/<inbound>/<user> or manual/<name>"
      : "";
  }

  function poolOptionLabel(entry) {
    if (entry.manual) return entry.ref;
    return `${entry.agent_id}/${entry.inbound_tag}/${entry.user || "unnamed user"}`;
  }

  function poolOptionDetail(entry) {
    const parts = [];
    if (entry.type) parts.push(entry.type);
    if (entry.port) parts.push(`port ${entry.port}`);
    if (!entry.manual) {
      parts.push(`v4 ${entry.ipv4 || "—"}`);
      parts.push(`v6 ${entry.ipv6 || "—"}`);
    }
    return parts.length ? " · " + parts.join(" · ") : "";
  }

  function renderPoolOptions(card) {
    const list = card.querySelector("[data-pool-options]");
    if (list.hidden) return;
    const refInput = field(card, "outbound", "ref");
    const filterValue = refInput.value.trim().toLowerCase();
    list.replaceChildren();
    const matches = poolOptionValues.filter((entry) => {
      if (!filterValue) return true;
      return entry.ref.toLowerCase().includes(filterValue) ||
        poolOptionLabel(entry).toLowerCase().includes(filterValue);
    });
    for (const entry of matches.slice(0, GEO_OPTION_RENDER_LIMIT)) {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "geo-option";
      option.dataset.poolOption = entry.ref;
      option.textContent = poolOptionLabel(entry) + poolOptionDetail(entry);
      if (!entry.available) {
        option.classList.add("is-unavailable");
        option.textContent += " — no usable address";
      }
      if (refInput.value.trim() === entry.ref) option.classList.add("is-selected");
      list.append(option);
    }
  }

  function openPoolOptions(card) {
    card.querySelector("[data-pool-options]").hidden = false;
    renderPoolOptions(card);
  }

  function geoSelection(card) {
    let selection = geoSelections.get(card);
    if (!selection) {
      selection = [];
      geoSelections.set(card, selection);
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

  // Fetch the rule set name catalog for a kind once; failures are remembered
  // so the hint shows on every combobox of that kind and free text still works.
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
          updateGeoHint(card);
          renderGeoOptions(card);
        }
      });
  }

  function updateGeoHint(card) {
    const hint = card.querySelector("[data-route-geo-hint]");
    const failed = geoOptionState.get(field(card, "route", "match_type").value) === "error";
    hint.hidden = !failed;
    hint.textContent = failed ? "List unavailable — type a name manually" : "";
  }

  function renderGeoChips(card) {
    const container = card.querySelector("[data-route-geo-chips]");
    container.replaceChildren();
    for (const name of geoSelection(card)) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = "geo-chip";
      chip.dataset.geoChip = name;
      chip.title = `Remove ${name}`;
      chip.append(document.createTextNode(name));
      const marker = document.createElement("span");
      marker.setAttribute("aria-hidden", "true");
      marker.textContent = "×";
      chip.append(marker);
      container.append(chip);
    }
  }

  function renderGeoOptions(card) {
    const list = card.querySelector("[data-route-geo-options]");
    if (list.hidden) return;
    const filterValue = card.querySelector("[data-route-geo-filter]").value.trim().toLowerCase();
    const kind = field(card, "route", "match_type").value;
    const selection = geoSelection(card);
    list.replaceChildren();
    const matches = (geoOptionValues.get(kind) || [])
      .filter((name) => !filterValue || name.includes(filterValue));
    for (const name of matches.slice(0, GEO_OPTION_RENDER_LIMIT)) {
      const option = document.createElement("button");
      option.type = "button";
      option.className = "geo-option";
      option.dataset.geoOption = name;
      option.textContent = name;
      if (selection.includes(name)) option.classList.add("is-selected");
      list.append(option);
    }
  }

  function openGeoOptions(card) {
    card.querySelector("[data-route-geo-options]").hidden = false;
    renderGeoOptions(card);
  }

  function addGeoChip(card, rawName) {
    const name = rawName.trim().toLowerCase();
    const selection = geoSelection(card);
    if (!/^[a-z0-9_-]+$/.test(name) || selection.includes(name)) return;
    selection.push(name);
    renderGeoChips(card);
    renderGeoOptions(card);
    updateRouteRuleVisibility(card);
  }

  function removeGeoChip(card, name) {
    const selection = geoSelection(card);
    const index = selection.indexOf(name);
    if (index === -1) return;
    selection.splice(index, 1);
    renderGeoChips(card);
    renderGeoOptions(card);
    updateRouteRuleVisibility(card);
  }

  function addRouteRule(rule = {}) {
    const card = routeRuleTemplate.content.firstElementChild.cloneNode(true);
    originals.set(card, clone(rule));
    setValue(field(card, "route", "inbound"), listValue(rule.inbound).join(", "));
    const geoKind = inferGeoMatchKind(rule.rule_set);
    const matchType = geoKind || routeMatchFields.find((name) => rule[name] !== undefined) || "protocol";
    setValue(field(card, "route", "match_type"), matchType);
    if (geoKind) {
      for (const tag of rule.rule_set) geoSelection(card).push(tag.slice(geoKind.length + 1));
      renderGeoChips(card);
    } else {
      const values = Array.isArray(rule[matchType]) ? rule[matchType] : [rule[matchType]].filter(Boolean);
      setValue(field(card, "route", "match_values"), values.join("\n"));
    }
    setValue(field(card, "route", "outbound"), rule.outbound);
    routeRuleList.append(card);
    updateRouteRuleVisibility(card);
    setCardEditing(card, Object.keys(rule).length === 0);
    disableWhenReadonly(card);
    updateResourceCounts();
    return card;
  }

  function updateRouteRuleVisibility(card) {
    const type = field(card, "route", "match_type").value;
    const geo = type === "geosite" || type === "geoip";
    card.querySelector("[data-route-values-plain]").hidden = geo;
    card.querySelector("[data-route-values-geo]").hidden = !geo;
    const outbound = field(card, "route", "outbound").value || "no outbound";
    if (geo) {
      ensureGeoOptions(type);
      updateGeoHint(card);
      const names = geoSelection(card);
      updateCardSummary(
        card,
        names[0] ? `${type}-${names[0]}` : "Routing rule",
        `${type} · ${names.length} set${names.length === 1 ? "" : "s"} · ${outbound}`,
      );
      return;
    }
    const values = splitValues(field(card, "route", "match_values").value);
    updateCardSummary(
      card,
      values[0] || "Routing rule",
      `${type.replaceAll("_", " ")} · ${outbound}`,
    );
  }

  function updateOutboundTagOptions() {
    outboundTags.replaceChildren();
    for (const input of outboundList.querySelectorAll('[data-outbound-field="tag"]')) {
      const tag = input.value.trim();
      if (!tag) {
        continue;
      }
      const option = document.createElement("option");
      option.value = tag;
      outboundTags.append(option);
    }
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
      throw new Error("Port 80 is reserved for ACME HTTP-01 and cannot be used by a proxy inbound.");
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
    } else {
      inbound.tls = {
        enabled: true,
        certificate_path: field(card, "inbound", "certificate_path").value.trim(),
        key_path: field(card, "inbound", "key_path").value.trim(),
      };
    }
    return inbound;
  }

  function serializeOutbound(card) {
    const kind = field(card, "outbound", "kind").value;
    const tag = field(card, "outbound", "tag").value.trim();
    if (kind === "direct" || kind === "block") {
      return { type: kind, tag };
    }
    if (kind === "pool") {
      const ref = field(card, "outbound", "ref").value.trim();
      if (!ref) {
        throw new Error(`Pool import ${tag || "(untagged)"} needs a pool entry — pick one from the list.`);
      }
      if (!POOL_REF_PATTERN.test(ref)) {
        throw new Error(`Pool import ${tag || "(untagged)"} has an invalid pool reference: ${ref}`);
      }
      const outbound = { type: "theatropolis-pool-ref", tag, ref };
      // Agent refs always pin an explicit family; manual refs resolve
      // address-free and carry none.
      const entry = poolOptionByRef(ref);
      const familyValue = field(card, "outbound", "family")?.value;
      if (!(entry && entry.manual) && POOL_FAMILIES.includes(familyValue)) {
        outbound.family = familyValue;
      }
      return outbound;
    }
    let outbound;
    try {
      outbound = JSON.parse(field(card, "outbound", "json").value);
    } catch {
      throw new Error(`External outbound ${tag || "(untagged)"} is not valid JSON.`);
    }
    if (!objectValue(outbound)) {
      throw new Error(`External outbound ${tag || "(untagged)"} must be a JSON object.`);
    }
    outbound.tag = tag;
    return outbound;
  }

  function serializeRouteRule(card) {
    const rule = clone(originals.get(card) || {});
    const matchType = field(card, "route", "match_type").value;
    for (const name of routeMatchFields) {
      delete rule[name];
    }
    const inbound = splitValues(field(card, "route", "inbound").value);
    if (inbound.length) rule.inbound = inbound;
    else delete rule.inbound;
    if (matchType === "geosite" || matchType === "geoip") {
      // geosite/geoip are UI-level match types; the JSON field stays rule_set.
      const names = geoSelection(card);
      if (names.length) rule.rule_set = names.map((name) => `${matchType}-${name}`);
    } else {
      const values = splitValues(field(card, "route", "match_values").value);
      if (values.length) rule[matchType] = values;
    }
    rule.action = "route";
    rule.outbound = field(card, "route", "outbound").value.trim();
    return rule;
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
    next.outbounds = Array.from(
      outboundList.querySelectorAll("[data-outbound-card]"),
      serializeOutbound,
    );
    if (providers.length) next.certificate_providers = providers;
    else delete next.certificate_providers;
    const route = objectValue(next.route) ? clone(next.route) : {};
    route.rules = Array.from(
      routeRuleList.querySelectorAll("[data-route-rule-card]"),
      serializeRouteRule,
    );
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
      });
    }
    for (const entry of originalRuleSets) {
      if (!sagerNetURL.test(String(entry?.url || ""))) ruleSets.push(entry);
    }
    if (ruleSets.length) route.rule_set = ruleSets;
    else delete route.rule_set;
    const finalOutbound = routeFinal.value.trim();
    if (finalOutbound) route.final = finalOutbound;
    else delete route.final;
    next.route = route;
    configTextarea.value = `${JSON.stringify(next, null, 2)}\n`;
    configTextarea.setCustomValidity("");
    documentModel = next;
    summary.textContent = `${next.inbounds.length} inbound(s), ${next.outbounds.length} outbound(s), ${route.rules.length} rule(s)`;
    return next;
  }

  function renderModel(model) {
    if (!objectValue(model)) {
      throw new Error("The configuration root must be a JSON object.");
    }
    documentModel = clone(model);
    inboundList.replaceChildren();
    outboundList.replaceChildren();
    routeRuleList.replaceChildren();
    const unsupported = [];
    for (const inbound of listValue(documentModel.inbounds)) {
      if (supportedInboundTypes.has(inbound?.type)) {
        addInbound(inbound);
      } else {
        unsupported.push(inbound?.tag || inbound?.type || "unnamed");
      }
    }
    for (const outbound of listValue(documentModel.outbounds)) {
      addOutbound(outbound);
    }
    const route = objectValue(documentModel.route) ? documentModel.route : {};
    for (const rule of listValue(route.rules)) {
      addRouteRule(rule);
    }
    setValue(routeFinal, route.final);
    updateOutboundTagOptions();
    if (unsupported.length) {
      setWarning(
        `Advanced-only inbounds are preserved unchanged: ${unsupported.join(", ")}. Edit them in Advanced JSON.`,
      );
    } else {
      setWarning("");
    }
    summary.textContent = `${listValue(documentModel.inbounds).length} inbound(s), ${listValue(documentModel.outbounds).length} outbound(s), ${listValue(route.rules).length} rule(s)`;
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
    const button = event.target.closest("button");
    if (!button) return;
    if (button.dataset.configTab) {
      switchMode(button.dataset.configTab);
      return;
    }
    if (button.matches("[data-add-inbound]")) {
      addInbound({ type: "shadowsocks", listen: "::" });
    } else if (button.matches("[data-add-outbound]")) {
      addOutbound({ type: "direct" });
    } else if (button.matches("[data-add-route-rule]")) {
      addRouteRule({});
    } else if (button.matches("[data-geo-chip]")) {
      const card = button.closest("[data-route-rule-card]");
      if (card) removeGeoChip(card, button.dataset.geoChip);
    } else if (button.matches("[data-geo-option]")) {
      const card = button.closest("[data-route-rule-card]");
      if (card) {
        addGeoChip(card, button.dataset.geoOption);
        const filter = card.querySelector("[data-route-geo-filter]");
        filter.value = "";
        renderGeoOptions(card);
        filter.focus();
      }
    } else if (button.matches("[data-pool-option]")) {
      const card = button.closest("[data-outbound-card]");
      if (card) {
        const refInput = field(card, "outbound", "ref");
        refInput.value = button.dataset.poolOption;
        card.querySelector("[data-pool-options]").hidden = true;
        updateOutboundVisibility(card);
        refInput.focus();
      }
    } else if (button.matches("[data-pool-family-option]")) {
      const card = button.closest("[data-outbound-card]");
      if (card) {
        field(card, "outbound", "family").value = button.dataset.poolFamilyOption;
        syncPoolFamily(card);
      }
    } else if (button.matches("[data-pool-probe]")) {
      const card = button.closest("[data-outbound-card]");
      if (card) requestPoolProbe(card, button);
    } else if (button.matches("[data-remove-card]")) {
      button.closest(".builder-card")?.remove();
      updateOutboundTagOptions();
      updateResourceCounts();
    } else if (button.matches("[data-edit-card]")) {
      const card = button.closest(".builder-card");
      if (card) setCardEditing(card, !card.classList.contains("is-editing"));
    } else if (button.matches("[data-add-user]")) {
      const card = button.closest("[data-inbound-card]");
      addUser(card);
      updateInboundVisibility(card);
    } else if (button.matches("[data-remove-user]")) {
      const card = button.closest("[data-inbound-card]");
      button.closest("[data-user-row]")?.remove();
      if (card) updateInboundVisibility(card);
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
    const card = event.target.closest("[data-inbound-card], [data-outbound-card], [data-route-rule-card]");
    if (card?.matches("[data-inbound-card]")) {
      updateInboundVisibility(card);
      validateSSKeys(card);
    }
    if (card?.matches("[data-outbound-card]")) updateOutboundVisibility(card);
    if (card?.matches("[data-route-rule-card]")) updateRouteRuleVisibility(card);
    if (event.target.matches("[data-route-geo-filter]") && card) {
      openGeoOptions(card);
    }
    if (event.target.matches("[data-pool-filter]") && card) {
      openPoolOptions(card);
    }
    if (event.target.matches('[data-outbound-field="tag"]')) updateOutboundTagOptions();
  });

  configurationEditor.addEventListener("change", (event) => {
    const inbound = event.target.closest("[data-inbound-card]");
    if (inbound) {
      updateInboundVisibility(inbound);
      validateSSKeys(inbound);
    }
    const outbound = event.target.closest("[data-outbound-card]");
    if (outbound) updateOutboundVisibility(outbound);
    const routeRule = event.target.closest("[data-route-rule-card]");
    if (routeRule) updateRouteRuleVisibility(routeRule);
  });

  configurationEditor.addEventListener("focusin", (event) => {
    if (event.target.matches("[data-route-geo-filter]")) {
      const card = event.target.closest("[data-route-rule-card]");
      if (card) openGeoOptions(card);
      return;
    }
    if (event.target.matches("[data-pool-filter]")) {
      const card = event.target.closest("[data-outbound-card]");
      if (card) openPoolOptions(card);
    }
  });

  configurationEditor.addEventListener("keydown", (event) => {
    if (event.target.matches("[data-pool-filter]")) {
      const card = event.target.closest("[data-outbound-card]");
      if (!card) return;
      if (event.key === "Enter" || event.key === "Escape") {
        // Enter must not submit the whole configuration form; the typed
        // reference is authoritative on its own (free-text fallback).
        event.preventDefault();
        card.querySelector("[data-pool-options]").hidden = true;
        updateOutboundVisibility(card);
      }
      return;
    }
    if (!event.target.matches("[data-route-geo-filter]")) return;
    const card = event.target.closest("[data-route-rule-card]");
    if (!card) return;
    if (event.key === "Enter") {
      // Free-text entry is allowed even when the catalog failed to load.
      event.preventDefault();
      addGeoChip(card, event.target.value);
      event.target.value = "";
      renderGeoOptions(card);
    } else if (event.key === "Escape") {
      // Keep the Escape from bubbling up and closing the manager dialog.
      event.preventDefault();
      card.querySelector("[data-route-geo-options]").hidden = true;
    }
  });

  document.addEventListener("click", (event) => {
    for (const list of routeRuleList.querySelectorAll("[data-route-geo-options]:not([hidden])")) {
      const combobox = list.closest("[data-route-values-geo]");
      if (combobox && !combobox.contains(event.target)) list.hidden = true;
    }
    for (const list of outboundList.querySelectorAll("[data-pool-options]:not([hidden])")) {
      const combobox = list.closest("[data-pool-field]");
      if (combobox && !combobox.contains(event.target)) list.hidden = true;
    }
  });

  configurationForm.addEventListener("submit", (event) => {
    if (!advancedPanel.hidden) {
      try {
        const parsed = JSON.parse(configTextarea.value);
        if (!objectValue(parsed)) throw new Error("The configuration root must be a JSON object.");
        configTextarea.setCustomValidity("");
      } catch (error) {
        event.preventDefault();
        configTextarea.setCustomValidity(error.message);
        configTextarea.reportValidity();
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
