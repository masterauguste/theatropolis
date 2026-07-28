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
  const ruleSetList = configurationEditor.querySelector("[data-rule-set-list]");
  const routeRuleList = configurationEditor.querySelector("[data-route-rule-list]");
  const routeFinal = configurationEditor.querySelector("[data-route-final]");
  const outboundTags = configurationForm.querySelector("[data-outbound-tags]");
  const inboundTemplate = document.getElementById("inbound-card-template");
  const userTemplate = document.getElementById("user-row-template");
  const outboundTemplate = document.getElementById("outbound-card-template");
  const ruleSetTemplate = document.getElementById("rule-set-card-template");
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

  function updateResourceCounts() {
    const counts = {
      inbound: inboundList.querySelectorAll("[data-inbound-card]").length,
      outbound: outboundList.querySelectorAll("[data-outbound-card]").length,
      "rule-set": ruleSetList.querySelectorAll("[data-rule-set-card]").length,
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
      const userInfo = btoa(method + ":" + password).replaceAll("=", "");
      return "ss://" + userInfo + "@" + host + ":" + port + "#" + label;
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

  function showCopyResult(button, copied) {
    const original = button.textContent;
    button.textContent = copied ? "Copied!" : "Copy failed";
    window.setTimeout(() => {
      button.textContent = original;
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

  function updateInboundVisibility(card) {
    const type = field(card, "inbound", "type").value;
    const tlsMode = field(card, "inbound", "tls_mode").value;
    for (const element of card.querySelectorAll("[data-ss-field]")) {
      element.hidden = type !== "shadowsocks";
    }
    for (const element of card.querySelectorAll("[data-hy2-field]")) {
      element.hidden = type !== "hysteria2";
    }
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
    setCardEditing(card, !inbound.tag);
    disableWhenReadonly(card);
    updateResourceCounts();
    return card;
  }

  function updateOutboundVisibility(card) {
    const kind = field(card, "outbound", "kind").value;
    card.querySelector("[data-external-outbound-field]").hidden = kind !== "external";
    field(card, "outbound", "json").required = kind === "external";
    updateCardSummary(
      card,
      field(card, "outbound", "tag").value || "New outbound",
      kind === "external" ? "External JSON" : kind,
    );
  }

  function addOutbound(outbound = {}) {
    const card = outboundTemplate.content.firstElementChild.cloneNode(true);
    originals.set(card, clone(outbound));
    const kind = outbound.type === "direct" || outbound.type === "block" ? outbound.type : "external";
    setValue(field(card, "outbound", "kind"), kind);
    setValue(field(card, "outbound", "tag"), outbound.tag);
    if (kind === "external") {
      setValue(field(card, "outbound", "json"), JSON.stringify(outbound, null, 2));
    }
    outboundList.append(card);
    updateOutboundVisibility(card);
    setCardEditing(card, !outbound.tag);
    disableWhenReadonly(card);
    updateOutboundTagOptions();
    updateResourceCounts();
    return card;
  }

  function inferRuleSet(ruleSet) {
    const url = String(ruleSet.url || "");
    const geosite = url.match(/SagerNet\/sing-geosite\/rule-set\/geosite-(.+)\.srs$/);
    if (geosite) {
      return { kind: "geosite", name: geosite[1], url };
    }
    const geoip = url.match(/SagerNet\/sing-geoip\/rule-set\/geoip-(.+)\.srs$/);
    if (geoip) {
      return { kind: "geoip", name: geoip[1], url };
    }
    return { kind: "custom", name: ruleSet.tag || "", url };
  }

  function updateRuleSetVisibility(card) {
    const kind = field(card, "rule-set", "kind").value;
    card.querySelector("[data-rule-set-url-field]").hidden = kind !== "custom";
    field(card, "rule-set", "url").required = kind === "custom";
    const name = field(card, "rule-set", "name").value || "New rule set";
    updateCardSummary(card, name, kind === "custom" ? "Custom SRS" : `SagerNet ${kind}`);
  }

  function addRuleSet(ruleSet = {}) {
    const card = ruleSetTemplate.content.firstElementChild.cloneNode(true);
    originals.set(card, clone(ruleSet));
    const inferred = inferRuleSet(ruleSet);
    setValue(field(card, "rule-set", "kind"), inferred.kind);
    setValue(field(card, "rule-set", "name"), inferred.name);
    setValue(field(card, "rule-set", "url"), inferred.url);
    ruleSetList.append(card);
    updateRuleSetVisibility(card);
    setCardEditing(card, !ruleSet.tag);
    disableWhenReadonly(card);
    updateResourceCounts();
    return card;
  }

  function addRouteRule(rule = {}) {
    const card = routeRuleTemplate.content.firstElementChild.cloneNode(true);
    originals.set(card, clone(rule));
    setValue(field(card, "route", "inbound"), listValue(rule.inbound).join(", "));
    const matchType = routeMatchFields.find((name) => rule[name] !== undefined) || "protocol";
    setValue(field(card, "route", "match_type"), matchType);
    const values = Array.isArray(rule[matchType]) ? rule[matchType] : [rule[matchType]].filter(Boolean);
    setValue(field(card, "route", "match_values"), values.join("\n"));
    setValue(field(card, "route", "outbound"), rule.outbound);
    routeRuleList.append(card);
    updateRouteRuleSummary(card);
    setCardEditing(card, Object.keys(rule).length === 0);
    disableWhenReadonly(card);
    updateResourceCounts();
    return card;
  }

  function updateRouteRuleSummary(card) {
    const type = field(card, "route", "match_type").value;
    const values = splitValues(field(card, "route", "match_values").value);
    const outbound = field(card, "route", "outbound").value || "no outbound";
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

  function serializeRuleSet(card) {
    const original = clone(originals.get(card) || {});
    const kind = field(card, "rule-set", "kind").value;
    const name = field(card, "rule-set", "name").value.trim();
    const prefix = kind === "geoip" ? "geoip" : "geosite";
    const tag = kind === "custom" ? name : `${prefix}-${name}`;
    const url = kind === "custom"
      ? field(card, "rule-set", "url").value.trim()
      : `https://raw.githubusercontent.com/SagerNet/sing-${prefix}/rule-set/${prefix}-${name}.srs`;
    return {
      ...original,
      type: "remote",
      tag,
      format: "binary",
      url,
    };
  }

  function serializeRouteRule(card) {
    const rule = clone(originals.get(card) || {});
    const matchType = field(card, "route", "match_type").value;
    for (const name of routeMatchFields) {
      delete rule[name];
    }
    const inbound = splitValues(field(card, "route", "inbound").value);
    const values = splitValues(field(card, "route", "match_values").value);
    if (inbound.length) rule.inbound = inbound;
    else delete rule.inbound;
    if (values.length) rule[matchType] = values;
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
    route.rule_set = Array.from(
      ruleSetList.querySelectorAll("[data-rule-set-card]"),
      serializeRuleSet,
    );
    route.rules = Array.from(
      routeRuleList.querySelectorAll("[data-route-rule-card]"),
      serializeRouteRule,
    );
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
    ruleSetList.replaceChildren();
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
    for (const ruleSet of listValue(route.rule_set)) {
      addRuleSet(ruleSet);
    }
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
    } else if (button.matches("[data-add-rule-set]")) {
      addRuleSet({});
    } else if (button.matches("[data-add-route-rule]")) {
      addRouteRule({});
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
    const card = event.target.closest("[data-inbound-card], [data-outbound-card], [data-rule-set-card]");
    if (card?.matches("[data-inbound-card]")) updateInboundVisibility(card);
    if (card?.matches("[data-outbound-card]")) updateOutboundVisibility(card);
    if (card?.matches("[data-rule-set-card]")) updateRuleSetVisibility(card);
    if (card?.matches("[data-route-rule-card]")) updateRouteRuleSummary(card);
    if (event.target.matches('[data-outbound-field="tag"]')) updateOutboundTagOptions();
  });

  configurationEditor.addEventListener("change", (event) => {
    const inbound = event.target.closest("[data-inbound-card]");
    if (inbound) updateInboundVisibility(inbound);
    const outbound = event.target.closest("[data-outbound-card]");
    if (outbound) updateOutboundVisibility(outbound);
    const ruleSet = event.target.closest("[data-rule-set-card]");
    if (ruleSet) updateRuleSetVisibility(ruleSet);
    const routeRule = event.target.closest("[data-route-rule-card]");
    if (routeRule) updateRouteRuleSummary(routeRule);
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
