"use strict";

function updateProxyEndpointForm(select) {
  const form = select.closest("form");
  if (!form) return;
  const protocol = select.value;
  for (const section of form.querySelectorAll("[data-proxy-section]")) {
    const kind = section.dataset.proxySection;
    section.hidden = kind === "shadowsocks" ? protocol !== "shadowsocks" :
      kind === "tls" ? protocol === "shadowsocks" : protocol !== kind;
  }
  const tlsMode = form.querySelector("[data-proxy-tls-mode]")?.value;
  for (const field of form.querySelectorAll("[data-proxy-acme]")) {
    field.hidden = protocol === "shadowsocks" || tlsMode !== "acme";
  }
  for (const field of form.querySelectorAll("[data-proxy-files]")) {
    field.hidden = protocol === "shadowsocks" || tlsMode !== "files";
  }
}

for (const select of document.querySelectorAll("[data-proxy-protocol]")) {
  updateProxyEndpointForm(select);
  select.addEventListener("change", () => updateProxyEndpointForm(select));
  select.closest("form")?.querySelector("[data-proxy-tls-mode]")?.addEventListener(
    "change",
    () => updateProxyEndpointForm(select),
  );
}

const proxyListenerCatalog = [...document.querySelectorAll(
  "[data-proxy-listener-catalog] [data-listener-id]",
)].map((element) => ({
  ...element.dataset,
  port: Number(element.dataset.port || 0),
  upMbps: Number(element.dataset.upMbps || 0),
  downMbps: Number(element.dataset.downMbps || 0),
  muxBrutalUp: Number(element.dataset.muxBrutalUp || 0),
  muxBrutalDown: Number(element.dataset.muxBrutalDown || 0),
  referenceCount: Number(element.dataset.referenceCount || 0),
}));

const proxyListenerAgent = (editor) => {
  const form = editor.closest("form");
  return form?.querySelector('[name="child_agent"]')?.value ||
    form?.querySelector('[name="agent_id"]')?.value || editor.dataset.agent || "";
};

const proxyListenerValue = (editor, name) => editor.querySelector(`[name="${name}"]`)?.value.trim() || "";

const proxyListenerModel = (editor) => {
  const model = {
    protocol: proxyListenerValue(editor, "protocol"),
    listen: proxyListenerValue(editor, "listen"),
    port: Number(proxyListenerValue(editor, "listen_port") || 0),
    method: proxyListenerValue(editor, "method"),
    muxPadding: proxyListenerValue(editor, "mux_padding"),
    muxBrutal: proxyListenerValue(editor, "mux_brutal"),
    muxBrutalUp: Number(proxyListenerValue(editor, "mux_brutal_up_mbps") || 0),
    muxBrutalDown: Number(proxyListenerValue(editor, "mux_brutal_down_mbps") || 0),
    tlsMode: proxyListenerValue(editor, "tls_mode"),
    serverName: proxyListenerValue(editor, "server_name"),
    email: proxyListenerValue(editor, "email"),
    certificatePath: proxyListenerValue(editor, "certificate_path"),
    keyPath: proxyListenerValue(editor, "key_path"),
    upMbps: Number(proxyListenerValue(editor, "up_mbps") || 0),
    downMbps: Number(proxyListenerValue(editor, "down_mbps") || 0),
    obfsType: proxyListenerValue(editor, "obfs_type"),
  };
  if (model.tlsMode === "acme") {
    model.certificatePath = "";
    model.keyPath = "";
  } else if (model.tlsMode === "self_signed") {
    model.email = "";
    model.certificatePath = "";
    model.keyPath = "";
  } else if (model.tlsMode === "files") {
    model.email = "";
  }
  return model;
};

const proxyListenerCompatibilityFields = (protocol) => {
  const fields = ["protocol", "listen", "port"];
  if (protocol === "shadowsocks") {
    return fields.concat("method", "muxPadding", "muxBrutal", "muxBrutalUp", "muxBrutalDown");
  }
  fields.push("tlsMode", "serverName", "email", "certificatePath", "keyPath");
  if (protocol === "hysteria2") fields.push("upMbps", "downMbps", "obfsType");
  return fields;
};

const proxyListenersMatch = (left, right) => {
  if (left.protocol !== right.protocol) return false;
  return proxyListenerCompatibilityFields(left.protocol).every((field) => String(left[field] ?? "") === String(right[field] ?? ""));
};

const proxyListenerFieldLabels = {
  protocol: "protocol",
  method: "Shadowsocks method",
  muxPadding: "multiplex padding",
  muxBrutal: "TCP Brutal",
  muxBrutalUp: "TCP Brutal upload rate",
  muxBrutalDown: "TCP Brutal download rate",
  tlsMode: "certificate mode",
  serverName: "domain or certificate identity",
  email: "ACME email",
  certificatePath: "certificate path",
  keyPath: "private-key path",
  upMbps: "Hysteria2 upload rate",
  downMbps: "Hysteria2 download rate",
  obfsType: "Hysteria2 obfuscation",
};

const proxyListenerClaims = (agent, listener) => {
  const networks = listener.protocol === "shadowsocks" ? ["TCP", "UDP"] :
    listener.protocol === "hysteria2" ? ["UDP"] : ["TCP"];
  return networks.map((network) => `${agent}/${network}/${listener.listen}:${listener.port}`);
};

const setProxyListenerStatus = (editor, message, kind = "") => {
  const status = editor.querySelector("[data-proxy-listener-status]");
  if (!status) return;
  status.textContent = message;
  status.className = `proxy-listener-status${kind ? ` is-${kind}` : ""}`;
};

const setProxyListenerField = (editor, name, value) => {
  const input = editor.querySelector(`[name="${name}"]`);
  if (!input) return;
  input.value = value ?? "";
  if (input instanceof HTMLSelectElement) input.dispatchEvent(new Event("change", { bubbles: true }));
};

const applyProxyListenerPreset = (editor, preset) => {
  for (const field of proxyListenerCompatibilityFields(preset.protocol)) {
    if (field === "port") setProxyListenerField(editor, "listen_port", preset.port);
    else if (field === "muxPadding") setProxyListenerField(editor, "mux_padding", preset.muxPadding);
    else if (field === "muxBrutal") setProxyListenerField(editor, "mux_brutal", preset.muxBrutal);
    else if (field === "muxBrutalUp") setProxyListenerField(editor, "mux_brutal_up_mbps", preset.muxBrutalUp);
    else if (field === "muxBrutalDown") setProxyListenerField(editor, "mux_brutal_down_mbps", preset.muxBrutalDown);
    else setProxyListenerField(editor, field.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`), preset[field]);
  }
  const protocol = editor.querySelector("[data-proxy-protocol]");
  if (protocol) updateProxyEndpointForm(protocol);
};

const showProxyListenerSummary = (editor, preset) => {
  const summary = editor.querySelector("[data-proxy-listener-summary]");
  if (!summary) return;
  const identity = preset.protocol === "shadowsocks" ? preset.method.replace("2022-blake3-", "") :
    `${preset.tlsMode.replace("_", "-")} · ${preset.serverName || "certificate identity pending"}`;
  summary.replaceChildren();
  const title = document.createElement("strong");
  title.textContent = `${preset.protocolLabel} on ${preset.listen}:${preset.port}`;
  const detail = document.createElement("span");
  detail.textContent = `${identity} · shared by ${preset.referenceCount} logical reference${preset.referenceCount === 1 ? "" : "s"}`;
  summary.append(title, detail);
  summary.hidden = false;
};

const validateProxyListener = (editor) => {
  const port = editor.querySelector('[name="listen_port"]');
  if (!(port instanceof HTMLInputElement)) return;
  port.setCustomValidity("");
  const agent = proxyListenerAgent(editor);
  const candidate = proxyListenerModel(editor);
  if (!agent || !candidate.listen || !candidate.port) {
    setProxyListenerStatus(editor, "Select an Agent and complete the socket to check availability.");
    return;
  }
  const claims = new Set(proxyListenerClaims(agent, candidate));
  const currentID = editor.dataset.currentListener || "";
  const others = proxyListenerCatalog.filter((preset) => preset.agent === agent && preset.listenerId !== currentID);
  const compatible = others.find((preset) => proxyListenersMatch(candidate, preset));
  if (compatible) {
    setProxyListenerStatus(editor, `Compatible with “${compatible.label}”. You can select it above to reuse its settings.`, "compatible");
    return;
  }
  const conflict = others.find((preset) => proxyListenerClaims(agent, preset).some((claim) => claims.has(claim)));
  if (conflict) {
    const differences = candidate.protocol === conflict.protocol ?
      proxyListenerCompatibilityFields(candidate.protocol)
        .filter((field) => !["listen", "port"].includes(field) && String(candidate[field] ?? "") !== String(conflict[field] ?? ""))
        .map((field) => proxyListenerFieldLabels[field] || field) : ["protocol"];
    const detail = differences.length ? ` The conflicting fields are: ${differences.join(", ")}.` : "";
    const message = `This socket overlaps “${conflict.label}”, but its listener-wide settings differ.${detail}`;
    port.setCustomValidity(message);
    setProxyListenerStatus(editor, `${message} Reuse that listener or choose another address or port.`, "conflict");
    return;
  }
  const current = proxyListenerCatalog.find((preset) => preset.listenerId === currentID && preset.agent === agent);
  if (current?.referenceCount > 1) {
    setProxyListenerStatus(editor, `This physical listener is shared by ${current.referenceCount} logical references. Saving changes updates all of them atomically.`, "warning");
    return;
  }
  if (current) {
    setProxyListenerStatus(editor, "Saving will update this physical listener atomically.", "compatible");
    return;
  }
  setProxyListenerStatus(editor, "This socket is available for a new physical listener.", "compatible");
};

const updateProxyListenerChoices = (editor) => {
  const select = editor.querySelector("[data-proxy-listener-select]");
  if (!(select instanceof HTMLSelectElement)) return;
  const previous = select.value;
  const agent = proxyListenerAgent(editor);
  select.replaceChildren(new Option("Configure manually", "manual"));
  for (const preset of proxyListenerCatalog.filter((item) => item.agent === agent)) {
    select.add(new Option(preset.label, preset.listenerId));
  }
  const currentID = editor.dataset.currentListener || "";
  select.value = [...select.options].some((option) => option.value === previous) ? previous :
    [...select.options].some((option) => option.value === currentID) ? currentID : "manual";
  select.dispatchEvent(new Event("change", { bubbles: true }));
};

for (const editor of document.querySelectorAll("[data-proxy-listener-editor]")) {
  const form = editor.closest("form");
  const select = editor.querySelector("[data-proxy-listener-select]");
  const fields = editor.querySelector("[data-proxy-listener-fields]");
  const summary = editor.querySelector("[data-proxy-listener-summary]");
  const updateSelection = () => {
    const preset = proxyListenerCatalog.find((item) => item.listenerId === select?.value);
    if (preset) {
      applyProxyListenerPreset(editor, preset);
      if (fields) fields.hidden = true;
      showProxyListenerSummary(editor, preset);
      editor.querySelector('[name="listen_port"]')?.setCustomValidity("");
      setProxyListenerStatus(editor, "Using the existing physical listener keeps all shared settings consistent.", "compatible");
    } else {
      if (fields) fields.hidden = false;
      if (summary) summary.hidden = true;
      validateProxyListener(editor);
    }
  };
  select?.addEventListener("change", updateSelection);
  for (const input of editor.querySelectorAll("[data-proxy-listener-fields] input, [data-proxy-listener-fields] select")) {
    input.addEventListener("input", () => validateProxyListener(editor));
    input.addEventListener("change", () => validateProxyListener(editor));
  }
  for (const agentSelect of form?.querySelectorAll('[name="child_agent"], [name="agent_id"]') || []) {
    agentSelect.addEventListener("change", () => updateProxyListenerChoices(editor));
  }
  updateProxyListenerChoices(editor);
}

for (const select of document.querySelectorAll("[data-proxy-match]")) {
  const update = () => {
    const values = select.closest("form")?.querySelector("[data-proxy-match-values]");
    if (!values) return;
    const all = select.value === "none";
    values.hidden = all;
    for (const input of values.querySelectorAll("input, textarea, select")) {
      input.required = !all;
      if (all) input.value = "";
    }
  };
  update();
  select.addEventListener("change", update);
}

for (const button of document.querySelectorAll("[data-copy-value]")) {
  button.addEventListener("click", async () => {
    const original = button.textContent;
    try {
      await navigator.clipboard.writeText(button.dataset.copyValue || "");
      button.textContent = "Copied";
    } catch (_) {
      button.textContent = "Copy failed";
    }
    window.setTimeout(() => { button.textContent = original; }, 1500);
  });
}

let draggedProxyBranch = null;
let draggedProxyBranchOrder = "";
let draggedProxyBranchElements = [];
let proxyBranchDropAccepted = false;

const topologyWorkflow = document.querySelector("[data-topology-workflow]");
const proxyDeployment = document.querySelector("[data-proxy-deployment][data-status-url]");
let topologyPolling = false;

const topologyMutationForms = () => [...(topologyWorkflow?.querySelectorAll("form") || [])]
  .filter((form) => {
    let path = "";
    try { path = new URL(form.action, window.location.href).pathname; } catch (_) { return false; }
    return path.startsWith("/proxy-nodes")
      && !path.includes("/users")
      && !path.endsWith("/deploy")
      && path !== "/proxy-nodes/deploy";
  });

const topologyActionControls = () => [
  ...(topologyWorkflow?.querySelectorAll(
    ".proxy-tree-panel button, #proxy-tree-inspector button, dialog[id^='proxy-add-link-'] button, dialog[id^='proxy-add-rule-'] button, dialog[id^='proxy-edit-link-'] button, .proxy-node-settings button",
  ) || []),
];

const setTopologyLocked = (locked) => {
  if (!topologyWorkflow) return;
  if (locked) {
    topologyWorkflow.dataset.topologyLocked = "true";
    topologyWorkflow.setAttribute("aria-busy", "true");
  } else {
    delete topologyWorkflow.dataset.topologyLocked;
    topologyWorkflow.removeAttribute("aria-busy");
  }
  const controls = [
    ...topologyMutationForms().flatMap((form) => [...form.elements]),
    ...topologyActionControls(),
  ];
  for (const control of new Set(controls)) {
    if (!(control instanceof HTMLButtonElement || control instanceof HTMLInputElement || control instanceof HTMLSelectElement || control instanceof HTMLTextAreaElement)) continue;
    if (locked) {
      if (!control.disabled) control.dataset.topologyEnabled = "true";
      control.disabled = true;
    } else if (control.dataset.topologyEnabled === "true") {
      control.disabled = false;
      delete control.dataset.topologyEnabled;
    }
  }
  const createLink = topologyWorkflow.querySelector("[data-topology-create]");
  if (createLink) createLink.setAttribute("aria-disabled", locked ? "true" : "false");
  for (const branch of topologyWorkflow.querySelectorAll("[data-proxy-rule-branch]")) {
    if (locked) {
      branch.dataset.topologyDraggable = branch.getAttribute("draggable") || "false";
      branch.setAttribute("draggable", "false");
    } else if (branch.dataset.topologyDraggable) {
      branch.setAttribute("draggable", branch.dataset.topologyDraggable);
      delete branch.dataset.topologyDraggable;
    }
  }
};

const renderTopologyStatus = (status) => {
  if (!proxyDeployment) return;
  proxyDeployment.hidden = false;
  proxyDeployment.classList.toggle("notice--error", status.status === "failed");
  const heading = proxyDeployment.querySelector("strong");
  if (heading) heading.textContent = `Topology change: ${status.label || status.status || "Applying"}`;
  let error = proxyDeployment.querySelector("p");
  if (status.error) {
    if (!error) {
      error = document.createElement("p");
      proxyDeployment.append(error);
    }
    error.textContent = status.error;
  } else if (error) {
    error.remove();
  }
};

const pollTopologyDeployment = async (reloadOnComplete) => {
  try {
    const response = await fetch(proxyDeployment?.dataset.statusUrl || "/proxy-nodes/deployment-status", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) throw new Error("status unavailable");
    const status = await response.json();
    renderTopologyStatus(status);
    if (!status.active) {
      topologyPolling = false;
      setTopologyLocked(false);
      document.dispatchEvent(new CustomEvent("topologyapplycomplete", { detail: status }));
      if (reloadOnComplete) window.location.reload();
      return;
    }
  } catch (_) {
    // Keep the current status visible and retry transient failures.
  }
  window.setTimeout(() => pollTopologyDeployment(reloadOnComplete), 2000);
};

const beginTopologyApply = (reloadOnComplete) => {
  setTopologyLocked(true);
  if (proxyDeployment) {
    proxyDeployment.hidden = false;
    const heading = proxyDeployment.querySelector("strong");
    if (heading) heading.textContent = "Applying topology change…";
  }
  if (topologyPolling) return;
  topologyPolling = true;
  window.setTimeout(() => pollTopologyDeployment(reloadOnComplete), 500);
};

if (topologyWorkflow?.dataset.topologyLocked === "true") beginTopologyApply(true);

document.addEventListener("click", (event) => {
  const createLink = event.target instanceof Element ? event.target.closest("[data-topology-create]") : null;
  if (createLink && topologyWorkflow?.dataset.topologyLocked === "true") event.preventDefault();
}, true);

const directProxyBranch = (target, list) => {
  const branch = target instanceof Element ? target.closest("[data-proxy-rule-branch]") : null;
  return branch?.parentElement === list ? branch : null;
};

const proxyBranchOrder = (list) => [...list.children]
  .filter((child) => child.matches("[data-proxy-rule-branch]"))
  .map((child) => child.dataset.proxyRuleBranch)
  .join(",");

const mergedProxyBranchOrder = (list, visibleOrder) => {
  const allRuleIDs = (list.dataset.proxyAllRuleIds || "").split(",").filter(Boolean);
  const visibleRuleIDs = visibleOrder.split(",").filter(Boolean);
  if (allRuleIDs.length === visibleRuleIDs.length) return visibleOrder;
  const visibleSet = new Set(visibleRuleIDs);
  let visibleIndex = 0;
  const merged = allRuleIDs.map((ruleID) => {
    if (!visibleSet.has(ruleID)) return ruleID;
    const replacement = visibleRuleIDs[visibleIndex];
    visibleIndex += 1;
    return replacement;
  });
  return visibleIndex === visibleRuleIDs.length ? merged.join(",") : visibleOrder;
};

document.addEventListener("dragstart", (event) => {
  const branch = event.target instanceof Element
    ? event.target.closest("[data-proxy-rule-branch]")
    : null;
  const list = branch?.parentElement;
  if (!branch || !list?.matches("[data-proxy-branch-list]") || list.dataset.reorderPending === "true" || topologyWorkflow?.dataset.topologyLocked === "true") return;
  draggedProxyBranch = branch;
  draggedProxyBranchOrder = proxyBranchOrder(list);
  draggedProxyBranchElements = [...list.children]
    .filter((child) => child.matches("[data-proxy-rule-branch]"));
  proxyBranchDropAccepted = false;
  branch.classList.add("is-dragging");
  event.dataTransfer.effectAllowed = "move";
  event.dataTransfer.setData("text/plain", branch.dataset.proxyRuleBranch || "route-rule");
});

document.addEventListener("dragover", (event) => {
  if (!draggedProxyBranch) return;
  const list = draggedProxyBranch.parentElement;
  if (!list || !(event.target instanceof Element) || !list.contains(event.target)) return;
  event.preventDefault();
  event.dataTransfer.dropEffect = "move";
  for (const branch of list.querySelectorAll(":scope > .is-drop-target")) {
    branch.classList.remove("is-drop-target");
  }
  const target = directProxyBranch(event.target, list);
  if (!target || target === draggedProxyBranch) return;
  target.classList.add("is-drop-target");
  const bounds = target.getBoundingClientRect();
  const after = event.clientY > bounds.top + bounds.height / 2;
  list.insertBefore(draggedProxyBranch, after ? target.nextElementSibling : target);
});

document.addEventListener("drop", (event) => {
  if (!draggedProxyBranch) return;
  const list = draggedProxyBranch.parentElement;
  if (list && event.target instanceof Element && list.contains(event.target)) {
    event.preventDefault();
    proxyBranchDropAccepted = true;
  }
});

document.addEventListener("dragend", () => {
  if (!draggedProxyBranch) return;
  const list = draggedProxyBranch.parentElement;
  draggedProxyBranch.classList.remove("is-dragging");
  for (const branch of list?.querySelectorAll(":scope > .is-drop-target") || []) {
    branch.classList.remove("is-drop-target");
  }
  if (list && !proxyBranchDropAccepted) {
    const anchor = [...list.children]
      .find((child) => !child.matches("[data-proxy-rule-branch]")) || null;
    for (const branch of draggedProxyBranchElements) list.insertBefore(branch, anchor);
  }
  const nextOrder = list ? proxyBranchOrder(list) : draggedProxyBranchOrder;
  const previousElements = draggedProxyBranchElements;
  draggedProxyBranch = null;
  draggedProxyBranchElements = [];
  if (!list || !proxyBranchDropAccepted || nextOrder === draggedProxyBranchOrder) return;
  const restoreOrder = () => {
    const anchor = [...list.children]
      .find((child) => !child.matches("[data-proxy-rule-branch]")) || null;
    for (const branch of previousElements) list.insertBefore(branch, anchor);
  };
  const persistedOrder = mergedProxyBranchOrder(list, nextOrder);
  const body = new URLSearchParams({
    csrf_token: list.dataset.csrfToken || "",
    rule_ids: persistedOrder,
  });
  list.dataset.reorderPending = "true";
  fetch(list.dataset.reorderUrl || "", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
    },
    body,
    credentials: "same-origin",
  }).then(async (response) => {
    if (!response.ok || response.redirected) throw new Error("reorder rejected");
    list.dataset.proxyAllRuleIds = persistedOrder;
    const priorities = new Map(persistedOrder.split(",").map((ruleID, index) => [ruleID, index + 1]));
    for (const branch of list.querySelectorAll(":scope > [data-proxy-rule-branch]")) {
      const priority = branch.querySelector(".proxy-map__priority");
      if (priority) priority.textContent = priorities.get(branch.dataset.proxyRuleBranch) || "";
    }
    if (response.status === 202) {
      const status = await response.json();
      renderTopologyStatus(status);
      document.addEventListener("topologyapplycomplete", (completion) => {
        if (completion.detail?.status === "failed") {
          restoreOrder();
          window.alert(completion.detail.error || "The topology change failed and the previous branch order was restored.");
        }
        delete list.dataset.reorderPending;
      }, { once: true });
      beginTopologyApply(false);
    } else {
      delete list.dataset.reorderPending;
    }
  }).catch(() => {
    restoreOrder();
    delete list.dataset.reorderPending;
    window.alert("The new branch order could not be saved. The previous order was restored.");
  });
});

const dialogTriggers = new WeakMap();

const redirectForExpiredSession = (response) => {
  let loginRedirect = false;
  try {
    loginRedirect = response.redirected && new URL(response.url).pathname === "/login";
  } catch {
    loginRedirect = false;
  }
  if (response.status !== 401 && !loginRedirect) return false;
  window.location.assign("/login");
  return true;
};

document.addEventListener("click", (event) => {
  const inspectorButton = event.target.closest("[data-proxy-inspector-open]");
  if (inspectorButton) {
    const dialog = document.getElementById("proxy-tree-inspector");
    const viewID = inspectorButton.dataset.proxyInspectorOpen;
    if (!(dialog instanceof HTMLDialogElement)) return;
    const views = [...dialog.querySelectorAll("[data-proxy-inspector-view]")];
    const selected = views.find((view) => view.dataset.proxyInspectorView === viewID);
    if (!selected) return;
    for (const view of views) {
      view.hidden = view !== selected;
    }
    const sourceDialog = inspectorButton.closest("dialog");
    if (sourceDialog instanceof HTMLDialogElement && sourceDialog !== dialog && sourceDialog.open) {
      sourceDialog.close();
    }
    dialogTriggers.set(dialog, inspectorButton);
    if (!dialog.open) dialog.showModal();
    return;
  }

  const button = event.target.closest("[data-dialog-open]");
  if (button) {
    const dialog = document.getElementById(button.dataset.dialogOpen);
    if (!(dialog instanceof HTMLDialogElement)) {
      return;
    }
    const matchDefault = button.dataset.proxyMatchDefault;
    const matchSelect = dialog.querySelector("[data-proxy-match]");
    if (matchDefault && matchSelect instanceof HTMLSelectElement) {
      matchSelect.value = matchDefault;
      matchSelect.dispatchEvent(new Event("change", { bubbles: true }));
    }
    dialogTriggers.set(dialog, button);
    if (!dialog.open) dialog.showModal();
    return;
  }

  const closeButton = event.target.closest("[data-dialog-close]");
  if (closeButton) {
    closeButton.closest("dialog")?.close();
  }
});

const initialInspector = new URLSearchParams(window.location.search).get("inspect");
if (initialInspector) {
  const inspectorButton = [...document.querySelectorAll("[data-proxy-inspector-open]")]
    .find((button) => button.dataset.proxyInspectorOpen === initialInspector);
  if (inspectorButton) {
    inspectorButton.click();
  } else {
    const dialog = document.getElementById("proxy-tree-inspector");
    const views = dialog instanceof HTMLDialogElement
      ? [...dialog.querySelectorAll("[data-proxy-inspector-view]")]
      : [];
    const selected = views.find((view) => view.dataset.proxyInspectorView === initialInspector);
    if (selected && dialog instanceof HTMLDialogElement) {
      for (const view of views) view.hidden = view !== selected;
      dialog.showModal();
    }
  }
  const cleanURL = new URL(window.location.href);
  cleanURL.searchParams.delete("inspect");
  window.history.replaceState(null, "", cleanURL);
}

document.addEventListener("cancel", (event) => {
  if (event.target.matches("dialog.modal")) {
    event.preventDefault();
  }
}, true);

document.addEventListener("close", (event) => {
  if (event.target.matches("dialog.modal")) {
    dialogTriggers.get(event.target)?.focus();
  }
}, true);

const loadAsyncRegion = async (region) => {
  const url = region.dataset.asyncUrl;
  if (!url || region.dataset.asyncLoading === "true") return;
  region.dataset.asyncLoading = "true";
  region.setAttribute("aria-busy", "true");
  region.innerHTML = `
    <div class="loading-state" role="status">
      <span class="loading-spinner" aria-hidden="true"></span>
      <span>${region.dataset.asyncLoadingLabel || "Loading…"}</span>
    </div>`;
  try {
    const response = await fetch(url, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "text/html" },
    });
    if (redirectForExpiredSession(response)) return;
    if (!response.ok) {
      throw new Error(`request returned ${response.status}`);
    }
    region.innerHTML = await response.text();
    region.setAttribute("aria-busy", "false");
  } catch {
    region.innerHTML = `
      <div class="notice notice--error async-error" role="alert">
        <span>This section could not be loaded.</span>
        <button class="button button--secondary button--small" type="button" data-async-retry>Try again</button>
      </div>`;
    region.setAttribute("aria-busy", "false");
  } finally {
    delete region.dataset.asyncLoading;
  }
};

for (const region of document.querySelectorAll("[data-async-region]")) {
  loadAsyncRegion(region);
}

document.addEventListener("click", (event) => {
  const retry = event.target.closest("[data-async-retry]");
  if (retry) {
    const region = retry.closest("[data-async-region]");
    if (region) loadAsyncRegion(region);
    return;
  }
  const reload = event.target.closest("[data-async-reload]");
  if (reload) {
    const region = document.getElementById(reload.dataset.asyncReload);
    if (region) loadAsyncRegion(region);
  }
});

for (const button of document.querySelectorAll("[data-copy-target]")) {
  button.addEventListener("click", async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    const section = button.closest(".copy-section");
    const status = section?.querySelector("[data-copy-status]");
    if (!target || !status) {
      return;
    }

    const value = target.textContent;
    const item = button.dataset.copyLabel || "value";
    try {
      await navigator.clipboard.writeText(value);
      status.textContent = `${item[0].toUpperCase()}${item.slice(1)} copied to clipboard.`;
      const label = button.querySelector("span");
      if (label) {
        const original = label.textContent;
        label.textContent = "Copied";
        window.setTimeout(() => {
          label.textContent = original;
        }, 1800);
      }
    } catch {
      const selection = window.getSelection();
      const range = document.createRange();
      range.selectNodeContents(target);
      selection.removeAllRanges();
      selection.addRange(range);
      status.textContent = `Clipboard access was unavailable. The ${item} has been selected for you.`;
    }
  });
}

for (const button of document.querySelectorAll("[data-reveal-secret]")) {
  button.addEventListener("click", () => {
    const input = button.closest(".secret-input")?.querySelector("input");
    if (!input) {
      return;
    }
    const revealing = input.type === "password";
    const secretLabel = button.dataset.secretLabel || "password";
    input.type = revealing ? "text" : "password";
    button.textContent = revealing ? "Hide" : "Show";
    button.setAttribute("aria-label", `${revealing ? "Hide" : "Show"} ${secretLabel}`);
    button.setAttribute("aria-pressed", revealing ? "true" : "false");
  });
}

const enrollmentResult = document.querySelector("[data-enrollment-result]");
if (enrollmentResult) {
  window.history.replaceState(null, "", "/servers");
}

const errorSummary = document.querySelector("[data-error-summary]");
if (errorSummary && !document.querySelector('[aria-invalid="true"]')) {
  errorSummary.focus();
}

const configurationDeploymentForm = document.querySelector("form.configuration-form");
if (configurationDeploymentForm) {
  const submitButton = configurationDeploymentForm.querySelector("[data-submit-button]");
  const resultNotice = configurationDeploymentForm.querySelector(
    "[data-configuration-deployment-result]",
  );
  const statusBadge = document.querySelector("[data-configuration-deployment-status]");
  const statusLabel = statusBadge?.querySelector("[data-configuration-deployment-label]");
  const originalSubmitLabel = submitButton?.textContent.trim();

  const showDeploymentStatus = (status) => {
    if (statusBadge && statusLabel && status.status_label) {
      statusBadge.hidden = false;
      statusBadge.className = `status status--${status.status_class || "offline"}`;
      statusLabel.textContent = status.status_label;
    }
  };

  const finishDeployment = (status) => {
    showDeploymentStatus(status);
    if (submitButton) {
      submitButton.disabled = false;
      submitButton.textContent = originalSubmitLabel;
    }
    if (resultNotice) {
      const succeeded = status.status_class === "online";
      resultNotice.hidden = false;
      resultNotice.className = `notice ${succeeded ? "notice--success" : "notice--error"}`;
      resultNotice.textContent = succeeded
        ? "Configuration deployed."
        : status.diagnostic || `${status.status_label || "Deployment"} did not complete successfully.`;
      resultNotice.focus();
    }
  };

  const pollSubmittedDeployment = async (statusURL) => {
    try {
      const response = await fetch(statusURL, {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (redirectForExpiredSession(response)) return;
      if (!response.ok) {
        window.setTimeout(() => pollSubmittedDeployment(statusURL), 5000);
        return;
      }
      const status = await response.json();
      showDeploymentStatus(status);
      if (status.pending === true) {
        window.setTimeout(() => pollSubmittedDeployment(statusURL), 2000);
        return;
      }
      finishDeployment(status);
    } catch {
      window.setTimeout(() => pollSubmittedDeployment(statusURL), 5000);
    }
  };

  configurationDeploymentForm.addEventListener("submit", async (event) => {
    if (event.defaultPrevented) {
      return;
    }
    event.preventDefault();
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = submitButton.dataset.submitLabel || "Deploying…";
    }
    if (resultNotice) {
      resultNotice.hidden = false;
      resultNotice.className = "notice";
      resultNotice.textContent = "The agent is validating and activating this configuration.";
    }
    try {
      const response = await fetch(configurationDeploymentForm.action, {
        method: "POST",
        body: new URLSearchParams(new FormData(configurationDeploymentForm)),
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (redirectForExpiredSession(response)) return;
      const responseText = await response.text();
      let data = {};
      try {
        data = JSON.parse(responseText);
      } catch {
        const errorDocument = new DOMParser().parseFromString(responseText, "text/html");
        data.error = errorDocument.querySelector(".notice--error")?.textContent.trim();
        if (!data.error && response.headers.get("Content-Type")?.startsWith("text/plain")) {
          data.error = responseText.trim();
        }
      }
      if (!response.ok || !data.status_url) {
        throw new Error(data.error || "The configuration could not be queued.");
      }
      await pollSubmittedDeployment(data.status_url);
    } catch (error) {
      if (submitButton) {
        submitButton.disabled = false;
        submitButton.textContent = originalSubmitLabel;
      }
      if (resultNotice) {
        resultNotice.hidden = false;
        resultNotice.className = "notice notice--error";
        resultNotice.textContent = error.message;
        resultNotice.focus();
      }
    }
  });
}

for (const form of document.querySelectorAll("form")) {
  form.addEventListener("submit", (event) => {
    window.setTimeout(() => {
      if (event.defaultPrevented) {
        return;
      }
      const button = form.querySelector("[data-submit-button]");
      if (button) {
        button.disabled = true;
        button.textContent = button.dataset.submitLabel || "Creating…";
      }
    }, 0);
  });
}

const pendingDeployment = document.querySelector("[data-deployment-refresh-url]");
if (pendingDeployment) {
  let lastInteraction = Date.now();
  for (const eventName of ["keydown", "pointerdown", "focusin"]) {
    document.addEventListener(eventName, () => {
      lastInteraction = Date.now();
    }, { passive: true });
  }

  const refreshWhenIdle = () => {
    if (document.hidden || Date.now() - lastInteraction < 3000) {
      window.setTimeout(refreshWhenIdle, 1000);
      return;
    }
    window.location.replace(pendingDeployment.dataset.deploymentRefreshUrl);
  };

  const pollDeployment = async () => {
    try {
      const response = await fetch(
        pendingDeployment.dataset.deploymentStatusUrl,
        {
          cache: "no-store",
          credentials: "same-origin",
          headers: { Accept: "application/json" },
        },
      );
      if (redirectForExpiredSession(response)) return;
      if (!response.ok) {
        window.setTimeout(pollDeployment, 5000);
        return;
      }
      const status = await response.json();
      if (status.pending === true) {
        window.setTimeout(pollDeployment, 2000);
        return;
      }
      refreshWhenIdle();
    } catch {
      window.setTimeout(pollDeployment, 5000);
    }
  };

  window.setTimeout(pollDeployment, 2000);
}

const versionCatalogURL = document.body.dataset.versionCatalogUrl;
if (versionCatalogURL) {
  const fetchCatalog = async (catalog) => {
    const response = await fetch(
      `${versionCatalogURL}?catalog=${encodeURIComponent(catalog)}`,
      {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      },
    );
    if (redirectForExpiredSession(response)) {
      throw new Error("Your session expired.");
    }
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || `version catalog returned ${response.status}`);
    }
    return data;
  };

  const loadAgentCatalog = async () => {
    const loadingIndicators = document.querySelectorAll("[data-agent-catalog-loading]");
    const refreshButton = document.querySelector("[data-master-version-refresh]");
    const agentInput = document.querySelector("[data-latest-agent-version]");
    const agentLabel = document.querySelector("[data-latest-agent-version-label]");
    const warning = document.querySelector("[data-agent-catalog-warning]");
    const masterLabel = document.querySelector("[data-master-latest-label]");
    const masterButton = document.querySelector("[data-master-update-button]");
    const masterButtonText = document.querySelector("[data-master-button-text]");

    if (refreshButton) {
      refreshButton.disabled = true;
      refreshButton.textContent = "Checking…";
    }
    for (const indicator of loadingIndicators) indicator.hidden = false;
    if (masterLabel) masterLabel.textContent = "checking…";
    if (masterButton) masterButton.disabled = true;
    if (warning) {
      warning.textContent = "";
      warning.hidden = true;
    }

    try {
      const data = await fetchCatalog("agent");
      const latest = data.latest_version || "";
      if (agentInput) agentInput.value = latest;
      if (agentLabel) agentLabel.textContent = latest || "unavailable";
      if (warning && data.agent_catalog_warning) {
        warning.textContent = data.agent_catalog_warning;
        warning.hidden = false;
      }

      if (masterLabel) masterLabel.textContent = latest || "unavailable";
      if (masterButton && masterButtonText && latest) {
        if (latest === document.body.dataset.masterVersion) {
          masterButton.disabled = true;
          masterButtonText.textContent = "Master is up to date";
        } else {
          masterButton.disabled = false;
          masterButtonText.textContent = `Update master to ${latest}`;
        }
      } else if (masterButton && masterButtonText) {
        masterButton.disabled = true;
        masterButtonText.textContent = "Latest version unavailable";
      }
    } catch (error) {
      if (agentInput) agentInput.value = "";
      if (agentLabel) agentLabel.textContent = "unavailable";
      if (masterLabel) masterLabel.textContent = "unavailable";
      if (masterButton) masterButton.disabled = true;
      if (masterButtonText) masterButtonText.textContent = "Latest version unavailable";
      if (warning) {
        warning.textContent = error.message;
        warning.hidden = false;
      }
    } finally {
      for (const indicator of loadingIndicators) indicator.hidden = true;
      if (refreshButton) {
        refreshButton.disabled = false;
        refreshButton.textContent = "Check again";
      }
    }
  };

  if (document.querySelector("[data-latest-agent-version], [data-master-latest-label]")) {
    loadAgentCatalog();
  }
  document
    .querySelector("[data-master-version-refresh]")
    ?.addEventListener("click", loadAgentCatalog);

  if (document.querySelector("[data-sing-box-version-select]")) {
    const singBoxLoading = document.querySelector("[data-sing-box-catalog-loading]");
    const fleetSelect = document.querySelector("[data-fleet-sing-box-select]");
    const fleetSubmit = document.querySelector("[data-fleet-sing-box-submit]");
    if (singBoxLoading) singBoxLoading.hidden = false;
    if (fleetSelect) fleetSelect.disabled = true;
    if (fleetSubmit) fleetSubmit.disabled = true;
    fetchCatalog("sing-box").then((data) => {
      const select = document.querySelector("[data-sing-box-version-select]");
      if (select) {
        select.innerHTML = "";
        for (const version of data.sing_box_versions || []) {
          const option = document.createElement("option");
          option.value = version.Tag;
          option.textContent = `${version.Tag} (${version.Branch})`;
          select.appendChild(option);
        }
        if (data.latest_sing_box_version) {
          select.value = data.latest_sing_box_version;
        }
        if (select.options.length === 0) {
          const option = document.createElement("option");
          option.value = "";
          option.textContent = "No versions available";
          select.appendChild(option);
        }
        const hasVersion = select.value !== "";
        if (fleetSelect) fleetSelect.disabled = !hasVersion;
        if (fleetSubmit) fleetSubmit.disabled = !hasVersion;
      }
      const warning = document.querySelector("[data-sing-box-catalog-warning]");
      const info = document.querySelector("[data-sing-box-catalog-info]");
      if (warning && data.sing_box_catalog_warning) {
        warning.textContent = data.sing_box_catalog_warning;
        warning.hidden = false;
        if (info) info.hidden = true;
      }
    }).catch((error) => {
      const select = document.querySelector("[data-sing-box-version-select]");
      if (select) {
        select.innerHTML = '<option value="">Versions unavailable</option>';
      }
      if (fleetSelect) fleetSelect.disabled = true;
      if (fleetSubmit) fleetSubmit.disabled = true;
      const warning = document.querySelector("[data-sing-box-catalog-warning]");
      if (warning) {
        warning.textContent = error.message;
        warning.hidden = false;
      }
    }).finally(() => {
      if (singBoxLoading) singBoxLoading.hidden = true;
    });
  }
}

const masterUpdateStatusURL = document.body.dataset.masterUpdateStatusUrl;
const masterUpdateForm = document.querySelector("[data-master-update-form]");

const monitorMasterUpdate = (statusURL, message, returnLink = null) => {
  let attempts = 0;
  const pollMasterUpdate = async () => {
    attempts++;
    try {
      const response = await fetch(statusURL, {
        cache: "no-store",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (response.status === 401 || response.status >= 500) {
        throw new Error("master is restarting");
      }
      if (!response.ok) {
        throw new Error(`update status returned ${response.status}`);
      }
      const status = await response.json();
      if (status.status === "applied") {
        if (message) message.textContent = "Update complete. Reconnecting to the updated master…";
        window.setTimeout(() => window.location.replace("/settings"), 700);
        return;
      }
      if (status.status === "failed") {
        if (message) message.textContent = status.diagnostic || "The master update failed.";
        if (returnLink) returnLink.hidden = false;
        return;
      }
      if (message && attempts > 1) {
        message.textContent = "The master is restarting. Waiting for it to come back online…";
      }
    } catch {
      if (message) message.textContent = "The master is restarting. Waiting for it to come back online…";
    }
    window.setTimeout(pollMasterUpdate, 1500);
  };
  window.setTimeout(pollMasterUpdate, 500);
};

if (masterUpdateStatusURL) {
  monitorMasterUpdate(
    masterUpdateStatusURL,
    document.querySelector("[data-master-update-message]"),
    document.querySelector("[data-master-update-return]"),
  );
}

if (masterUpdateForm) {
  masterUpdateForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const progress = document.querySelector("[data-master-update-progress]");
    const button = masterUpdateForm.querySelector("[data-master-update-button]");
    if (progress) {
      progress.hidden = false;
      progress.textContent = "Scheduling the verified update…";
    }
    if (button) button.disabled = true;
    try {
      const response = await fetch(masterUpdateForm.action, {
        method: "POST",
        body: new URLSearchParams(new FormData(masterUpdateForm)),
        credentials: "same-origin",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok || !data.status_url) {
        throw new Error(data.error || `update request returned ${response.status}`);
      }
      if (progress) progress.textContent = "Installing the update. Waiting for the master to restart…";
      monitorMasterUpdate(data.status_url, progress);
    } catch (error) {
      if (progress) progress.textContent = error.message || "The master update could not be scheduled.";
      if (button) button.disabled = false;
    }
  });
}
