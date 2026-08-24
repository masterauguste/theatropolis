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
  const muxEnabled = protocol === "shadowsocks" &&
    form.querySelector("[data-proxy-mux-enabled]")?.value === "1";
  const muxBrutal = muxEnabled &&
    form.querySelector("[data-proxy-mux-brutal]")?.value === "1";
  for (const field of form.querySelectorAll("[data-proxy-mux-options]")) {
    field.hidden = !muxEnabled;
  }
  for (const field of form.querySelectorAll("[data-proxy-mux-brutal-bandwidth]")) {
    field.hidden = !muxBrutal;
  }
}

for (const select of document.querySelectorAll("[data-proxy-protocol]")) {
  updateProxyEndpointForm(select);
  select.addEventListener("change", () => updateProxyEndpointForm(select));
  select.closest("form")?.querySelector("[data-proxy-tls-mode]")?.addEventListener(
    "change",
    () => updateProxyEndpointForm(select),
  );
  for (const muxSelect of select.closest("form")?.querySelectorAll(
    "[data-proxy-mux-enabled], [data-proxy-mux-brutal]",
  ) || []) {
    muxSelect.addEventListener("change", () => updateProxyEndpointForm(select));
  }
}

for (const select of document.querySelectorAll("[data-proxy-match]")) {
  const update = () => {
    const values = select.closest("form")?.querySelector("[data-proxy-match-values]");
    if (values) values.hidden = select.value === "none";
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

const proxyDeployment = document.querySelector("[data-proxy-deployment][data-status-url]");
if (proxyDeployment) {
  const pollProxyDeployment = async () => {
    try {
      const response = await fetch(proxyDeployment.dataset.statusUrl, {
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (!response.ok) throw new Error("status unavailable");
      const status = await response.json();
      if (!status.active) {
        window.location.reload();
        return;
      }
    } catch (_) {
      // Keep the current status visible and retry transient failures.
    }
    window.setTimeout(pollProxyDeployment, 2000);
  };
  window.setTimeout(pollProxyDeployment, 1000);
}

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
  const manageHopButton = event.target.closest("[data-proxy-hop-manage]");
  if (manageHopButton) {
    const dialog = document.getElementById("proxy-hop-manager");
    const hopID = manageHopButton.dataset.proxyHopManage;
    if (!(dialog instanceof HTMLDialogElement)) return;
    const views = [...dialog.querySelectorAll("[data-proxy-hop-manager-view]")];
    const selected = views.find((view) => view.dataset.proxyHopManagerView === hopID);
    if (!selected) return;
    for (const view of views) {
      view.hidden = view !== selected;
    }
    const sourceDialog = manageHopButton.closest("dialog");
    if (sourceDialog instanceof HTMLDialogElement && sourceDialog !== dialog && sourceDialog.open) {
      sourceDialog.close();
    }
    const treeButton = [...document.querySelectorAll("[data-proxy-inspector-open]")]
      .find((button) => button.dataset.proxyInspectorOpen === `hop-${hopID}`);
    dialogTriggers.set(dialog, treeButton || manageHopButton);
    if (!dialog.open) dialog.showModal();
    return;
  }

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
    dialogTriggers.set(dialog, button);
    if (!dialog.open) dialog.showModal();
    return;
  }

  const closeButton = event.target.closest("[data-dialog-close]");
  if (closeButton) {
    closeButton.closest("dialog")?.close();
  }
});

const initialManagedHop = new URLSearchParams(window.location.search).get("manage_hop");
if (initialManagedHop) {
  const manageHopButton = [...document.querySelectorAll("[data-proxy-hop-manage]")]
    .find((button) => button.dataset.proxyHopManage === initialManagedHop);
  manageHopButton?.click();
  const cleanURL = new URL(window.location.href);
  cleanURL.searchParams.delete("manage_hop");
  window.history.replaceState(null, "", cleanURL);
}

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
    if (singBoxLoading) singBoxLoading.hidden = false;
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
