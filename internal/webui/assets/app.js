"use strict";

const dialogTriggers = new WeakMap();

for (const button of document.querySelectorAll("[data-dialog-open]")) {
  button.addEventListener("click", () => {
    const dialog = document.getElementById(button.dataset.dialogOpen);
    if (!(dialog instanceof HTMLDialogElement)) {
      return;
    }
    dialogTriggers.set(dialog, button);
    dialog.showModal();
  });
}

for (const dialog of document.querySelectorAll("dialog.modal")) {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) {
      dialog.close();
    }
  });
  dialog.addEventListener("close", () => {
    dialogTriggers.get(dialog)?.focus();
  });
  for (const button of dialog.querySelectorAll("[data-dialog-close]")) {
    button.addEventListener("click", () => dialog.close());
  }
}

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
    if (!response.ok) {
      throw new Error(`version catalog returned ${response.status}`);
    }
    return response.json();
  };

  if (document.querySelector("[data-latest-agent-version], [data-master-latest-label]")) {
  fetchCatalog("agent").then((data) => {
    const latest = data.latest_version || "";
    const agentInput = document.querySelector("[data-latest-agent-version]");
    const agentLabel = document.querySelector("[data-latest-agent-version-label]");
    const agentWarning = document.querySelector("[data-agent-catalog-warning]");
    if (agentInput) agentInput.value = latest;
    if (agentLabel) agentLabel.textContent = latest || "unavailable";
    if (agentWarning && data.agent_catalog_warning) {
      agentWarning.textContent = data.agent_catalog_warning;
      agentWarning.hidden = false;
    }

    const masterLabel = document.querySelector("[data-master-latest-label]");
    const masterButton = document.querySelector("[data-master-update-button]");
    const masterButtonText = document.querySelector("[data-master-button-text]");
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
  }).catch(() => {
    const agentLabel = document.querySelector("[data-latest-agent-version-label]");
    const masterLabel = document.querySelector("[data-master-latest-label]");
    const masterButtonText = document.querySelector("[data-master-button-text]");
    if (agentLabel) agentLabel.textContent = "unavailable";
    if (masterLabel) masterLabel.textContent = "unavailable";
    if (masterButtonText) masterButtonText.textContent = "Latest version unavailable";
  });
  }

  if (document.querySelector("[data-sing-box-version-select]")) {
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
  }).catch(() => {
    const select = document.querySelector("[data-sing-box-version-select]");
    if (select) {
      select.innerHTML = '<option value="">Versions unavailable</option>';
    }
    const warning = document.querySelector("[data-sing-box-catalog-warning]");
    if (warning) {
      warning.textContent = "GitHub releases could not be loaded.";
      warning.hidden = false;
    }
  });
  }
}
