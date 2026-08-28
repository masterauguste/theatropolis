"use strict";

(() => {
  const forms = Array.from(document.querySelectorAll("[data-subscription-rule-form]"));
  if (forms.length === 0) return;

  const t = (text) => window.theatropolisText?.(text) || text;

  const elementsFor = (form) => ({
    match: form.querySelector("[data-subscription-rule-match]"),
    value: form.querySelector("[data-subscription-rule-value]"),
    textField: form.querySelector("[data-subscription-text-field]"),
    textarea: form.querySelector("[data-subscription-rule-textarea]"),
    geositeField: form.querySelector("[data-subscription-geosite-field]"),
    geosite: form.querySelector("[data-subscription-geosite]"),
    status: form.querySelector("[data-subscription-geosite-status]"),
    retry: form.querySelector("[data-subscription-geosite-retry]"),
  });

  const setStatus = (elements, message = "", retry = false) => {
    const copy = elements.status?.querySelector("span");
    if (!elements.status || !copy || !elements.retry) return;
    copy.textContent = message;
    elements.status.hidden = message === "";
    elements.retry.hidden = !retry;
  };

  const loadCatalog = () => {
    if (typeof window.theatropolisRuleSetCatalog !== "function") {
      return Promise.reject(new Error("rule-set catalog is unavailable"));
    }
    return window.theatropolisRuleSetCatalog("geosite");
  };

  const populateOptions = (elements, options) => {
    const current = elements.geosite.value;
    const labels = new Map();
    if (current) labels.set(current, current.replaceAll("\n", ", "));
    for (const option of options) labels.set(option, option);

    elements.geosite.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.disabled = true;
    placeholder.textContent = t("Select a Geosite rule set");
    elements.geosite.append(placeholder);
    for (const [value, label] of labels) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = label;
      elements.geosite.append(option);
    }
    elements.geosite.value = current;
    if (!current) placeholder.selected = true;
  };

  const compactOptions = (elements) => {
    const current = elements.geosite.value;
    elements.geosite.replaceChildren();
    const option = document.createElement("option");
    option.value = current;
    option.textContent = current ? current.replaceAll("\n", ", ") : t("Loading Geosite options…");
    option.disabled = !current;
    option.selected = true;
    elements.geosite.append(option);
  };

  const enableCatalog = async (form) => {
    const elements = elementsFor(form);
    elements.geosite.disabled = elements.match.value !== "geosite";
    setStatus(elements, t("Loading Geosite options…"));
    try {
      const options = await loadCatalog();
      populateOptions(elements, options);
      elements.geosite.disabled = elements.match.value !== "geosite";
      setStatus(elements);
    } catch (_error) {
      elements.geosite.disabled = elements.match.value !== "geosite";
      setStatus(elements, t("Geosite catalog unavailable."), true);
    }
  };

  const syncForm = (form) => {
    const elements = elementsFor(form);
    const geosite = elements.match.value === "geosite";
    elements.textField.hidden = geosite;
    elements.textarea.disabled = geosite;
    elements.textarea.required = !geosite;
    elements.geositeField.hidden = !geosite;
    elements.geosite.required = geosite;
    elements.geosite.disabled = !geosite;
    elements.value.value = geosite ? elements.geosite.value : elements.textarea.value;
    if (geosite && form.closest("dialog")?.open) enableCatalog(form);
  };

  for (const form of forms) {
    const elements = elementsFor(form);
    elements.match.addEventListener("change", () => syncForm(form));
    elements.textarea.addEventListener("input", () => {
      if (elements.match.value !== "geosite") elements.value.value = elements.textarea.value;
    });
    elements.geosite.addEventListener("change", () => {
      elements.value.value = elements.geosite.value;
    });
    form.addEventListener("submit", () => {
      elements.value.value = elements.match.value === "geosite"
        ? elements.geosite.value
        : elements.textarea.value;
    });
    syncForm(form);
  }

  const initialMatch = new URLSearchParams(window.location.search).get("rule_match");
  if (initialMatch === "geosite") {
    const form = document.querySelector("dialog[open] [data-subscription-rule-form]");
    if (form) {
      const elements = elementsFor(form);
      elements.match.value = "geosite";
      syncForm(form);
    }
    const cleanURL = new URL(window.location.href);
    cleanURL.searchParams.delete("rule_match");
    window.history.replaceState(null, "", cleanURL);
  }

  document.addEventListener("click", (event) => {
    const trigger = event.target.closest?.("[data-dialog-open]");
    if (!trigger) return;
    const form = document.getElementById(trigger.dataset.dialogOpen)
      ?.querySelector("[data-subscription-rule-form]");
    if (form) syncForm(form);
  });

  document.addEventListener("close", (event) => {
    const form = event.target.querySelector?.("[data-subscription-rule-form]");
    if (!form) return;
    const elements = elementsFor(form);
    if (elements.geosite.options.length > 2) compactOptions(elements);
    setStatus(elements);
  }, true);
})();
