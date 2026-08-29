"use strict";

(() => {
  const forms = Array.from(document.querySelectorAll("[data-subscription-rule-form]"));
  if (forms.length === 0) return;

  const t = (text) => window.theatropolisText?.(text) || text;
  const catalogKind = (match) => match === "geosite" || match === "geoip" ? match : "";

  const elementsFor = (form) => ({
    match: form.querySelector("[data-subscription-rule-match]"),
    value: form.querySelector("[data-subscription-rule-value]"),
    textField: form.querySelector("[data-subscription-text-field]"),
    textarea: form.querySelector("[data-subscription-rule-textarea]"),
    ruleSetField: form.querySelector("[data-subscription-rule-set-field]"),
    ruleSetLabel: form.querySelector("[data-subscription-rule-set-label]"),
    ruleSet: form.querySelector("[data-subscription-rule-set]"),
    status: form.querySelector("[data-subscription-rule-set-status]"),
    retry: form.querySelector("[data-subscription-rule-set-retry]"),
    noResolveField: form.querySelector("[data-subscription-no-resolve-field]"),
    noResolve: form.querySelector("[data-subscription-no-resolve]"),
  });

  const setStatus = (elements, message = "", retry = false) => {
    const copy = elements.status?.querySelector("span");
    if (!elements.status || !copy || !elements.retry) return;
    copy.textContent = message;
    elements.status.hidden = message === "";
    elements.retry.hidden = !retry;
  };

  const loadCatalog = (kind) => {
    if (typeof window.theatropolisRuleSetCatalog !== "function") {
      return Promise.reject(new Error("rule-set catalog is unavailable"));
    }
    return window.theatropolisRuleSetCatalog(kind);
  };

  const populateOptions = (elements, kind, options) => {
    const current = elements.ruleSet.value;
    const labels = new Map();
    if (current) labels.set(current, current.replaceAll("\n", ", "));
    for (const option of options) labels.set(option, option);

    elements.ruleSet.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.disabled = true;
    placeholder.textContent = kind === "geosite"
      ? t("Select a Geosite rule set")
      : t("Select a GeoIP rule set");
    elements.ruleSet.append(placeholder);
    for (const [value, label] of labels) {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = label;
      elements.ruleSet.append(option);
    }
    elements.ruleSet.value = current;
    if (!current) placeholder.selected = true;
  };

  const compactOptions = (elements) => {
    const current = elements.ruleSet.value;
    elements.ruleSet.replaceChildren();
    const option = document.createElement("option");
    option.value = current;
    option.textContent = current ? current.replaceAll("\n", ", ") : t("Loading…");
    option.disabled = !current;
    option.selected = true;
    elements.ruleSet.append(option);
  };

  const enableCatalog = async (form, kind) => {
    const elements = elementsFor(form);
    elements.ruleSet.disabled = catalogKind(elements.match.value) !== kind;
    setStatus(elements, t("Loading…"));
    try {
      const options = await loadCatalog(kind);
      if (catalogKind(elements.match.value) !== kind) return;
      populateOptions(elements, kind, options);
      elements.ruleSet.disabled = false;
      setStatus(elements);
    } catch (_error) {
      if (catalogKind(elements.match.value) !== kind) return;
      elements.ruleSet.disabled = false;
      setStatus(elements, t("Rule set catalog unavailable."), true);
    }
  };

  const syncForm = (form) => {
    const elements = elementsFor(form);
    const kind = catalogKind(elements.match.value);
    elements.textField.hidden = Boolean(kind);
    elements.textarea.disabled = Boolean(kind);
    elements.textarea.required = !kind;
    elements.ruleSetField.hidden = !kind;
    elements.ruleSet.required = Boolean(kind);
    elements.ruleSet.disabled = !kind;
    if (kind) {
      if (elements.ruleSet.dataset.ruleSetKind && elements.ruleSet.dataset.ruleSetKind !== kind) {
        elements.ruleSet.value = "";
        compactOptions(elements);
      }
      elements.ruleSet.dataset.ruleSetKind = kind;
      elements.ruleSetLabel.textContent = kind === "geosite" ? "Geosite" : "GeoIP";
    }
    const supportsNoResolve = elements.match.value === "ip_cidr" || elements.match.value === "geoip";
    elements.noResolveField.hidden = !supportsNoResolve;
    elements.noResolve.disabled = !supportsNoResolve;
    elements.value.value = kind ? elements.ruleSet.value : elements.textarea.value;
    if (kind && form.closest("dialog")?.open) enableCatalog(form, kind);
  };

  for (const form of forms) {
    const elements = elementsFor(form);
    elements.match.addEventListener("change", () => syncForm(form));
    elements.textarea.addEventListener("input", () => {
      if (!catalogKind(elements.match.value)) elements.value.value = elements.textarea.value;
    });
    elements.ruleSet.addEventListener("change", () => {
      elements.value.value = elements.ruleSet.value;
    });
    elements.retry.addEventListener("click", () => {
      const kind = catalogKind(elements.match.value);
      if (kind) enableCatalog(form, kind);
    });
    form.addEventListener("formdata", (event) => {
      const supportsNoResolve = elements.match.value === "ip_cidr" || elements.match.value === "geoip";
      event.formData.set("no_resolve", supportsNoResolve && elements.noResolve.checked ? "yes" : "no");
    });
    form.addEventListener("submit", () => {
      elements.value.value = catalogKind(elements.match.value)
        ? elements.ruleSet.value
        : elements.textarea.value;
    });
    syncForm(form);
  }

  const initialMatch = new URLSearchParams(window.location.search).get("rule_match");
  if (initialMatch === "geosite" || initialMatch === "geoip") {
    const form = document.querySelector("dialog[open] [data-subscription-rule-form]");
    if (form) {
      const elements = elementsFor(form);
      elements.match.value = initialMatch;
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
    if (elements.ruleSet.options.length > 2) compactOptions(elements);
    setStatus(elements);
  }, true);

  const ruleList = document.querySelector("[data-subscription-rule-list]");
  if (!ruleList) return;
  const reorderStatus = document.querySelector("[data-subscription-reorder-status]");
  let draggedRule = null;
  let draggedRuleOrder = [];
  let dragPreview = null;
  let dragHideFrame = 0;
  let dropAccepted = false;
  const reorderAnimations = new WeakMap();
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

  const ruleCards = () => [...ruleList.querySelectorAll(":scope > [data-subscription-rule-card]")];
  const ruleOrder = () => ruleCards().map((card) => card.dataset.ruleId).join(",");

  const updateRulePositions = () => {
    ruleCards().forEach((card, index) => {
      const position = String(index + 1);
      const badge = card.querySelector(".subscription-rule__order");
      const handlePosition = card.querySelector("[data-subscription-rule-handle-position]");
      if (badge) badge.textContent = position;
      if (handlePosition) handlePosition.textContent = position;
    });
  };

  const settleRuleAnimations = () => {
    for (const card of ruleCards()) reorderAnimations.get(card)?.cancel();
  };

  const cardPositions = () => {
    settleRuleAnimations();
    return new Map(ruleCards().map((card) => [card, card.getBoundingClientRect().top]));
  };

  const animateRuleReflow = (positions) => {
    if (reducedMotion.matches) return;
    for (const card of ruleCards()) {
      if (card === draggedRule) continue;
      const previousTop = positions.get(card);
      if (previousTop === undefined) continue;
      const delta = previousTop - card.getBoundingClientRect().top;
      if (Math.abs(delta) < 1 || typeof card.animate !== "function") continue;
      reorderAnimations.get(card)?.cancel();
      const animation = card.animate(
        [
          { transform: `translateY(${delta}px)` },
          { transform: "translateY(0)" },
        ],
        { duration: 160, easing: "cubic-bezier(0.2, 0.75, 0.25, 1)" },
      );
      reorderAnimations.set(card, animation);
      const release = () => {
        if (reorderAnimations.get(card) === animation) reorderAnimations.delete(card);
      };
      animation.addEventListener("finish", release, { once: true });
      animation.addEventListener("cancel", release, { once: true });
    }
  };

  const removeDragPreview = () => {
    dragPreview?.remove();
    dragPreview = null;
  };

  const createDragPreview = (card, event) => {
    removeDragPreview();
    const bounds = card.getBoundingClientRect();
    dragPreview = card.cloneNode(true);
    dragPreview.removeAttribute("draggable");
    dragPreview.removeAttribute("data-subscription-rule-card");
    dragPreview.removeAttribute("data-rule-id");
    dragPreview.setAttribute("aria-hidden", "true");
    dragPreview.setAttribute("inert", "");
    dragPreview.className = "subscription-rule__drag-preview";
    dragPreview.style.width = `${bounds.width}px`;
    document.body.append(dragPreview);
    if (event.dataTransfer) {
      const offsetX = Math.max(0, Math.min(bounds.width, event.clientX - bounds.left));
      const offsetY = Math.max(0, Math.min(bounds.height, event.clientY - bounds.top));
      event.dataTransfer.setDragImage(dragPreview, offsetX, offsetY);
    }
  };

  const restoreRuleOrder = (cards) => {
    const positions = cardPositions();
    for (const card of cards) ruleList.append(card);
    updateRulePositions();
    animateRuleReflow(positions);
  };

  const showReorderStatus = (message, error = false) => {
    if (!reorderStatus) return;
    reorderStatus.textContent = message;
    reorderStatus.classList.toggle("sr-only", !error);
    reorderStatus.classList.toggle("is-error", error);
  };

  const setReorderPending = (pending) => {
    if (pending) {
      ruleList.dataset.reorderPending = "true";
      ruleList.setAttribute("aria-busy", "true");
    } else {
      delete ruleList.dataset.reorderPending;
      ruleList.removeAttribute("aria-busy");
    }
    for (const card of ruleCards()) {
      card.draggable = !pending;
      const handle = card.querySelector("[data-subscription-rule-handle]");
      if (handle) handle.disabled = pending;
    }
  };

  const redirectedToLogin = (response) => {
    try {
      return response.status === 401 || (response.redirected && new URL(response.url).pathname === "/login");
    } catch (_error) {
      return response.status === 401;
    }
  };

  const persistRuleOrder = async (previousCards, movedCard, restoreFocus = false) => {
    setReorderPending(true);
    showReorderStatus("");
    try {
      const response = await fetch(ruleList.dataset.reorderUrl || "", {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        },
        credentials: "same-origin",
        body: new URLSearchParams({
          csrf_token: ruleList.dataset.csrfToken || "",
          rule_ids: ruleOrder(),
        }),
      });
      if (redirectedToLogin(response)) {
        window.location.assign("/login");
        return;
      }
      if (!response.ok || response.redirected) throw new Error("subscription Rule reorder rejected");
      const position = ruleCards().indexOf(movedCard) + 1;
      showReorderStatus(t("Rule moved to position {position}.").replace("{position}", String(position)));
    } catch (_error) {
      restoreRuleOrder(previousCards);
      showReorderStatus(t("Rule order could not be saved. Previous order restored."), true);
    } finally {
      setReorderPending(false);
      if (restoreFocus) movedCard.querySelector("[data-subscription-rule-handle]")?.focus();
    }
  };

  ruleList.addEventListener("dragstart", (event) => {
    const card = event.target instanceof Element
      ? event.target.closest("[data-subscription-rule-card]")
      : null;
    if (!card || card.parentElement !== ruleList || ruleList.dataset.reorderPending === "true") return;
    draggedRule = card;
    draggedRuleOrder = ruleCards();
    dropAccepted = false;
    createDragPreview(card, event);
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "move";
      event.dataTransfer.setData("text/plain", card.dataset.ruleId || "subscription-rule");
    }
    dragHideFrame = window.requestAnimationFrame(() => card.classList.add("is-dragging"));
  });

  ruleList.addEventListener("dragover", (event) => {
    if (!draggedRule || !(event.target instanceof Element) || !ruleList.contains(event.target)) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
    const reference = ruleCards()
      .filter((card) => card !== draggedRule)
      .find((card) => {
        const bounds = card.getBoundingClientRect();
        return event.clientY < bounds.top + bounds.height / 2;
      }) || null;
    if (reference === draggedRule.nextElementSibling || (!reference && !draggedRule.nextElementSibling)) return;
    const positions = cardPositions();
    ruleList.insertBefore(draggedRule, reference);
    animateRuleReflow(positions);
  });

  ruleList.addEventListener("drop", (event) => {
    if (!draggedRule || !(event.target instanceof Element) || !ruleList.contains(event.target)) return;
    event.preventDefault();
    dropAccepted = true;
  });

  ruleList.addEventListener("dragend", () => {
    if (!draggedRule) return;
    window.cancelAnimationFrame(dragHideFrame);
    dragHideFrame = 0;
    const movedCard = draggedRule;
    const previousCards = draggedRuleOrder;
    const previousOrder = previousCards.map((card) => card.dataset.ruleId).join(",");
    movedCard.classList.remove("is-dragging");
    removeDragPreview();
    draggedRule = null;
    draggedRuleOrder = [];
    if (!dropAccepted) {
      restoreRuleOrder(previousCards);
      return;
    }
    dropAccepted = false;
    updateRulePositions();
    if (ruleOrder() !== previousOrder) persistRuleOrder(previousCards, movedCard);
  });

  ruleList.addEventListener("keydown", (event) => {
    const handle = event.target instanceof Element
      ? event.target.closest("[data-subscription-rule-handle]")
      : null;
    if (!handle || (event.key !== "ArrowUp" && event.key !== "ArrowDown") || ruleList.dataset.reorderPending === "true") return;
    const card = handle.closest("[data-subscription-rule-card]");
    const cards = ruleCards();
    const index = cards.indexOf(card);
    const targetIndex = index + (event.key === "ArrowUp" ? -1 : 1);
    if (index < 0 || targetIndex < 0 || targetIndex >= cards.length) return;
    event.preventDefault();
    if (targetIndex < index) ruleList.insertBefore(card, cards[targetIndex]);
    else ruleList.insertBefore(card, cards[targetIndex].nextElementSibling);
    updateRulePositions();
    persistRuleOrder(cards, card, true);
  });
})();
