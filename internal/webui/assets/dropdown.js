"use strict";

(() => {
  const t = (text) => window.theatropolisText?.(text) || text;
  const enhanced = new WeakMap();
  const controls = new Set();
  const optionBatchSize = 80;
  let openControl = null;
  let menuSequence = 0;

  const fieldLabel = (select) => {
    const field = select.closest(".field");
    return field?.querySelector(":scope > span")?.textContent.trim() || select.name || t("Option");
  };

  const selectedLabel = (control) =>
    control.select.selectedOptions[0]?.textContent || t("Select an option");

  const svgPart = (name, attributes) => {
    const element = document.createElementNS("http://www.w3.org/2000/svg", name);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
    return element;
  };

  const availableButtons = (control) =>
    control.optionButtons.filter((button) => !button.disabled && !button.hidden);

  const positionMenu = (control) => {
    const bounds = control.trigger.getBoundingClientRect();
    const gap = Number.parseFloat(
      getComputedStyle(document.documentElement).getPropertyValue("--select-menu-gap"),
    ) || 6;
    const viewportWidth = document.documentElement.clientWidth;
    const viewportMargin = 8;
    const menuWidth = Math.max(
      0,
      Math.min(bounds.width, viewportWidth - viewportMargin * 2),
    );
    const availableBelow = window.innerHeight - bounds.bottom - gap - 12;
    const availableAbove = bounds.top - gap - 12;
    const maxHeight = Math.max(0, Math.min(360, Math.max(availableBelow, availableAbove)));
    control.menu.style.width = `${menuWidth}px`;
    control.menu.style.maxHeight = `${maxHeight}px`;
    control.menu.style.left =
      `${Math.max(
        viewportMargin,
        Math.min(bounds.left, viewportWidth - menuWidth - viewportMargin),
      )}px`;
    if (availableBelow >= 180 || availableBelow >= availableAbove) {
      control.menu.style.top = `${bounds.bottom + gap}px`;
      control.menu.style.bottom = "auto";
    } else {
      control.menu.style.top = "auto";
      control.menu.style.bottom = `${window.innerHeight - bounds.top + gap}px`;
    }
  };

  const readOptions = (control) => {
    control.optionRecords = Array.from(control.select.options, (option) => ({
      value: option.value,
      label: option.textContent,
      disabled: option.disabled,
    }));
  };

  const clearRenderedOptions = (control) => {
    control.options.replaceChildren();
    control.empty.hidden = true;
    control.optionButtons = [];
    control.filteredRecords = [];
    control.renderOffset = 0;
  };

  const renderNextBatch = (control, reset = false) => {
    if (reset) {
      clearRenderedOptions(control);
      const normalized = control.query.trim().toLocaleLowerCase();
      control.filteredRecords = control.optionRecords.filter((record) =>
        !normalized ||
        record.label.toLocaleLowerCase().includes(normalized) ||
        record.value.toLocaleLowerCase().includes(normalized),
      );
    }
    if (control.filteredRecords.length === 0) {
      control.empty.hidden = false;
      control.options.append(control.empty);
      return;
    }
    const records = control.filteredRecords.slice(
      control.renderOffset,
      control.renderOffset + optionBatchSize,
    );
    if (records.length === 0) return;
    const fragment = document.createDocumentFragment();
    for (const record of records) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "select-box__option";
      button.setAttribute("role", "option");
      button.setAttribute("aria-selected", String(record.value === control.select.value));
      button.dataset.value = record.value;
      button.disabled = record.disabled;
      button.textContent = record.label;
      fragment.append(button);
      control.optionButtons.push(button);
    }
    control.renderOffset += records.length;
    control.options.append(fragment);
  };

  const filterOptions = (control, query = "") => {
    control.query = query;
    control.clear.hidden = query.length === 0;
    if (control.open) renderNextBatch(control, true);
  };

  const closeDropdown = (control = openControl, restoreFocus = false) => {
    if (!control || !control.open) return;
    control.open = false;
    control.trigger.setAttribute("aria-expanded", "false");
    control.wrapper.classList.remove("is-open");
    if (typeof control.menu.hidePopover === "function" && control.menu.matches(":popover-open")) {
      control.menu.hidePopover();
    }
    control.menu.hidden = true;
    control.filter.value = "";
    control.query = "";
    control.clear.hidden = true;
    clearRenderedOptions(control);
    if (openControl === control) openControl = null;
    if (restoreFocus) control.trigger.focus();
  };

  const focusOption = (control, index) => {
    const available = availableButtons(control);
    if (available.length === 0) return;
    const normalized = (index + available.length) % available.length;
    available[normalized].focus({ preventScroll: true });
    available[normalized].scrollIntoView({ block: "nearest" });
  };

  const focusFilter = (control) => {
    window.requestAnimationFrame(() => {
      if (!control.open) return;
      control.filter.focus({ preventScroll: true });
    });
  };

  const openDropdown = (control, focusTarget = "filter") => {
    if (control.select.disabled) return;
    if (!control.open) {
      closeDropdown();
      const currentRoot = control.select.closest("dialog") || document.body;
      if (control.menu.parentElement !== currentRoot) currentRoot.append(control.menu);
      control.open = true;
      openControl = control;
      control.trigger.setAttribute("aria-expanded", "true");
      control.wrapper.classList.add("is-open");
      control.menu.hidden = false;
      control.filter.value = "";
      control.query = "";
      filterOptions(control);
      if (typeof control.menu.showPopover === "function") {
        control.menu.showPopover();
      }
      positionMenu(control);
    }
    if (focusTarget === "selected") {
      const available = availableButtons(control);
      const selectedIndex = available.findIndex(
        (button) => button.getAttribute("aria-selected") === "true",
      );
      focusOption(control, selectedIndex < 0 ? 0 : selectedIndex);
    } else if (focusTarget === "filter") {
      focusFilter(control);
    }
  };

  const selectValue = (control, value) => {
    if (control.select.disabled) return;
    control.select.value = value;
    control.select.dispatchEvent(new Event("input", { bubbles: true }));
    control.select.dispatchEvent(new Event("change", { bubbles: true }));
    syncControl(control, false);
    closeDropdown(control, true);
  };

  function syncControl(control, rebuild = true) {
    if (rebuild) readOptions(control);
    control.value.textContent = selectedLabel(control);
    control.trigger.tabIndex = control.select.disabled ? -1 : 0;
    control.trigger.setAttribute("aria-disabled", String(control.select.disabled));
    control.wrapper.classList.toggle("is-disabled", control.select.disabled);
    control.trigger.setAttribute("aria-label", fieldLabel(control.select));
    const invalid = control.select.getAttribute("aria-invalid") === "true";
    control.wrapper.classList.toggle("is-invalid", invalid);
    if (control.open) renderNextBatch(control, true);
    else clearRenderedOptions(control);
    if (control.select.disabled) closeDropdown(control);
  }

  const enhanceSelect = (select) => {
    if (enhanced.has(select) || select.closest("[data-native-select]")) return;

    const wrapper = document.createElement("span");
    wrapper.className = "select-box";
    wrapper.dataset.customSelect = "";

    const trigger = document.createElement("span");
    trigger.className = "select-box__trigger";
    trigger.tabIndex = 0;
    trigger.setAttribute("role", "combobox");
    trigger.setAttribute("aria-haspopup", "listbox");
    trigger.setAttribute("aria-expanded", "false");

    const value = document.createElement("span");
    value.className = "select-box__value";

    const chevron = document.createElement("span");
    chevron.className = "select-box__chevron";
    chevron.setAttribute("aria-hidden", "true");
    const chevronSVG = svgPart("svg", { viewBox: "0 0 20 20" });
    chevronSVG.append(svgPart("path", { d: "m5.5 7.5 4.5 4.5 4.5-4.5" }));
    chevron.append(chevronSVG);
    trigger.append(value, chevron);

    const menu = document.createElement("span");
    menu.className = "select-box__menu";
    menu.setAttribute("popover", "manual");
    menu.hidden = true;

    const search = document.createElement("span");
    search.className = "select-box__search";
    const searchIcon = document.createElement("span");
    searchIcon.className = "select-box__search-icon";
    searchIcon.setAttribute("aria-hidden", "true");
    const searchSVG = svgPart("svg", { viewBox: "0 0 20 20" });
    searchSVG.append(
      svgPart("circle", { cx: "8.5", cy: "8.5", r: "5.25" }),
      svgPart("path", { d: "m12.5 12.5 4 4" }),
    );
    searchIcon.append(searchSVG);
    const filter = document.createElement("input");
    filter.type = "search";
    filter.className = "select-box__filter";
    filter.autocomplete = "off";
    filter.spellcheck = false;
    filter.placeholder = t("Filter options");
    filter.setAttribute("aria-label", t("Filter options"));
    const clear = document.createElement("button");
    clear.type = "button";
    clear.className = "select-box__clear";
    clear.setAttribute("aria-label", t("Clear filter"));
    clear.textContent = "×";
    clear.hidden = true;
    search.append(searchIcon, filter, clear);

    const options = document.createElement("span");
    options.className = "select-box__options";
    options.id = `select-box-menu-${++menuSequence}`;
    options.setAttribute("role", "listbox");
    trigger.setAttribute("aria-controls", options.id);
    menu.append(search, options);

    select.before(wrapper);
    select.classList.add("select-box__native");
    select.tabIndex = -1;
    wrapper.append(select, trigger);
    const menuRoot = select.closest("dialog") || document.body;
    menuRoot.append(menu);

    const control = {
      select,
      wrapper,
      trigger,
      value,
      menu,
      search,
      filter,
      clear,
      options,
      empty: document.createElement("span"),
      optionButtons: [],
      optionRecords: [],
      filteredRecords: [],
      renderOffset: 0,
      open: false,
      query: "",
      composing: false,
    };
    control.empty.className = "select-box__empty";
    control.empty.textContent = t("No matching options");
    control.empty.hidden = true;
    enhanced.set(select, control);
    controls.add(control);
    syncControl(control);

    trigger.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      if (control.select.disabled) return;
      if (control.open) closeDropdown(control, true);
      else openDropdown(control);
    });
    trigger.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        openDropdown(control, "selected");
      } else if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openDropdown(control);
      } else if (event.key === "Escape") {
        event.preventDefault();
        closeDropdown(control, true);
      } else if (
        event.key.length === 1 &&
        !event.altKey &&
        !event.ctrlKey &&
        !event.metaKey
      ) {
        event.preventDefault();
        openDropdown(control);
        control.filter.value = event.key;
        control.query = event.key;
        filterOptions(control, control.query);
        focusFilter(control);
      }
    });
    filter.addEventListener("compositionstart", () => {
      control.composing = true;
    });
    filter.addEventListener("compositionend", () => {
      control.composing = false;
      control.query = filter.value;
      filterOptions(control, control.query);
    });
    filter.addEventListener("input", () => {
      if (control.composing) return;
      control.query = filter.value;
      filterOptions(control, control.query);
    });
    filter.addEventListener("keydown", (event) => {
      if (event.isComposing || control.composing) return;
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        focusOption(control, event.key === "ArrowDown" ? 0 : -1);
      } else if (event.key === "Escape") {
        event.preventDefault();
        closeDropdown(control, true);
      } else if (event.key === "Tab") {
        closeDropdown(control);
      }
    });
    clear.addEventListener("click", (event) => {
      event.preventDefault();
      filter.value = "";
      control.query = "";
      filterOptions(control);
      filter.focus();
    });
    options.addEventListener("click", (event) => {
      if (!(event.target instanceof Element)) return;
      const button = event.target.closest(".select-box__option");
      if (!button || button.disabled) return;
      event.preventDefault();
      event.stopPropagation();
      selectValue(control, button.dataset.value);
    });
    options.addEventListener("scroll", () => {
      if (
        options.scrollTop + options.clientHeight >= options.scrollHeight - 32 &&
        control.renderOffset < control.filteredRecords.length
      ) {
        renderNextBatch(control);
      }
    });
    menu.addEventListener("keydown", (event) => {
      if (event.target === filter) return;
      const available = availableButtons(control);
      const current = available.indexOf(document.activeElement);
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        focusOption(control, current + (event.key === "ArrowDown" ? 1 : -1));
      } else if (event.key === "Home" || event.key === "End") {
        event.preventDefault();
        focusOption(control, event.key === "Home" ? 0 : available.length - 1);
      } else if (event.key === "Escape") {
        event.preventDefault();
        closeDropdown(control, true);
      } else if (event.key === "Tab") {
        closeDropdown(control);
      } else if (
        event.key.length === 1 &&
        !event.altKey &&
        !event.ctrlKey &&
        !event.metaKey
      ) {
        event.preventDefault();
        filter.focus();
        filter.value = event.key;
        control.query = event.key;
        filterOptions(control, control.query);
      }
    });
    select.addEventListener("change", () => syncControl(control, false));
    select.addEventListener("focus", () => trigger.focus());
    select.addEventListener("invalid", () => {
      control.wrapper.classList.add("is-invalid");
      window.setTimeout(() => trigger.focus(), 0);
    });
  };

  for (const select of document.querySelectorAll("select")) {
    enhanceSelect(select);
  }

  const observer = new MutationObserver((mutations) => {
    const selects = new Set();
    for (const mutation of mutations) {
      if (mutation.target instanceof HTMLSelectElement) {
        selects.add(mutation.target);
      } else if (
        mutation.target instanceof HTMLOptionElement ||
        mutation.target.parentElement instanceof HTMLOptionElement
      ) {
        const option =
          mutation.target instanceof HTMLOptionElement
            ? mutation.target
            : mutation.target.parentElement;
        const select = option.closest("select");
        if (select) selects.add(select);
      }
      for (const node of mutation.addedNodes) {
        if (!(node instanceof Element)) continue;
        if (node instanceof HTMLSelectElement) selects.add(node);
        for (const nested of node.querySelectorAll("select")) selects.add(nested);
      }
    }
    for (const select of selects) {
      enhanceSelect(select);
      const control = enhanced.get(select);
      if (control) syncControl(control);
    }
    for (const control of controls) {
      if (control.select.isConnected && control.wrapper.isConnected) continue;
      closeDropdown(control);
      control.menu.remove();
      controls.delete(control);
    }
  });
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["disabled", "selected", "aria-invalid"],
    characterData: true,
  });

  document.addEventListener("pointerdown", (event) => {
    if (
      openControl &&
      !openControl.wrapper.contains(event.target) &&
      !openControl.menu.contains(event.target)
    ) {
      closeDropdown();
    }
  });
  document.addEventListener(
    "reset",
    (event) => {
      window.setTimeout(() => {
        for (const select of event.target.querySelectorAll("select")) {
          const control = enhanced.get(select);
          if (control) syncControl(control, false);
        }
      }, 0);
    },
    true,
  );
  window.addEventListener("pageshow", () => {
    for (const select of document.querySelectorAll("select")) {
      const control = enhanced.get(select);
      if (control) syncControl(control, false);
    }
  });
  window.addEventListener("resize", () => closeDropdown());
  window.addEventListener("scroll", (event) => {
    // The options list owns dropdown scrolling. Close only when another
    // surface scrolls and moves the trigger.
    if (
      openControl &&
      (event.target === openControl.options || openControl.options.contains(event.target))
    ) {
      return;
    }
    closeDropdown();
  }, true);
})();
