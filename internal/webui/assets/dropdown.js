"use strict";

(() => {
  const enhanced = new WeakMap();
  let openControl = null;
  let menuSequence = 0;

  const fieldLabel = (select) => {
    const field = select.closest(".field");
    return field?.querySelector(":scope > span")?.textContent.trim() || select.name || "Option";
  };

  const selectedLabel = (control) =>
    control.select.selectedOptions[0]?.textContent || "Select an option";

  const availableButtons = (control) =>
    control.optionButtons.filter((button) => !button.disabled && !button.hidden);

  const positionMenu = (control) => {
    const bounds = control.trigger.getBoundingClientRect();
    const gap = 6;
    const availableBelow = window.innerHeight - bounds.bottom - gap - 12;
    const availableAbove = bounds.top - gap - 12;
    const maxHeight = Math.max(120, Math.min(320, Math.max(availableBelow, availableAbove)));
    control.menu.style.width = `${bounds.width}px`;
    control.menu.style.maxHeight = `${maxHeight}px`;
    control.menu.style.left =
      `${Math.max(8, Math.min(bounds.left, window.innerWidth - bounds.width - 8))}px`;
    if (availableBelow >= 150 || availableBelow >= availableAbove) {
      control.menu.style.top = `${bounds.bottom + gap}px`;
      control.menu.style.bottom = "auto";
    } else {
      control.menu.style.top = "auto";
      control.menu.style.bottom = `${window.innerHeight - bounds.top + gap}px`;
    }
  };

  const filterOptions = (control, query = "") => {
    const normalized = query.trim().toLocaleLowerCase();
    for (const button of control.optionButtons) {
      const label = button.textContent.trim().toLocaleLowerCase();
      const value = button.dataset.value.toLocaleLowerCase();
      button.hidden = Boolean(normalized) &&
        !label.includes(normalized) &&
        !value.includes(normalized);
    }
    const anyVisible = availableButtons(control).length > 0;
    control.empty.hidden = anyVisible;
  };

  const closeDropdown = (control = openControl, restoreFocus = false) => {
    if (!control || !control.open) return;
    control.open = false;
    control.input.setAttribute("aria-expanded", "false");
    control.wrapper.classList.remove("is-open");
    if (typeof control.menu.hidePopover === "function" && control.menu.matches(":popover-open")) {
      control.menu.hidePopover();
    }
    control.menu.hidden = true;
    control.input.value = selectedLabel(control);
    control.query = "";
    filterOptions(control);
    if (openControl === control) openControl = null;
    if (restoreFocus) {
      control.suppressFocusOpen = true;
      control.input.focus();
      control.suppressFocusOpen = false;
    }
  };

  const focusOption = (control, index) => {
    const available = availableButtons(control);
    if (available.length === 0) return;
    const normalized = (index + available.length) % available.length;
    available[normalized].focus();
  };

  const openDropdown = (control, focusSelected = false) => {
    if (control.select.disabled) return;
    if (!control.open) {
      closeDropdown();
      control.open = true;
      openControl = control;
      control.input.setAttribute("aria-expanded", "true");
      control.wrapper.classList.add("is-open");
      control.menu.hidden = false;
      control.query = "";
      if (typeof control.menu.showPopover === "function") {
        control.menu.showPopover();
      }
      filterOptions(control);
      positionMenu(control);
    }
    if (focusSelected) {
      const available = availableButtons(control);
      const selectedIndex = available.findIndex(
        (button) => button.getAttribute("aria-selected") === "true",
      );
      focusOption(control, selectedIndex < 0 ? 0 : selectedIndex);
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

  const rebuildOptions = (control) => {
    control.menu.replaceChildren();
    control.optionButtons = Array.from(control.select.options, (option) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "select-box__option";
      button.setAttribute("role", "option");
      button.dataset.value = option.value;
      button.disabled = option.disabled;
      button.textContent = option.textContent;
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        selectValue(control, option.value);
      });
      control.menu.append(button);
      return button;
    });
    control.empty = document.createElement("span");
    control.empty.className = "select-box__empty";
    control.empty.textContent = "No matching options";
    control.empty.hidden = true;
    control.menu.append(control.empty);
  };

  function syncControl(control, rebuild = true) {
    if (rebuild) rebuildOptions(control);
    if (!control.open) control.input.value = selectedLabel(control);
    control.input.disabled = control.select.disabled;
    control.wrapper.classList.toggle("is-disabled", control.select.disabled);
    control.input.setAttribute("aria-label", fieldLabel(control.select));
    const invalid = control.select.getAttribute("aria-invalid") === "true";
    control.wrapper.classList.toggle("is-invalid", invalid);
    const selected = control.select.selectedOptions[0];
    for (const button of control.optionButtons) {
      const isSelected = selected && button.dataset.value === selected.value;
      button.setAttribute("aria-selected", String(Boolean(isSelected)));
    }
    filterOptions(control, control.query);
    if (control.select.disabled) closeDropdown(control);
  }

  const enhanceSelect = (select) => {
    if (enhanced.has(select) || select.closest("[data-native-select]")) return;

    const wrapper = document.createElement("span");
    wrapper.className = "select-box";
    wrapper.dataset.customSelect = "";

    const trigger = document.createElement("span");
    trigger.className = "select-box__trigger";

    const input = document.createElement("input");
    input.type = "text";
    input.className = "select-box__input";
    input.autocomplete = "off";
    input.spellcheck = false;
    input.setAttribute("role", "combobox");
    input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-haspopup", "listbox");
    input.setAttribute("aria-expanded", "false");

    const chevron = document.createElement("span");
    chevron.className = "select-box__chevron";
    chevron.setAttribute("aria-hidden", "true");
    chevron.innerHTML =
      '<svg viewBox="0 0 20 20"><path d="m5.5 7.5 4.5 4.5 4.5-4.5"/></svg>';
    trigger.append(input, chevron);

    const menu = document.createElement("span");
    menu.className = "select-box__menu";
    menu.id = `select-box-menu-${++menuSequence}`;
    menu.setAttribute("role", "listbox");
    menu.setAttribute("popover", "manual");
    menu.hidden = true;
    input.setAttribute("aria-controls", menu.id);

    select.before(wrapper);
    select.classList.add("select-box__native");
    select.tabIndex = -1;
    wrapper.append(select, trigger, menu);

    const control = {
      select,
      wrapper,
      trigger,
      input,
      menu,
      empty: null,
      optionButtons: [],
      open: false,
      suppressFocusOpen: false,
      query: "",
    };
    enhanced.set(select, control);
    syncControl(control);

    trigger.addEventListener("pointerdown", (event) => {
      if (event.target === input || control.select.disabled) return;
      event.preventDefault();
      input.focus();
      openDropdown(control);
    });
    input.addEventListener("focus", () => {
      if (control.suppressFocusOpen) return;
      openDropdown(control);
      input.select();
    });
    input.addEventListener("input", () => {
      openDropdown(control);
      control.query = input.value;
      filterOptions(control, control.query);
    });
    input.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown" || event.key === "ArrowUp") {
        event.preventDefault();
        openDropdown(control);
        focusOption(control, event.key === "ArrowDown" ? 0 : -1);
      } else if (event.key === "Enter") {
        const first = availableButtons(control)[0];
        if (control.open && first) {
          event.preventDefault();
          first.click();
        }
      } else if (event.key === "Escape") {
        event.preventDefault();
        closeDropdown(control, true);
      } else if (event.key === "Tab") {
        closeDropdown(control);
      }
    });
    menu.addEventListener("keydown", (event) => {
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
      }
    });
    select.addEventListener("change", () => syncControl(control, false));
    select.addEventListener("focus", () => input.focus());
    select.addEventListener("invalid", () => {
      control.wrapper.classList.add("is-invalid");
      window.setTimeout(() => input.focus(), 0);
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
  });
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ["disabled", "selected", "aria-invalid"],
    characterData: true,
  });

  document.addEventListener("pointerdown", (event) => {
    if (openControl && !openControl.wrapper.contains(event.target)) {
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
  window.addEventListener("scroll", () => closeDropdown(), true);
})();
