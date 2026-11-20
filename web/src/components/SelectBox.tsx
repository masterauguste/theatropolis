import React, { useEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { useApp } from "../context/AppContext";

export interface SelectOption {
  value: string;
  label: string;
  detail?: string;
  status?: "reachable" | "reference" | "unreachable" | "stale" | "pending" | "offline" | string;
  disabled?: boolean;
  hidden?: boolean;
}

interface SelectBoxProps {
  value: string;
  onChange: (value: string) => void;
  options: SelectOption[];
  disabled?: boolean;
  invalid?: boolean;
  ariaLabel?: string;
  placeholder?: string;
  searchable?: boolean;
}

const BATCH_SIZE = 80;
const ALLOWED_STATUSES = new Set(["reachable", "reference", "unreachable", "stale", "pending", "offline"]);

export const SelectBox: React.FC<SelectBoxProps> = ({
  value,
  onChange,
  options,
  disabled = false,
  invalid = false,
  ariaLabel,
  placeholder,
  searchable = true,
}) => {
  const { t } = useApp();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [renderLimit, setRenderLimit] = useState(BATCH_SIZE);
  const [menuStyle, setMenuStyle] = useState<React.CSSProperties>({});

  const wrapperRef = useRef<HTMLSpanElement>(null);
  const triggerRef = useRef<HTMLSpanElement>(null);
  const menuRef = useRef<HTMLSpanElement>(null);
  const filterRef = useRef<HTMLInputElement>(null);

  const visibleOptions = useMemo(() => options.filter((opt) => !opt.hidden), [options]);
  const selected = useMemo(
    () => visibleOptions.find((opt) => opt.value === value) || options.find((opt) => opt.value === value),
    [options, visibleOptions, value],
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLocaleLowerCase();
    if (!q) return visibleOptions;
    return visibleOptions.filter(
      (opt) =>
        opt.label.toLocaleLowerCase().includes(q) ||
        (opt.detail || "").toLocaleLowerCase().includes(q) ||
        opt.value.toLocaleLowerCase().includes(q),
    );
  }, [visibleOptions, query]);

  const positionMenu = () => {
    const trigger = triggerRef.current;
    if (!trigger) return;
    const bounds = trigger.getBoundingClientRect();
    const gap = 6;
    const margin = 8;
    const vw = window.visualViewport?.width || document.documentElement.clientWidth;
    const vh = window.visualViewport?.height || window.innerHeight;
    const vLeft = window.visualViewport?.offsetLeft || 0;
    const vTop = window.visualViewport?.offsetTop || 0;
    const width = Math.max(160, Math.min(bounds.width, vw - margin * 2));
    const availBelow = vh - (bounds.bottom - vTop) - gap - 12;
    const availAbove = bounds.top - vTop - gap - 12;
    const maxHeight = Math.max(120, Math.min(360, Math.max(availBelow, availAbove)));
    const placeBelow = availBelow >= 180 || availBelow >= availAbove;
    const left = Math.max(vLeft + margin, Math.min(bounds.left, vLeft + vw - width - margin));
    const menuHeight = menuRef.current?.getBoundingClientRect().height || Math.min(maxHeight, 260);
    const desiredTop = placeBelow ? bounds.bottom + gap : bounds.top - gap - menuHeight;
    const top = Math.max(vTop + margin, Math.min(desiredTop, vTop + vh - menuHeight - margin));
    setMenuStyle({
      position: "fixed",
      left: `${left}px`,
      top: `${top}px`,
      width: `${width}px`,
      maxHeight: `${maxHeight}px`,
      bottom: "auto",
      zIndex: 9999,
    });
  };

  useEffect(() => {
    if (!open) return;
    positionMenu();
    const frame = window.requestAnimationFrame(() => {
      positionMenu();
      if (searchable) filterRef.current?.focus({ preventScroll: true });
    });
    const onResize = () => positionMenu();
    const onClickOutside = (event: MouseEvent) => {
      const target = event.target as Node;
      if (!wrapperRef.current?.contains(target) && !menuRef.current?.contains(target)) {
        setOpen(false);
      }
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        setOpen(false);
        triggerRef.current?.focus();
      }
    };
    window.addEventListener("resize", onResize);
    window.addEventListener("scroll", onResize, true);
    document.addEventListener("mousedown", onClickOutside);
    document.addEventListener("keydown", onKeyDown, true);
    return () => {
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", onResize);
      window.removeEventListener("scroll", onResize, true);
      document.removeEventListener("mousedown", onClickOutside);
      document.removeEventListener("keydown", onKeyDown, true);
    };
  }, [open, searchable]);

  const portalRoot = useMemo(() => {
    const dialog = wrapperRef.current?.closest("dialog");
    return dialog || document.body;
  }, [open]);

  const openMenu = () => {
    if (disabled) return;
    setQuery("");
    setRenderLimit(BATCH_SIZE);
    setOpen((prev) => !prev);
  };

  const pick = (opt: SelectOption) => {
    if (opt.disabled) return;
    if (opt.value !== value) {
      onChange(opt.value);
    }
    setOpen(false);
    triggerRef.current?.focus();
  };

  const renderContent = (opt: SelectOption | undefined) => {
    if (!opt) return placeholder || t("Select an option");
    if (!opt.detail) return opt.label;
    const status = opt.status && ALLOWED_STATUSES.has(opt.status) ? opt.status : "";
    return (
      <>
        <span className="select-box__option-copy">
          <span className="select-box__option-title">{opt.label}</span>
          <span className="select-box__option-detail">{opt.detail}</span>
        </span>
        {status && (
          <span className={`select-box__option-signal select-box__option-signal--${status}`} aria-hidden="true" />
        )}
      </>
    );
  };

  return (
    <span
      ref={wrapperRef}
      className={`select-box ${open ? "is-open" : ""} ${disabled ? "is-disabled" : ""} ${invalid ? "is-invalid" : ""}`.trim()}
      data-custom-select=""
    >
      <span
        ref={triggerRef}
        className="select-box__trigger"
        tabIndex={disabled ? -1 : 0}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-disabled={disabled}
        aria-label={ariaLabel}
        onClick={(e) => {
          e.preventDefault();
          openMenu();
        }}
        onKeyDown={(e) => {
          if (disabled) return;
          if (e.key === "Enter" || e.key === " " || e.key === "ArrowDown" || e.key === "ArrowUp") {
            e.preventDefault();
            if (!open) openMenu();
          }
        }}
      >
        <span className={`select-box__value ${selected?.detail ? "select-box__value--rich" : ""}`}>
          {renderContent(selected)}
        </span>
        <span className="select-box__chevron" aria-hidden="true">
          <svg viewBox="0 0 20 20">
            <path d="m5.5 7.5 4.5 4.5 4.5-4.5" />
          </svg>
        </span>
      </span>

      {open &&
        createPortal(
          <span ref={menuRef} className="select-box__menu" style={menuStyle}>
            {searchable && (
              <span className="select-box__search">
                <span className="select-box__search-icon" aria-hidden="true">
                  <svg viewBox="0 0 20 20">
                    <circle cx="8.5" cy="8.5" r="5.25" />
                    <path d="m12.5 12.5 4 4" />
                  </svg>
                </span>
                <input
                  ref={filterRef}
                  type="search"
                  className="select-box__filter"
                  value={query}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder={t("Filter options")}
                  aria-label={t("Filter options")}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setRenderLimit(BATCH_SIZE);
                  }}
                />
                {query && (
                  <button
                    type="button"
                    className="select-box__clear"
                    aria-label={t("Clear filter")}
                    onClick={() => {
                      setQuery("");
                      filterRef.current?.focus();
                    }}
                  >
                    ×
                  </button>
                )}
              </span>
            )}
            <span
              className="select-box__options"
              role="listbox"
              onScroll={(e) => {
                const el = e.currentTarget;
                if (el.scrollTop + el.clientHeight >= el.scrollHeight - 60 && renderLimit < filtered.length) {
                  setRenderLimit((prev) => prev + BATCH_SIZE);
                }
              }}
            >
              {filtered.length === 0 ? (
                <span className="select-box__empty">{t("No matching options")}</span>
              ) : (
                filtered.slice(0, renderLimit).map((opt) => (
                  <button
                    key={opt.value}
                    type="button"
                    className="select-box__option"
                    role="option"
                    aria-selected={opt.value === value}
                    disabled={opt.disabled}
                    onClick={() => pick(opt)}
                  >
                    {renderContent(opt)}
                  </button>
                ))
              )}
            </span>
          </span>,
          portalRoot,
        )}
    </span>
  );
};
