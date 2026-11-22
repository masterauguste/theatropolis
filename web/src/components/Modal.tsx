import React, { useEffect, useRef } from "react";
import { useApp } from "../context/AppContext";

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: React.ReactNode;
  eyebrow?: React.ReactNode;
  size?: "compact" | "form" | "wide" | "default";
  className?: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  hideClose?: boolean;
}

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  eyebrow,
  size = "default",
  className = "",
  children,
  footer,
  hideClose = false,
}) => {
  const { t } = useApp();
  const dialogRef = useRef<HTMLDialogElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const dialog = dialogRef.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      const previouslyFocused = document.activeElement;
      const focusedInsideBeforeShow =
        previouslyFocused instanceof HTMLElement &&
        dialog.contains(previouslyFocused) &&
        previouslyFocused !== closeButtonRef.current;
      dialog.showModal();
      if (focusedInsideBeforeShow) {
        previouslyFocused.focus({ preventScroll: true });
      } else if (document.activeElement === closeButtonRef.current) {
        dialog.focus({ preventScroll: true });
      }
    } else if (!open && dialog.open) {
      dialog.close();
    }
  }, [open]);

  if (!open) return null;

  const surfaceClass = [
    "modal__surface",
    size === "compact" ? "modal__surface--compact" : "",
    size === "form" ? "modal__surface--form" : "",
    size === "wide" ? "modal__surface--wide" : "",
  ]
    .filter(Boolean)
    .join(" ");

  return (
    <dialog
      ref={dialogRef}
      tabIndex={-1}
      className={`modal ${className}`.trim()}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className={surfaceClass}>
        <header className="modal__header">
          <div>
            {eyebrow && <p className="eyebrow">{eyebrow}</p>}
            <h2>{title}</h2>
          </div>
          {!hideClose && (
            <button
              ref={closeButtonRef}
              type="button"
              className="button button--secondary button--icon-only"
              aria-label={t("Close")}
              onClick={onClose}
            >
              ×
            </button>
          )}
        </header>
        {children}
        {footer && <footer className="modal__footer">{footer}</footer>}
      </div>
    </dialog>
  );
};
