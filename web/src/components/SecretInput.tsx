import React, { useState } from "react";
import { useApp } from "../context/AppContext";

interface SecretInputProps extends Omit<React.InputHTMLAttributes<HTMLInputElement>, "type"> {
  secretLabel?: string;
}

export const SecretInput: React.FC<SecretInputProps> = ({ secretLabel = "password", ...props }) => {
  const { t } = useApp();
  const [visible, setVisible] = useState(false);

  return (
    <span className="secret-input">
      <input {...props} type={visible ? "text" : "password"} />
      <button
        type="button"
        className="button button--secondary button--small"
        aria-pressed={visible}
        aria-label={`${visible ? t("Hide") : t("Show")} ${t(secretLabel)}`}
        onClick={() => setVisible((prev) => !prev)}
      >
        {visible ? t("Hide") : t("Show")}
      </button>
    </span>
  );
};
