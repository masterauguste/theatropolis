import React, { useCallback, useEffect, useState } from "react";
import { fetchRuleSetCatalog } from "../api/client";
import { useApp } from "../context/AppContext";
import { SelectBox } from "./SelectBox";

interface ProxyRuleMatchFieldsProps {
  match: string;
  values: string;
  onMatchChange: (match: string) => void;
  onValuesChange: (values: string) => void;
  allowAllFallback?: boolean;
  includeLegacyRuleSet?: boolean;
}

export const ProxyRuleMatchFields: React.FC<ProxyRuleMatchFieldsProps> = ({
  match,
  values,
  onMatchChange,
  onValuesChange,
  allowAllFallback = true,
  includeLegacyRuleSet = false,
}) => {
  const { t } = useApp();
  const kind = match === "geosite" || match === "geoip" ? match : "";
  const [catalogOptions, setCatalogOptions] = useState<string[]>([]);
  const [catalogLoading, setCatalogLoading] = useState(false);
  const [catalogError, setCatalogError] = useState("");

  const loadCatalog = useCallback(async (targetKind: "geosite" | "geoip") => {
    setCatalogLoading(true);
    setCatalogError("");
    try {
      const opts = await fetchRuleSetCatalog(targetKind);
      setCatalogOptions(opts);
    } catch {
      setCatalogError(t("Rule set catalog unavailable."));
    } finally {
      setCatalogLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (kind === "geosite" || kind === "geoip") {
      void loadCatalog(kind);
    }
  }, [kind, loadCatalog]);

  const matchOptions = [
    ...(includeLegacyRuleSet || match === "rule_set"
      ? [{ value: "rule_set", label: t("Legacy custom rule — choose a supported match") }]
      : []),
    ...(allowAllFallback ? [{ value: "none", label: t("ALL — fallback") }] : []),
    { value: "protocol", label: t("Protocol") },
    { value: "domain", label: t("Domain") },
    { value: "domain_suffix", label: t("Domain suffix") },
    { value: "domain_keyword", label: t("Domain keyword") },
    { value: "domain_regex", label: t("Domain regex") },
    { value: "ip_cidr", label: t("IP / CIDR") },
    { value: "geosite", label: "Geosite" },
    { value: "geoip", label: "GeoIP" },
    { value: "network", label: t("Network") },
  ];

  const ruleSetSelectOptions = (() => {
    const items: { value: string; label: string; disabled?: boolean }[] = [
      {
        value: "",
        label: kind === "geosite" ? t("Select a Geosite rule set") : t("Select a GeoIP rule set"),
        disabled: true,
      },
    ];
    if (values && !catalogOptions.includes(values)) {
      items.push({ value: values, label: values.replaceAll("\n", ", ") });
    }
    for (const opt of catalogOptions) {
      items.push({ value: opt, label: opt });
    }
    return items;
  })();

  return (
    <>
      <label className="field">
        <span>{t("Match type")}</span>
        <SelectBox
          searchable={false}
          value={match}
          onChange={(nextMatch) => {
            const nextKind = nextMatch === "geosite" || nextMatch === "geoip" ? nextMatch : "";
            onMatchChange(nextMatch);
            if (nextMatch === "none" || (nextKind && nextKind !== kind)) {
              onValuesChange("");
            }
          }}
          options={matchOptions}
        />
      </label>

      {match !== "none" && !kind && (
        <label className="field">
          <span>{t("Values")}</span>
          <textarea
            className="resize-none"
            data-route-field="match_values"
            rows={4}
            placeholder={t("One value per line or comma-separated")}
            value={values}
            onChange={(e) => onValuesChange(e.target.value)}
            required
          />
        </label>
      )}

      {kind && (
        <label className="field">
          <span>{kind === "geosite" ? "Geosite" : "GeoIP"}</span>
          <SelectBox
            value={values}
            onChange={onValuesChange}
            options={ruleSetSelectOptions}
            disabled={catalogLoading && !values}
            placeholder={catalogLoading ? t("Loading…") : undefined}
          />
          {catalogLoading && <small className="subscription-geosite-status">{t("Loading…")}</small>}
          {catalogError && (
            <small className="subscription-geosite-status">
              <span>{catalogError}</span>{" "}
              <button
                type="button"
                className="button-link"
                onClick={() => void loadCatalog(kind)}
              >
                {t("Retry")}
              </button>
            </small>
          )}
        </label>
      )}
    </>
  );
};
