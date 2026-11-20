import React from "react";
import type { MembershipPlanView } from "../api/types";
import { useApp } from "../context/AppContext";
import { SelectBox } from "./SelectBox";

export interface MembershipPlanDraft {
  quotaMode: string;
  quotaGiB: string;
  expirationMode: string;
  subscriptionValue: string;
  subscriptionUnit: string;
}

export function planToDraft(plan?: MembershipPlanView | null): MembershipPlanDraft {
  return {
    quotaMode: plan?.QuotaMode || "unlimited",
    quotaGiB: plan?.QuotaGiB || "",
    expirationMode: plan?.ExpirationMode || "none",
    subscriptionValue: plan?.SubscriptionValue || "",
    subscriptionUnit: plan?.SubscriptionUnit || "months",
  };
}

export function planDraftToFields(draft: MembershipPlanDraft): Record<string, string> {
  return {
    quota_mode: draft.quotaMode,
    monthly_quota_gib: draft.quotaMode === "limited" ? draft.quotaGiB : "",
    expiration_mode: draft.expirationMode,
    subscription_value: draft.expirationMode === "finite" ? draft.subscriptionValue : "",
    subscription_unit: draft.expirationMode === "finite" ? draft.subscriptionUnit : "months",
  };
}

interface MembershipPlanFieldsProps {
  value: MembershipPlanDraft;
  onChange: (next: MembershipPlanDraft) => void;
}

export const MembershipPlanFields: React.FC<MembershipPlanFieldsProps> = ({ value, onChange }) => {
  const { t } = useApp();

  return (
    <div className="membership-plan-fields">
      <label className="field">
        <span>{t("Monthly traffic quota")}</span>
        <SelectBox
          searchable={false}
          value={value.quotaMode}
          onChange={(quotaMode) => onChange({ ...value, quotaMode })}
          options={[
            { value: "unlimited", label: t("Unlimited") },
            { value: "limited", label: t("Set a monthly quota") },
          ]}
        />
      </label>
      {value.quotaMode === "limited" && (
        <label className="field">
          <span>{t("Quota (GiB)")}</span>
          <input
            type="number"
            min={1}
            max={1000000}
            step={1}
            required
            value={value.quotaGiB}
            onChange={(e) => onChange({ ...value, quotaGiB: e.target.value })}
            placeholder="100"
          />
        </label>
      )}
      <label className="field">
        <span>{t("Subscription expiration")}</span>
        <SelectBox
          searchable={false}
          value={value.expirationMode}
          onChange={(expirationMode) => onChange({ ...value, expirationMode })}
          options={[
            { value: "none", label: t("No expiration") },
            { value: "finite", label: t("Expire after a duration") },
          ]}
        />
      </label>
      {value.expirationMode === "finite" && (
        <div className="subscription-duration-fields">
          <label className="field">
            <span>{t("Duration")}</span>
            <input
              type="number"
              min={1}
              max={52560000}
              step={1}
              required
              value={value.subscriptionValue}
              onChange={(e) => onChange({ ...value, subscriptionValue: e.target.value })}
              placeholder="1"
            />
          </label>
          <label className="field">
            <span>{t("Unit")}</span>
            <SelectBox
              searchable={false}
              value={value.subscriptionUnit}
              onChange={(subscriptionUnit) => onChange({ ...value, subscriptionUnit })}
              options={[
                { value: "minutes", label: t("Minutes") },
                { value: "hours", label: t("Hours") },
                { value: "days", label: t("Days") },
                { value: "months", label: t("Calendar months") },
              ]}
            />
          </label>
        </div>
      )}
    </div>
  );
};
