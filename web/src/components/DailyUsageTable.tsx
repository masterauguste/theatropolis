import React from "react";
import type { DailyUsageDayView } from "../api/types";
import { useApp } from "../context/AppContext";

interface DailyUsageTableProps {
  days: DailyUsageDayView[] | null | undefined;
  showPerNode?: boolean;
}

export const DailyUsageTable: React.FC<DailyUsageTableProps> = ({ days, showPerNode = false }) => {
  const { t } = useApp();
  const list = days || [];

  if (list.length === 0) {
    return (
      <div className="panel__empty">
        <strong>{t("No traffic recorded in the last 30 days.")}</strong>
      </div>
    );
  }

  return (
    <div className="table-wrap daily-usage-table">
      <table>
        <thead>
          <tr>
            <th>{t("Date")}</th>
            <th>{t("Total")}</th>
            {showPerNode && <th>{t("Nodes")}</th>}
          </tr>
        </thead>
        <tbody>
          {list.map((day) => (
            <tr key={day.DateLabel}>
              <td data-label={t("Date")}>
                <time dateTime={day.Date ? day.Date.slice(0, 10) : undefined}>{day.DateLabel}</time>
              </td>
              <td data-label={t("Total")}>
                <strong>{day.TotalLabel}</strong>
              </td>
              {showPerNode && (
                <td data-label={t("Nodes")}>
                  {day.Nodes && day.Nodes.length > 0 ? (
                    <div className="daily-usage-nodes">
                      {day.Nodes.map((node) => (
                        <span key={node.ProxyNodeID}>
                          <span>{node.Name}</span>
                          <strong>{node.UsageLabel}</strong>
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
};
