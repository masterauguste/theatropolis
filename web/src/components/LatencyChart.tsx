import React, { useCallback, useEffect, useId, useState } from "react";
import { fetchJSON } from "../api/client";
import type { LinkLatencyPointView, LinkLatencyView } from "../api/types";
import { useApp } from "../context/AppContext";

interface LatencyChartProps {
  historyUrl: string;
}

interface HistoryPayload {
  current?: LinkLatencyView;
  probe_type?: string;
  points?: LinkLatencyPointView[];
}

const RANGES = ["1h", "6h", "24h", "7d"] as const;

export const LatencyChart: React.FC<LatencyChartProps> = ({ historyUrl }) => {
  const { t, locale } = useApp();
  const gradientId = useId().replace(/:/g, "");
  const [range, setRange] = useState<(typeof RANGES)[number]>("6h");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [payload, setPayload] = useState<HistoryPayload | null>(null);

  const load = useCallback(
    async (nextRange: string) => {
      setLoading(true);
      setError("");
      try {
        const sep = historyUrl.includes("?") ? "&" : "?";
        const data = await fetchJSON<HistoryPayload>(`${historyUrl}${sep}range=${encodeURIComponent(nextRange)}`);
        setPayload(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : t("Latency history unavailable"));
      } finally {
        setLoading(false);
      }
    },
    [historyUrl, t],
  );

  useEffect(() => {
    void load(range);
  }, [load, range]);

  const points = payload?.points || [];
  const samples = points.filter((p) => p.responses > 0);
  const rawMax = Math.max(10, ...samples.map((p) => p.maximum_ms || p.average_ms || 0));
  const maximum = Math.ceil(rawMax / 10) * 10;

  const width = 760;
  const height = 228;
  const padLeft = 52;
  const padRight = 46;
  const padTop = 18;
  const padBottom = 34;
  const plotWidth = width - padLeft - padRight;
  const plotHeight = height - padTop - padBottom;
  const xFor = (idx: number) => padLeft + (plotWidth * idx) / Math.max(1, points.length - 1);

  const coords = points
    .map((point, idx) =>
      point.responses > 0 ? ([xFor(idx), padTop + plotHeight - (point.average_ms / maximum) * plotHeight] as const) : null,
    )
    .filter((v): v is readonly [number, number] => v !== null);

  const linePath = coords.map(([px, py], i) => `${i === 0 ? "M" : "L"}${px.toFixed(1)} ${py.toFixed(1)}`).join(" ");
  const baselineY = padTop + plotHeight;
  const areaPath =
    coords.length > 1
      ? `${linePath} L${coords[coords.length - 1][0].toFixed(1)} ${baselineY.toFixed(1)} L${coords[0][0].toFixed(1)} ${baselineY.toFixed(1)} Z`
      : "";

  const formatTime = (iso: string) => {
    const parsed = new Date(iso);
    if (Number.isNaN(parsed.getTime())) return iso;
    return new Intl.DateTimeFormat(locale, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hourCycle: "h23" }).format(parsed);
  };

  return (
    <section className="link-monitor">
      <header>
        <div>
          <strong>{t("Link latency")}</strong>
          {payload?.current && (
            <span className={`link-latency link-latency--${payload.current.status || "pending"}`}>
              {payload.current.label || "—"}
              {payload.probe_type ? ` · ${payload.probe_type.toUpperCase()}` : ""}
            </span>
          )}
        </div>
        <div className="link-monitor__ranges" role="group" aria-label={t("Time range")}>
          {RANGES.map((item) => (
            <button
              key={item}
              type="button"
              className="button button--secondary button--small"
              aria-pressed={range === item}
              onClick={() => setRange(item)}
            >
              {item}
            </button>
          ))}
        </div>
      </header>

      <div className="link-monitor__chart">
        {loading ? (
          <span className="loading-state">
            <span className="loading-spinner loading-spinner--small" aria-hidden="true" />
            <span>{t("Loading…")}</span>
          </span>
        ) : error ? (
          <span>{error}</span>
        ) : points.length === 0 ? (
          <span>{t("No history yet")}</span>
        ) : (
          <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="xMidYMid meet" aria-hidden="true">
            <defs>
              <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#2554e8" stopOpacity="0.22" />
                <stop offset="100%" stopColor="#2554e8" stopOpacity="0.01" />
              </linearGradient>
            </defs>
            {[0, 1, 2, 3].map((index) => {
              const ratio = index / 3;
              const y = padTop + plotHeight * ratio;
              return (
                <g key={index}>
                  <line
                    x1={padLeft}
                    y1={y}
                    x2={width - padRight}
                    y2={y}
                    className={index === 3 ? "link-monitor__axis" : "link-monitor__grid"}
                  />
                  <text x={padLeft - 8} y={y + 3.5} textAnchor="end" className="link-monitor__tick">
                    {Math.round(maximum * (1 - ratio))} ms
                  </text>
                  <text x={width - padRight + 8} y={y + 3.5} textAnchor="start" className="link-monitor__tick link-monitor__tick--loss">
                    {Math.round(100 * (1 - ratio))}%
                  </text>
                </g>
              );
            })}
            {areaPath && <path d={areaPath} fill={`url(#${gradientId})`} />}
            {linePath && <path d={linePath} fill="none" stroke="#2554e8" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />}
            {points.map((point, idx) =>
              point.loss_percent > 0 ? (
                <rect
                  key={`loss-${idx}`}
                  x={xFor(idx) - 3}
                  y={padTop + plotHeight * (1 - Math.min(100, point.loss_percent) / 100)}
                  width={6}
                  height={Math.max(2, plotHeight * (Math.min(100, point.loss_percent) / 100))}
                  fill="rgba(220, 38, 38, 0.35)"
                  rx={1.5}
                />
              ) : null,
            )}
            {points.length > 0 && (
              <>
                <text x={padLeft} y={height - 10} textAnchor="start" className="link-monitor__tick">
                  {formatTime(points[0].at)}
                </text>
                <text x={width - padRight} y={height - 10} textAnchor="end" className="link-monitor__tick">
                  {formatTime(points[points.length - 1].at)}
                </text>
              </>
            )}
          </svg>
        )}
      </div>
    </section>
  );
};
