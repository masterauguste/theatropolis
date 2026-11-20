import React, { useMemo } from "react";
import { useApp } from "../context/AppContext";

interface LocalTimeProps {
  dateTime: string;
  fallback?: string;
}

export const LocalTime: React.FC<LocalTimeProps> = ({ dateTime, fallback }) => {
  const { locale } = useApp();
  const formatted = useMemo(() => {
    const parsed = new Date(dateTime);
    if (Number.isNaN(parsed.getTime())) return fallback || dateTime;
    try {
      return new Intl.DateTimeFormat(locale, {
        year: "numeric",
        month: "long",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hourCycle: "h23",
      }).format(parsed);
    } catch {
      return fallback || dateTime;
    }
  }, [dateTime, fallback, locale]);

  return <time dateTime={dateTime}>{formatted}</time>;
};
