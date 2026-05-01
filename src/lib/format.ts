export function formatDate(value?: string | Date | null) {
  if (!value) {
    return "Never";
  }

  const date = value instanceof Date ? value : new Date(value);

  if (Number.isNaN(date.getTime())) {
    return "Unknown";
  }

  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export function formatNumber(value?: number | string | null) {
  return Number(value ?? 0).toLocaleString("en");
}

export function asNumber(value?: number | string | null) {
  return Number(value ?? 0);
}
