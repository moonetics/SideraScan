const jakartaDateTimeFormatter = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  hour: "2-digit",
  hour12: false,
  minute: "2-digit",
  month: "short",
  second: "2-digit",
  timeZone: "Asia/Jakarta",
  timeZoneName: "short",
  year: "numeric"
});

const isoDatePattern =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?(?:Z|[+-]\d{2}:\d{2})?$/;

export function formatJakartaDateTime(value: string | null | undefined) {
  if (!value) {
    return "Never";
  }

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return value;
  }

  return jakartaDateTimeFormatter.format(date);
}

export function formatMaybeJakartaDateTime(value: string) {
  if (!isoDatePattern.test(value)) {
    return value;
  }

  return formatJakartaDateTime(value);
}
