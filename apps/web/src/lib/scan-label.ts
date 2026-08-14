export function scanDisplayLabel(scan: { id: string; playerLabel: string | null }) {
  const label = scan.playerLabel?.trim();

  if (label) {
    return label;
  }

  return `Unlabeled scan - Scan ${scan.id.slice(0, 8)}`;
}
