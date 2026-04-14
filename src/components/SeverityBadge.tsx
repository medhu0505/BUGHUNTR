import type { Severity } from "@/lib/mock-data";

const styles: Record<Severity, string> = {
  critical: 'bg-destructive/20 text-destructive border-destructive/40',
  high: 'bg-warning/20 text-warning border-warning/40',
  medium: 'bg-accent/20 text-accent border-accent/40',
  low: 'bg-info/20 text-info border-info/40',
  info: 'bg-muted text-muted-foreground border-muted',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-xs font-mono uppercase tracking-wider border rounded ${styles[severity]}`}>
      {severity}
    </span>
  );
}
