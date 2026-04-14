import type { LucideIcon } from "lucide-react";

interface StatsCardProps {
  title: string;
  value: number;
  icon: LucideIcon;
  variant?: 'default' | 'critical' | 'high' | 'medium' | 'low';
}

const variantStyles = {
  default: 'neon-border',
  critical: 'neon-border border-destructive/40',
  high: 'neon-border border-warning/40',
  medium: 'neon-border border-accent/40',
  low: 'neon-border border-info/40',
};

const valueStyles = {
  default: 'text-primary',
  critical: 'text-destructive',
  high: 'text-warning',
  medium: 'text-accent',
  low: 'text-info',
};

export function StatsCard({ title, value, icon: Icon, variant = 'default' }: StatsCardProps) {
  return (
    <div className={`bg-card rounded-lg border p-4 ${variantStyles[variant]}`}>
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground uppercase tracking-wider">{title}</p>
        <Icon className={`h-4 w-4 ${valueStyles[variant]}`} />
      </div>
      <p className={`text-3xl font-bold mt-2 ${valueStyles[variant]}`}>{value}</p>
    </div>
  );
}
