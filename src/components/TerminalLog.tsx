import { useEffect, useRef } from "react";

interface TerminalLogProps {
  isRunning: boolean;
  lines: string[];
}

export function TerminalLog({ isRunning, lines }: TerminalLogProps) {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [lines]);

  return (
    <div className="terminal-bg rounded border border-border neon-border overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-border bg-muted/30">
        <div className="h-2 w-2 rounded-full bg-destructive" />
        <div className="h-2 w-2 rounded-full bg-warning" />
        <div className="h-2 w-2 rounded-full bg-primary" />
        <span className="ml-2 text-xs text-muted-foreground">terminal — scan output</span>
      </div>
      <div ref={containerRef} className="p-3 h-48 overflow-y-auto font-mono text-xs leading-relaxed scanline">
        {lines.length === 0 && !isRunning && (
          <span className="text-muted-foreground">Awaiting scan command...</span>
        )}
        {lines.filter(line => line && line.trim() !== "").map((line, i) => (
          <div key={i} className={
            line.includes('[!]') || line.includes('[CRITICAL]') ? 'text-destructive' :
            line.includes('[+]') || line.includes("complete") ? 'text-primary' :
            'text-foreground'
          }>
            {line}
          </div>
        ))}
        {isRunning && (
          <span className="text-primary animate-terminal-blink">▊</span>
        )}
      </div>
    </div>
  );
}
