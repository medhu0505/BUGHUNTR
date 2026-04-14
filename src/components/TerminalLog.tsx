import { useEffect, useRef, useState } from "react";
import { MOCK_LOG_LINES } from "@/lib/mock-data";

interface TerminalLogProps {
  isRunning: boolean;
  target: string;
  onComplete?: () => void;
}

export function TerminalLog({ isRunning, target, onComplete }: TerminalLogProps) {
  const [lines, setLines] = useState<string[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval>>();

  useEffect(() => {
    if (isRunning) {
      setLines([]);
      let idx = 0;
      const logs = MOCK_LOG_LINES.map(l => l.replace('{target}', target).replace('{count}', String(Math.floor(Math.random() * 5) + 1)));
      intervalRef.current = setInterval(() => {
        if (idx < logs.length) {
          setLines(prev => [...prev, `${new Date().toLocaleTimeString()} ${logs[idx]}`]);
          idx++;
        } else {
          clearInterval(intervalRef.current);
          onComplete?.();
        }
      }, 600);
    }
    return () => clearInterval(intervalRef.current);
  }, [isRunning, onComplete, target]);

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
        {lines.map((line, i) => (
          <div key={i} className={
            line.includes('[!]') || line.includes('[CRITICAL]') ? 'text-destructive' :
            line.includes('[+]') ? 'text-primary' :
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
