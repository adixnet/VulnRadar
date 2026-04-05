import { useEffect, useRef } from 'react';

interface TerminalOutputProps {
  logs: string[];
  isActive: boolean;
}

const TerminalOutput = ({ logs, isActive }: TerminalOutputProps) => {
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs]);

  const getLogColor = (log: string | undefined) => {
    if (!log) return 'text-terminal-text';
    if (log.includes('FOUND:') || log.includes('WARNING:') || log.includes('DANGEROUS'))
      return 'text-severity-high';
    if (log.includes('✗') || log.includes('MISSING'))
      return 'text-severity-medium';
    if (log.includes('✓') || log.includes('GOOD') || log.includes('NOT VULNERABLE'))
      return 'text-success';
    if (log.includes('OPEN'))
      return 'text-info';
    return 'text-terminal-text';
  };

  return (
    <div className="rounded-md border border-border bg-terminal-bg overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-secondary/50">
        <div className="w-3 h-3 rounded-full bg-severity-critical" />
        <div className="w-3 h-3 rounded-full bg-severity-medium" />
        <div className="w-3 h-3 rounded-full bg-success" />
        <span className="ml-2 text-xs font-mono text-muted-foreground">
          vulnradar — live output
        </span>
      </div>
      <div
        ref={containerRef}
        className="p-4 h-80 overflow-y-auto font-mono text-xs leading-relaxed"
      >
        {logs.map((log, i) => (
          <div key={i} className={`${getLogColor(log)} whitespace-pre-wrap`}>
            <span className="text-muted-foreground mr-2 select-none">
              {String(i + 1).padStart(3, '0')}
            </span>
            {log}
          </div>
        ))}
        {isActive && (
          <span className="inline-block w-2 h-4 bg-terminal-cursor animate-typing-cursor ml-1" />
        )}
      </div>
    </div>
  );
};

export default TerminalOutput;
