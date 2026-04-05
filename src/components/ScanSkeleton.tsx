const ScanSkeleton = () => {
  return (
    <div className="space-y-6 animate-pulse">
      <div className="flex items-center justify-between">
        <div className="space-y-2">
          <div className="h-6 w-48 bg-secondary rounded" />
          <div className="h-4 w-32 bg-secondary rounded" />
        </div>
        <div className="h-4 w-24 bg-secondary rounded" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 rounded-md border border-border bg-card overflow-hidden">
          <div className="flex items-center gap-2 px-4 py-2 border-b border-border bg-secondary/50">
            <div className="w-3 h-3 rounded-full bg-muted" />
            <div className="w-3 h-3 rounded-full bg-muted" />
            <div className="w-3 h-3 rounded-full bg-muted" />
            <div className="ml-2 h-3 w-40 bg-muted rounded" />
          </div>
          <div className="p-4 space-y-2">
            {Array.from({ length: 12 }).map((_, i) => (
              <div key={i} className="flex gap-2">
                <div className="h-3 w-8 bg-muted rounded" />
                <div className="h-3 bg-muted rounded" style={{ width: `${30 + Math.random() * 60}%` }} />
              </div>
            ))}
          </div>
        </div>
        <div className="rounded-md border border-border bg-card p-4 space-y-4">
          <div className="h-4 w-28 bg-secondary rounded" />
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="flex items-center gap-3">
              <div className="w-8 h-8 rounded-md bg-muted" />
              <div className="flex-1 space-y-1">
                <div className="h-3 w-full bg-muted rounded" />
                <div className="h-1 w-full bg-muted rounded-full" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ScanSkeleton;
