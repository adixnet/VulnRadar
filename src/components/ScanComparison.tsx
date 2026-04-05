import { ScanResult } from '@/lib/scanner-data';
import { ArrowLeftRight, Shield, Globe, Lock } from 'lucide-react';

interface ScanComparisonProps {
  scanA: ScanResult;
  scanB: ScanResult;
  onClose: () => void;
}

const ScanComparison = ({ scanA, scanB, onClose }: ScanComparisonProps) => {
  const critA = scanA.vulnerabilities.filter(v => v.severity === 'critical').length;
  const critB = scanB.vulnerabilities.filter(v => v.severity === 'critical').length;
  const highA = scanA.vulnerabilities.filter(v => v.severity === 'high').length;
  const highB = scanB.vulnerabilities.filter(v => v.severity === 'high').length;
  const medA = scanA.vulnerabilities.filter(v => v.severity === 'medium').length;
  const medB = scanB.vulnerabilities.filter(v => v.severity === 'medium').length;
  const lowA = scanA.vulnerabilities.filter(v => v.severity === 'low').length;
  const lowB = scanB.vulnerabilities.filter(v => v.severity === 'low').length;

  const riskA = Math.min(100, critA * 25 + highA * 15 + medA * 8 + lowA * 3);
  const riskB = Math.min(100, critB * 25 + highB * 15 + medB * 8 + lowB * 3);

  const secureA = scanA.headers.filter(h => h.status === 'secure').length;
  const secureB = scanB.headers.filter(h => h.status === 'secure').length;
  const missingA = scanA.headers.filter(h => h.status === 'missing').length;
  const missingB = scanB.headers.filter(h => h.status === 'missing').length;

  const diff = (a: number, b: number) => {
    if (a === b) return <span className="text-muted-foreground text-xs">—</span>;
    if (a < b) return <span className="text-success text-xs font-mono">▼ {b - a}</span>;
    return <span className="text-severity-critical text-xs font-mono">▲ {a - b}</span>;
  };

  const diffInverse = (a: number, b: number) => {
    if (a === b) return <span className="text-muted-foreground text-xs">—</span>;
    if (a > b) return <span className="text-success text-xs font-mono">▲ {a - b}</span>;
    return <span className="text-severity-critical text-xs font-mono">▼ {b - a}</span>;
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <ArrowLeftRight className="w-5 h-5 text-primary" />
          <h2 className="text-lg font-bold text-foreground">Scan Comparison</h2>
        </div>
        <button onClick={onClose} className="text-sm text-muted-foreground hover:text-foreground border border-border px-3 py-1.5 rounded-md hover:bg-secondary transition-colors">
          Close Comparison
        </button>
      </div>

      {/* Targets Header */}
      <div className="grid grid-cols-3 gap-4">
        <div className="text-right">
          <div className="text-sm font-mono text-primary truncate">{scanA.target}</div>
          <div className="text-xs text-muted-foreground">{scanA.startTime.toLocaleDateString()}</div>
        </div>
        <div className="text-center text-xs text-muted-foreground self-center">vs</div>
        <div className="text-left">
          <div className="text-sm font-mono text-primary truncate">{scanB.target}</div>
          <div className="text-xs text-muted-foreground">{scanB.startTime.toLocaleDateString()}</div>
        </div>
      </div>

      {/* Comparison Table */}
      <div className="rounded-md border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="bg-secondary border-b border-border">
              <th className="text-left p-3 text-xs text-muted-foreground uppercase">Metric</th>
              <th className="text-center p-3 text-xs text-muted-foreground uppercase">{scanA.target}</th>
              <th className="text-center p-3 text-xs text-muted-foreground uppercase">{scanB.target}</th>
              <th className="text-center p-3 text-xs text-muted-foreground uppercase">Diff</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            <tr className="border-b border-border/50">
              <td className="p-3 text-foreground flex items-center gap-2"><Shield className="w-3.5 h-3.5 text-primary" /> Risk Score</td>
              <td className="p-3 text-center font-bold text-severity-high">{riskA}</td>
              <td className="p-3 text-center font-bold text-severity-high">{riskB}</td>
              <td className="p-3 text-center">{diff(riskA, riskB)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-foreground">Total Vulnerabilities</td>
              <td className="p-3 text-center">{scanA.vulnerabilities.length}</td>
              <td className="p-3 text-center">{scanB.vulnerabilities.length}</td>
              <td className="p-3 text-center">{diff(scanA.vulnerabilities.length, scanB.vulnerabilities.length)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-severity-critical">Critical</td>
              <td className="p-3 text-center">{critA}</td>
              <td className="p-3 text-center">{critB}</td>
              <td className="p-3 text-center">{diff(critA, critB)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-severity-high">High</td>
              <td className="p-3 text-center">{highA}</td>
              <td className="p-3 text-center">{highB}</td>
              <td className="p-3 text-center">{diff(highA, highB)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-severity-medium">Medium</td>
              <td className="p-3 text-center">{medA}</td>
              <td className="p-3 text-center">{medB}</td>
              <td className="p-3 text-center">{diff(medA, medB)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-severity-low">Low</td>
              <td className="p-3 text-center">{lowA}</td>
              <td className="p-3 text-center">{lowB}</td>
              <td className="p-3 text-center">{diff(lowA, lowB)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-foreground flex items-center gap-2"><Globe className="w-3.5 h-3.5 text-primary" /> Secure Headers</td>
              <td className="p-3 text-center text-success">{secureA}</td>
              <td className="p-3 text-center text-success">{secureB}</td>
              <td className="p-3 text-center">{diffInverse(secureA, secureB)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-foreground">Missing Headers</td>
              <td className="p-3 text-center text-severity-medium">{missingA}</td>
              <td className="p-3 text-center text-severity-medium">{missingB}</td>
              <td className="p-3 text-center">{diff(missingA, missingB)}</td>
            </tr>
            <tr className="border-b border-border/50">
              <td className="p-3 text-foreground flex items-center gap-2"><Lock className="w-3.5 h-3.5 text-primary" /> SSL Grade</td>
              <td className="p-3 text-center">{scanA.sslInfo.grade}</td>
              <td className="p-3 text-center">{scanB.sslInfo.grade}</td>
              <td className="p-3 text-center text-muted-foreground text-xs">—</td>
            </tr>
            <tr>
              <td className="p-3 text-foreground">Technologies</td>
              <td className="p-3 text-center">{scanA.technologies.length}</td>
              <td className="p-3 text-center">{scanB.technologies.length}</td>
              <td className="p-3 text-center text-muted-foreground text-xs">—</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Unique Vulnerabilities */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="rounded-md border border-border bg-card p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3">
            Unique to <span className="text-primary font-mono">{scanA.target}</span>
          </h3>
          <div className="space-y-2">
            {scanA.vulnerabilities
              .filter(va => !scanB.vulnerabilities.some(vb => vb.title === va.title))
              .map(v => (
                <div key={v.id} className="text-xs font-mono flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${
                    v.severity === 'critical' ? 'bg-severity-critical' :
                    v.severity === 'high' ? 'bg-severity-high' :
                    v.severity === 'medium' ? 'bg-severity-medium' : 'bg-severity-low'
                  }`} />
                  <span className="text-foreground truncate">{v.title}</span>
                </div>
              ))}
            {scanA.vulnerabilities.filter(va => !scanB.vulnerabilities.some(vb => vb.title === va.title)).length === 0 && (
              <div className="text-xs text-muted-foreground">No unique findings</div>
            )}
          </div>
        </div>
        <div className="rounded-md border border-border bg-card p-4">
          <h3 className="text-sm font-semibold text-foreground mb-3">
            Unique to <span className="text-primary font-mono">{scanB.target}</span>
          </h3>
          <div className="space-y-2">
            {scanB.vulnerabilities
              .filter(vb => !scanA.vulnerabilities.some(va => va.title === vb.title))
              .map(v => (
                <div key={v.id} className="text-xs font-mono flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full ${
                    v.severity === 'critical' ? 'bg-severity-critical' :
                    v.severity === 'high' ? 'bg-severity-high' :
                    v.severity === 'medium' ? 'bg-severity-medium' : 'bg-severity-low'
                  }`} />
                  <span className="text-foreground truncate">{v.title}</span>
                </div>
              ))}
            {scanB.vulnerabilities.filter(vb => !scanA.vulnerabilities.some(va => va.title === vb.title)).length === 0 && (
              <div className="text-xs text-muted-foreground">No unique findings</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ScanComparison;
