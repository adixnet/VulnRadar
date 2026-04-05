import { ScanResult } from '@/lib/scanner-data';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import VulnerabilityCard from './VulnerabilityCard';
import AiAnalysis from './AiAnalysis';
import { Shield, Globe, Lock, Server, Cpu, Network, FileWarning, ArrowRight, Search, Plug, Code, Unlink, ExternalLink, Brain } from 'lucide-react';

interface ScanReportProps {
  result: ScanResult;
}

const ScanReport = ({ result }: ScanReportProps) => {
  const critCount = result.vulnerabilities.filter(v => v.severity === 'critical').length;
  const highCount = result.vulnerabilities.filter(v => v.severity === 'high').length;
  const medCount = result.vulnerabilities.filter(v => v.severity === 'medium').length;
  const lowCount = result.vulnerabilities.filter(v => v.severity === 'low').length;

  const riskScore = Math.min(100, critCount * 25 + highCount * 15 + medCount * 8 + lowCount * 3);
  const riskColor = riskScore >= 70 ? 'text-severity-critical' : riskScore >= 40 ? 'text-severity-medium' : 'text-success';

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-5 gap-3">
        <div className="rounded-md border border-border bg-card p-3 sm:p-4 text-center">
          <div className={`text-2xl sm:text-3xl font-bold font-mono ${riskColor}`}>{riskScore}</div>
          <div className="text-xs text-muted-foreground mt-1">Risk Score</div>
        </div>
        <div className="rounded-md border border-severity-critical/30 bg-severity-critical/5 p-3 sm:p-4 text-center">
          <div className="text-2xl sm:text-3xl font-bold font-mono text-severity-critical">{critCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Critical</div>
        </div>
        <div className="rounded-md border border-severity-high/30 bg-severity-high/5 p-3 sm:p-4 text-center">
          <div className="text-2xl sm:text-3xl font-bold font-mono text-severity-high">{highCount}</div>
          <div className="text-xs text-muted-foreground mt-1">High</div>
        </div>
        <div className="rounded-md border border-severity-medium/30 bg-severity-medium/5 p-3 sm:p-4 text-center">
          <div className="text-2xl sm:text-3xl font-bold font-mono text-severity-medium">{medCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Medium</div>
        </div>
        <div className="rounded-md border border-severity-low/30 bg-severity-low/5 p-3 sm:p-4 text-center">
          <div className="text-2xl sm:text-3xl font-bold font-mono text-severity-low">{lowCount}</div>
          <div className="text-xs text-muted-foreground mt-1">Low</div>
        </div>
      </div>

      {/* Tabbed Results */}
      <Tabs defaultValue="vulns" className="w-full">
        <TabsList className="bg-secondary border border-border w-full justify-start overflow-x-auto flex-wrap h-auto gap-1 p-1">
          <TabsTrigger value="vulns" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Shield className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Vulnerabilities</span><span className="sm:hidden">Vulns</span>
          </TabsTrigger>
          <TabsTrigger value="headers" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Globe className="w-3.5 h-3.5" /> Headers
          </TabsTrigger>
          <TabsTrigger value="ssl" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Lock className="w-3.5 h-3.5" /> SSL
          </TabsTrigger>
          <TabsTrigger value="tech" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Cpu className="w-3.5 h-3.5" /> Tech
          </TabsTrigger>
          <TabsTrigger value="dns" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Server className="w-3.5 h-3.5" /> DNS
          </TabsTrigger>
          <TabsTrigger value="files" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <FileWarning className="w-3.5 h-3.5" /> Files
          </TabsTrigger>
          <TabsTrigger value="subdomains" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Search className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Subdomains</span><span className="sm:hidden">Subs</span>
          </TabsTrigger>
          <TabsTrigger value="redirects" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <ArrowRight className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Redirects</span><span className="sm:hidden">Redir</span>
          </TabsTrigger>
          <TabsTrigger value="ports" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Plug className="w-3.5 h-3.5" /> Ports
          </TabsTrigger>
          <TabsTrigger value="injection" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Code className="w-3.5 h-3.5" /> <span className="hidden sm:inline">SQLi/XSS</span><span className="sm:hidden">Inject</span>
          </TabsTrigger>
          <TabsTrigger value="cors" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Unlink className="w-3.5 h-3.5" /> CORS
          </TabsTrigger>
          <TabsTrigger value="openredirect" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <ExternalLink className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Open Redirect</span><span className="sm:hidden">Redir</span>
          </TabsTrigger>
          <TabsTrigger value="ai" className="data-[state=active]:bg-primary/20 data-[state=active]:text-primary gap-1.5 text-xs sm:text-sm">
            <Brain className="w-3.5 h-3.5" /> <span className="hidden sm:inline">AI Analysis</span><span className="sm:hidden">AI</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="vulns" className="space-y-2 mt-4">
          {result.vulnerabilities.length === 0 && (
            <div className="text-center py-8 text-muted-foreground text-sm">No vulnerabilities found — looking good!</div>
          )}
          {result.vulnerabilities
            .sort((a, b) => b.cvss - a.cvss)
            .map((vuln, i) => (
              <VulnerabilityCard key={vuln.id} vuln={vuln} index={i} />
            ))}
        </TabsContent>

        <TabsContent value="headers" className="mt-4">
          <div className="space-y-2">
            {result.headers.map(header => (
              <div
                key={header.name}
                className={`flex items-center justify-between p-3 rounded-md border ${
                  header.status === 'secure'
                    ? 'border-success/20 bg-success/5'
                    : header.status === 'missing'
                    ? 'border-severity-critical/20 bg-severity-critical/5'
                    : 'border-severity-medium/20 bg-severity-medium/5'
                }`}
              >
                <span className="text-xs sm:text-sm font-mono text-foreground truncate mr-2">{header.name}</span>
                <span
                  className={`text-xs font-mono px-2 py-0.5 rounded shrink-0 ${
                    header.status === 'secure'
                      ? 'text-success bg-success/10'
                      : header.status === 'missing'
                      ? 'text-severity-critical bg-severity-critical/10'
                      : 'text-severity-medium bg-severity-medium/10'
                  }`}
                >
                  {header.status === 'missing' ? 'MISSING' : header.value ? (header.value.length > 30 ? header.value.slice(0, 30) + '…' : header.value) : 'WARNING'}
                </span>
              </div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="ssl" className="mt-4">
          <div className="rounded-md border border-border bg-card p-4 sm:p-6 space-y-4">
            <div className="flex items-center gap-4">
              <div className={`text-4xl sm:text-5xl font-bold font-mono ${
                result.sslInfo.grade.startsWith('A') ? 'text-success' :
                result.sslInfo.grade.startsWith('B') ? 'text-severity-medium' : 'text-severity-critical'
              }`}>
                {result.sslInfo.grade}
              </div>
              <div>
                <div className="text-sm text-foreground font-medium">SSL/TLS Grade</div>
                <div className="text-xs text-muted-foreground">Protocol: {result.sslInfo.protocol}</div>
                <div className="text-xs text-muted-foreground">Cipher: {result.sslInfo.cipher}</div>
                <div className="text-xs text-muted-foreground">Expires: {result.sslInfo.expiry}</div>
              </div>
            </div>
            {result.sslInfo.issues.length > 0 && (
              <div>
                <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-2">Issues</h4>
                <div className="space-y-1">
                  {result.sslInfo.issues.map((issue, i) => (
                    <div key={i} className="text-sm text-severity-medium flex items-center gap-2">
                      <span className="w-1 h-1 rounded-full bg-severity-medium shrink-0" />
                      {issue}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="tech" className="mt-4">
          {result.technologies.length === 0 && (
            <div className="text-center py-8 text-muted-foreground text-sm">No technologies detected from headers.</div>
          )}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {result.technologies.map(tech => (
              <div key={tech.name} className="flex items-center justify-between p-3 rounded-md border border-border bg-card">
                <div>
                  <span className="text-sm font-medium text-foreground">{tech.name}</span>
                  <span className="text-xs text-muted-foreground ml-2">{tech.version}</span>
                </div>
                <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded">{tech.category}</span>
              </div>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="dns" className="mt-4">
          <div className="rounded-md border border-border overflow-hidden overflow-x-auto">
            <table className="w-full text-sm font-mono">
              <thead>
                <tr className="bg-secondary border-b border-border">
                  <th className="text-left p-3 text-xs text-muted-foreground uppercase">Type</th>
                  <th className="text-left p-3 text-xs text-muted-foreground uppercase">Value</th>
                </tr>
              </thead>
              <tbody>
                {result.dnsRecords.map((record, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-secondary/50">
                    <td className="p-3 text-info whitespace-nowrap">{record.type}</td>
                    <td className="p-3 text-foreground break-all">{record.value}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </TabsContent>

        <TabsContent value="files" className="mt-4">
          {(!result.sensitiveFiles || result.sensitiveFiles.length === 0) ? (
            <div className="text-center py-8 text-success text-sm font-mono">✓ No sensitive files exposed — looking good!</div>
          ) : (
            <div className="space-y-2">
              {result.sensitiveFiles.map((file, i) => (
                <div key={i} className={`flex items-center justify-between p-3 rounded-md border ${
                  file.severity === 'critical' ? 'border-severity-critical/30 bg-severity-critical/5' :
                  file.severity === 'high' ? 'border-severity-high/30 bg-severity-high/5' :
                  'border-severity-medium/30 bg-severity-medium/5'
                }`}>
                  <div>
                    <span className="text-sm font-mono text-foreground">{file.name}</span>
                    <span className="text-xs text-muted-foreground ml-2">{file.path}</span>
                  </div>
                  <span className={`text-xs font-mono px-2 py-0.5 rounded uppercase ${
                    file.severity === 'critical' ? 'text-severity-critical bg-severity-critical/10' :
                    file.severity === 'high' ? 'text-severity-high bg-severity-high/10' :
                    'text-severity-medium bg-severity-medium/10'
                  }`}>
                    {file.severity}
                  </span>
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="subdomains" className="mt-4">
          {(!result.subdomains || result.subdomains.length === 0) ? (
            <div className="text-center py-8 text-muted-foreground text-sm">No subdomains discovered via DNS enumeration.</div>
          ) : (
            <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2">
              {result.subdomains.map((sub, i) => (
                <div key={i} className="flex items-center gap-2 p-3 rounded-md border border-border bg-card">
                  <Network className="w-3.5 h-3.5 text-primary shrink-0" />
                  <span className="text-sm font-mono text-foreground truncate">{sub}</span>
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="redirects" className="mt-4">
          {(!result.redirectChain || result.redirectChain.length === 0) ? (
            <div className="text-center py-8 text-muted-foreground text-sm">No redirect chain data available.</div>
          ) : (
            <div className="space-y-2">
              {result.redirectChain.map((step, i) => (
                <div key={i} className="flex items-center gap-3 p-3 rounded-md border border-border bg-card">
                  <span className="w-6 h-6 rounded-full bg-primary/20 text-primary text-xs font-mono flex items-center justify-center shrink-0">{i + 1}</span>
                  <span className="text-sm font-mono text-foreground truncate flex-1">{step.url}</span>
                  <span className={`text-xs font-mono px-2 py-0.5 rounded ${
                    step.status >= 300 && step.status < 400 ? 'text-severity-medium bg-severity-medium/10' :
                    step.status === 200 ? 'text-success bg-success/10' :
                    'text-muted-foreground bg-secondary'
                  }`}>
                    {step.status || '—'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="ports" className="mt-4">
          {(!result.openPorts || result.openPorts.length === 0) ? (
            <div className="text-center py-8 text-muted-foreground text-sm">No open web service ports detected.</div>
          ) : (
            <div className="rounded-md border border-border overflow-hidden overflow-x-auto">
              <table className="w-full text-sm font-mono">
                <thead>
                  <tr className="bg-secondary border-b border-border">
                    <th className="text-left p-3 text-xs text-muted-foreground uppercase">Port</th>
                    <th className="text-left p-3 text-xs text-muted-foreground uppercase">Service</th>
                    <th className="text-left p-3 text-xs text-muted-foreground uppercase">Version / Banner</th>
                    <th className="text-left p-3 text-xs text-muted-foreground uppercase">State</th>
                  </tr>
                </thead>
                <tbody>
                  {result.openPorts.map((port, i) => {
                    const isRisky = [5432, 9200, 8888, 10000, 3000, 5000, 8000, 9090].includes(port.port);
                    return (
                      <tr key={i} className={`border-b border-border/50 ${isRisky ? 'bg-severity-high/5' : 'hover:bg-secondary/50'}`}>
                        <td className="p-3 text-primary font-bold">{port.port}</td>
                        <td className="p-3 text-foreground">{port.service}</td>
                        <td className="p-3 text-muted-foreground break-all">{port.version}</td>
                        <td className="p-3">
                          <span className={`text-xs font-mono px-2 py-0.5 rounded ${isRisky ? 'text-severity-high bg-severity-high/10' : 'text-success bg-success/10'}`}>
                            {isRisky ? 'OPEN ⚠️' : 'OPEN'}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </TabsContent>

        <TabsContent value="injection" className="mt-4">
          {(!result.injectionFindings || result.injectionFindings.length === 0) ? (
            <div className="text-center py-8 text-success text-sm font-mono">✓ No SQL injection or XSS vulnerabilities detected — looking good!</div>
          ) : (
            <div className="space-y-3">
              {result.injectionFindings.map((finding, i) => (
                <div key={i} className={`p-4 rounded-md border ${
                  finding.type === 'sqli' ? 'border-severity-critical/30 bg-severity-critical/5' : 'border-severity-high/30 bg-severity-high/5'
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className={`text-xs font-mono px-2 py-0.5 rounded uppercase ${
                      finding.type === 'sqli' ? 'text-severity-critical bg-severity-critical/10' : 'text-severity-high bg-severity-high/10'
                    }`}>
                      {finding.type === 'sqli' ? 'SQL INJECTION' : 'REFLECTED XSS'}
                    </span>
                    <span className={`text-xs font-mono px-2 py-0.5 rounded uppercase ${
                      finding.severity === 'critical' ? 'text-severity-critical bg-severity-critical/10' : 'text-severity-high bg-severity-high/10'
                    }`}>
                      {finding.severity}
                    </span>
                  </div>
                  <div className="text-sm font-medium text-foreground mb-1">{finding.payloadName}</div>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <div><span className="text-foreground/70">Parameter:</span> {finding.param}</div>
                    <div><span className="text-foreground/70">Evidence:</span> {finding.evidence}</div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="cors" className="mt-4">
          {(!result.corsFindings || result.corsFindings.length === 0) ? (
            <div className="text-center py-8 text-success text-sm font-mono">✓ No CORS misconfigurations detected — looking good!</div>
          ) : (
            <div className="space-y-3">
              {result.corsFindings.map((finding, i) => (
                <div key={i} className={`p-4 rounded-md border ${
                  finding.severity === 'critical' ? 'border-severity-critical/30 bg-severity-critical/5' :
                  finding.severity === 'high' ? 'border-severity-high/30 bg-severity-high/5' :
                  'border-severity-medium/30 bg-severity-medium/5'
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono px-2 py-0.5 rounded uppercase text-severity-high bg-severity-high/10">
                      {finding.type.replace(/_/g, ' ')}
                    </span>
                    <span className={`text-xs font-mono px-2 py-0.5 rounded uppercase ${
                      finding.severity === 'critical' ? 'text-severity-critical bg-severity-critical/10' :
                      finding.severity === 'high' ? 'text-severity-high bg-severity-high/10' :
                      'text-severity-medium bg-severity-medium/10'
                    }`}>
                      {finding.severity}
                    </span>
                  </div>
                  <div className="text-sm text-foreground mb-1">{finding.description}</div>
                  <div className="text-xs text-muted-foreground">
                    <span className="text-foreground/70">Evidence:</span> {finding.evidence}
                  </div>
                </div>
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="openredirect" className="mt-4">
          {(!result.openRedirectFindings || result.openRedirectFindings.length === 0) ? (
            <div className="text-center py-8 text-success text-sm font-mono">✓ No open redirects detected — looking good!</div>
          ) : (
            <div className="space-y-3">
              {result.openRedirectFindings.map((finding, i) => (
                <div key={i} className={`p-4 rounded-md border ${
                  finding.severity === 'high' ? 'border-severity-high/30 bg-severity-high/5' : 'border-severity-medium/30 bg-severity-medium/5'
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-mono px-2 py-0.5 rounded uppercase text-severity-high bg-severity-high/10">
                      OPEN REDIRECT
                    </span>
                    <span className={`text-xs font-mono px-2 py-0.5 rounded uppercase ${
                      finding.severity === 'high' ? 'text-severity-high bg-severity-high/10' : 'text-severity-medium bg-severity-medium/10'
                    }`}>
                      {finding.severity}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <div><span className="text-foreground/70">Parameter:</span> {finding.param}</div>
                    <div><span className="text-foreground/70">Redirected To:</span> <span className="text-severity-high">{finding.redirectedTo}</span></div>
                    <div><span className="text-foreground/70">URL:</span> <span className="break-all">{finding.url}</span></div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </TabsContent>
        <TabsContent value="ai" className="mt-4">
          <AiAnalysis result={result} />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default ScanReport;
