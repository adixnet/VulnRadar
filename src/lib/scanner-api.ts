import { supabase } from '@/integrations/supabase/client';
import type { ScanResult, Vulnerability, InjectionFinding, CorsFinding, OpenRedirectFinding } from '@/lib/scanner-data';

// Client-side vulnerability generation from merged phase data
function generateVulnerabilities(data: {
  headers: { name: string; value: string; status: string }[];
  dnsRecords: { type: string; value: string }[];
  sslInfo: { grade: string; issues: string[] };
  sensitiveFiles: { path: string; name: string; status: number; severity: string }[];
  redirectChain: { url: string; status: number }[];
  openPorts: { port: number; service: string }[];
  injectionFindings: InjectionFinding[];
  corsFindings: CorsFinding[];
  openRedirectFindings: OpenRedirectFinding[];
}, domain: string): Vulnerability[] {
  const vulns: Vulnerability[] = [];
  let vulnId = 1;

  const missingHeaders = data.headers.filter(h => h.status === 'missing');
  if (missingHeaders.length >= 3) {
    vulns.push({
      id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `${missingHeaders.length} Critical Security Headers Missing`,
      severity: missingHeaders.length >= 5 ? 'high' : 'medium', category: 'Security Misconfiguration',
      description: `Missing: ${missingHeaders.map(h => h.name).join(', ')}.`,
      impact: 'Vulnerable to clickjacking, XSS, MIME-type sniffing.',
      remediation: `Add headers: ${missingHeaders.map(h => h.name).join(', ')}`,
      cvss: missingHeaders.length >= 5 ? 7.1 : 5.3, cwe: 'CWE-693',
      evidence: `Missing: ${missingHeaders.map(h => h.name).join(', ')}`,
    });
  }

  if (missingHeaders.find(h => h.name.toLowerCase().includes('content-security'))) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'No Content Security Policy', severity: 'high', category: 'XSS',
      description: 'CSP header not set.', impact: 'No XSS protection.',
      remediation: "Implement strict CSP", cvss: 6.1, cwe: 'CWE-79', evidence: 'CSP not present' });
  }

  if (missingHeaders.find(h => h.name.toLowerCase().includes('x-frame'))) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'Clickjacking — Missing X-Frame-Options', severity: 'medium', category: 'UI Redress',
      description: 'X-Frame-Options not set.', impact: 'Iframe attacks possible.',
      remediation: "Set X-Frame-Options: DENY", cvss: 4.3, cwe: 'CWE-1021', evidence: 'X-Frame-Options not present' });
  }

  const serverWarning = data.headers.find(h => h.name === 'Server' && h.status === 'warning');
  if (serverWarning) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'Server Version Disclosure', severity: 'low', category: 'Information Disclosure',
      description: `Server header reveals: "${serverWarning.value}".`, impact: 'Known CVE lookup.',
      remediation: 'Remove Server header.', cvss: 3.7, cwe: 'CWE-200', evidence: `Server: ${serverWarning.value}` });
  }

  const hasSPF = data.dnsRecords.some(r => r.type === 'TXT' && r.value.includes('v=spf1'));
  const hasDMARC = data.dnsRecords.some(r => r.type === 'DMARC');
  if (!hasSPF || !hasDMARC) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `Email Spoofing — Missing ${!hasSPF && !hasDMARC ? 'SPF & DMARC' : !hasSPF ? 'SPF' : 'DMARC'}`,
      severity: 'medium', category: 'Email Security', description: `${!hasSPF ? 'No SPF. ' : ''}${!hasDMARC ? 'No DMARC.' : ''}`,
      impact: 'Phishing possible.', remediation: 'Add missing records.', cvss: 5.0, cwe: 'CWE-290', evidence: `${!hasSPF ? 'No SPF. ' : ''}${!hasDMARC ? 'No DMARC.' : ''}` });
  }

  if (!data.dnsRecords.some(r => r.type === 'DNSSEC' && r.value.includes('Enabled'))) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'DNSSEC Not Enabled', severity: 'low', category: 'DNS Security',
      description: 'DNSSEC not enabled.', impact: 'DNS cache poisoning.',
      remediation: 'Enable DNSSEC.', cvss: 3.7, cwe: 'CWE-350', evidence: 'No DNSKEY' });
  }

  if (!data.dnsRecords.some(r => r.type === 'CAA')) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'No CAA Records', severity: 'low', category: 'Certificate Security',
      description: 'No CAA records.', impact: 'Any CA can issue certs.',
      remediation: 'Add CAA records.', cvss: 3.0, cwe: 'CWE-295', evidence: 'No CAA' });
  }

  if (data.sslInfo.grade === 'F') {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'SSL/TLS Critical Failure', severity: 'critical', category: 'Encryption',
      description: `SSL grade F. Issues: ${data.sslInfo.issues.join(', ')}`, impact: 'Data interception.',
      remediation: 'Fix SSL.', cvss: 9.1, cwe: 'CWE-326', evidence: 'SSL Grade: F' });
  }

  for (const issue of data.sslInfo.issues) {
    if (issue.toLowerCase().includes('expired')) {
      vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'SSL Certificate Expired', severity: 'critical', category: 'Encryption',
        description: 'SSL cert expired.', impact: 'MITM possible.',
        remediation: 'Renew certificate.', cvss: 8.6, cwe: 'CWE-295', evidence: issue });
    }
  }

  for (const file of data.sensitiveFiles || []) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `Exposed: ${file.name}`, severity: file.severity as any, category: 'Information Disclosure',
      description: `${file.name} at ${file.path}.`, impact: file.severity === 'critical' ? 'Full compromise.' : 'Info disclosure.',
      remediation: `Block ${file.path}.`, cvss: file.severity === 'critical' ? 9.1 : file.severity === 'high' ? 7.5 : 5.3, cwe: 'CWE-200', evidence: `HTTP 200 at ${file.path}` });
  }

  const httpNoRedirect = (data.redirectChain || []).find(c => c.url.startsWith('http://') && c.status === 200);
  if (httpNoRedirect) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'No HTTP→HTTPS Redirect', severity: 'medium', category: 'Transport Security',
      description: 'HTTP returns 200.', impact: 'Unencrypted data.',
      remediation: '301 redirect.', cvss: 5.3, cwe: 'CWE-319', evidence: 'HTTP 200' });
  }

  for (const f of data.injectionFindings || []) {
    if (f.type === 'sqli') {
      vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `SQLi — ${f.payloadName} (${f.param})`, severity: 'critical', category: 'Injection',
        description: `SQLi via ${f.payloadName} on "${f.param}".`, impact: 'Database compromise.',
        remediation: 'Parameterized queries.', cvss: 9.8, cwe: 'CWE-89', evidence: f.evidence });
    } else {
      vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `XSS — ${f.payloadName} (${f.param})`, severity: 'high', category: 'Cross-Site Scripting',
        description: `XSS: ${f.payloadName} reflected in "${f.param}".`, impact: 'Session theft.',
        remediation: 'Encode output. CSP.', cvss: 6.1, cwe: 'CWE-79', evidence: f.evidence });
    }
  }

  const riskyPorts = (data.openPorts || []).filter(p => [5432, 3306, 6379, 27017, 9200, 8888, 10000, 3000, 5000, 8000, 9090].includes(p.port));
  if (riskyPorts.length > 0) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `${riskyPorts.length} Risky Port(s) Exposed`,
      severity: riskyPorts.some(p => [5432, 3306, 6379, 27017, 9200].includes(p.port)) ? 'high' : 'medium',
      category: 'Network Security', description: `Risky ports: ${riskyPorts.map(p => `${p.port} (${p.service})`).join(', ')}.`,
      impact: 'Internal services exposed.', remediation: 'Firewall rules.',
      cvss: riskyPorts.some(p => [5432, 3306, 6379, 27017, 9200].includes(p.port)) ? 7.5 : 5.3, cwe: 'CWE-200',
      evidence: `Open: ${riskyPorts.map(p => p.port).join(', ')}` });
  }

  for (const cf of data.corsFindings || []) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `CORS — ${cf.type.replace(/_/g, ' ')}`, severity: cf.severity, category: 'CORS',
      description: cf.description, impact: cf.severity === 'critical' ? 'Any site can read responses.' : 'Cross-origin leakage.',
      remediation: 'Restrict CORS origins.', cvss: cf.severity === 'critical' ? 9.1 : cf.severity === 'high' ? 7.5 : 5.3,
      cwe: 'CWE-942', evidence: cf.evidence });
  }

  for (const orf of data.openRedirectFindings || []) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `Open Redirect — "${orf.param}"`, severity: orf.severity, category: 'Open Redirect',
      description: `"${orf.param}" allows external redirect.`, impact: 'Phishing.',
      remediation: 'Validate redirect URLs.', cvss: orf.severity === 'high' ? 6.1 : 4.3, cwe: 'CWE-601', evidence: `${orf.url} → ${orf.redirectedTo}` });
  }

  return vulns;
}

const RECON_PROGRESS = [
  { phase: 0, progress: 30, msg: '[RECON] Querying DNS servers...' },
  { phase: 0, progress: 60, msg: '[RECON] Checking SPF/DMARC/DNSSEC records...' },
  { phase: 0, progress: 90, msg: '[RECON] Checking CAA records...' },
  { phase: 1, progress: 30, msg: '[SUBDOMAIN] Enumerating subdomains (100 prefixes)...' },
  { phase: 1, progress: 60, msg: '[SUBDOMAIN] Querying Certificate Transparency...' },
  { phase: 1, progress: 80, msg: '[SUBDOMAIN] Resolving discovered hosts...' },
  { phase: 2, progress: 30, msg: '[HEADERS] Fetching HTTP response headers...' },
  { phase: 2, progress: 60, msg: '[HEADERS] Analyzing security headers...' },
  { phase: 2, progress: 90, msg: '[HEADERS] Fingerprinting technologies...' },
  { phase: 3, progress: 30, msg: '[REDIRECT] Checking HTTP→HTTPS redirect...' },
  { phase: 3, progress: 80, msg: '[REDIRECT] Tracing redirect chain...' },
];

const ACTIVE_PROGRESS = [
  { phase: 4, progress: 20, msg: '[FILES] Checking 22 sensitive file paths...' },
  { phase: 4, progress: 50, msg: '[FILES] Checking admin panels and backups...' },
  { phase: 4, progress: 90, msg: '[FILES] Checking config files and logs...' },
  { phase: 5, progress: 30, msg: '[SSL] Testing HTTPS connection...' },
  { phase: 5, progress: 60, msg: '[SSL] Analyzing certificate chain...' },
  { phase: 5, progress: 90, msg: '[SSL] Checking for vulnerabilities...' },
  { phase: 7, progress: 10, msg: '[SPIDER] Starting active URL crawling (depth 2)...' },
  { phase: 7, progress: 25, msg: '[SPIDER] Fetching seed pages (12 paths)...' },
  { phase: 7, progress: 45, msg: '[SPIDER] Following internal links...' },
  { phase: 7, progress: 60, msg: '[SPIDER] Extracting forms and parameters...' },
  { phase: 7, progress: 80, msg: '[SPIDER] Crawling deeper (depth 2)...' },
  { phase: 7, progress: 95, msg: '[SPIDER] Compiling crawl results...' },
  { phase: 8, progress: 20, msg: '[PORTS] Probing 20 common ports...' },
  { phase: 8, progress: 50, msg: '[PORTS] Checking database ports...' },
  { phase: 8, progress: 90, msg: '[PORTS] Analyzing open services...' },
];

const ATTACK_PROGRESS = [
  { phase: 9, progress: 10, msg: '[INJECTION] Phase 1: GET parameter fuzzing (20 paths)...' },
  { phase: 9, progress: 25, msg: '[INJECTION] Testing SQLi payloads (15 variants)...' },
  { phase: 9, progress: 40, msg: '[INJECTION] Testing XSS reflection (14 payloads)...' },
  { phase: 9, progress: 50, msg: '[INJECTION] Phase 2: POST form fuzzing (12 endpoints)...' },
  { phase: 9, progress: 60, msg: '[INJECTION] Phase 2b: Crawled form fuzzing...' },
  { phase: 9, progress: 70, msg: '[INJECTION] Testing login/search/contact forms...' },
  { phase: 9, progress: 80, msg: '[INJECTION] Phase 3: Header injection testing...' },
  { phase: 9, progress: 95, msg: '[INJECTION] Deduplicating & analyzing findings...' },
  { phase: 10, progress: 20, msg: '[CORS] Testing origin reflection...' },
  { phase: 10, progress: 50, msg: '[CORS] Testing null origin & subdomain bypass...' },
  { phase: 10, progress: 80, msg: '[CORS] Checking preflight configuration...' },
  { phase: 11, progress: 20, msg: '[REDIRECT-VULN] Testing 20 redirect parameters...' },
  { phase: 11, progress: 50, msg: '[REDIRECT-VULN] Fuzzing auth redirect endpoints...' },
  { phase: 11, progress: 80, msg: '[REDIRECT-VULN] Checking meta refresh & JS redirects...' },
];

function startProgressTimer(
  progressLogs: { phase: number; progress: number; msg: string }[],
  onLog: (log: string) => void,
  onPhaseChange: (phase: number, progress: number) => void,
  intervalMs = 1200,
): { stop: () => void } {
  let index = 0;
  const timer = setInterval(() => {
    if (index < progressLogs.length) {
      const p = progressLogs[index];
      onLog(p.msg);
      onPhaseChange(p.phase, p.progress);
      index++;
    }
  }, intervalMs);
  return { stop: () => clearInterval(timer) };
}

export async function performRealScan(
  target: string,
  onLog: (log: string) => void,
  onPhaseChange: (phase: number, progress: number) => void
): Promise<ScanResult> {
  onLog(`[INIT] Target: ${target}`);
  onLog('[INIT] VulnRadar Engine v1.0.0 — DEEP SCAN MODE');
  onLog('[INIT] Connecting to scan backend...');
  onLog('[INIT] Scan split into 3 phase groups for maximum depth');
  onLog('');

  const startTime = new Date();

  // Accumulated results across phases
  let dnsRecords: any[] = [];
  let subdomains: string[] = [];
  let headers: any[] = [];
  let technologies: any[] = [];
  let redirectChain: any[] = [];
  let sensitiveFiles: any[] = [];
  let sslInfo = { grade: 'N/A', expiry: 'N/A', protocol: 'N/A', cipher: 'N/A', issues: [] as string[] };
  let openPorts: any[] = [];
  let crawlStats = { pagesDiscovered: 0, paramsFound: 0, formsFound: 0 };
  let crawlData: any = null;
  let injectionFindings: InjectionFinding[] = [];
  let corsFindings: CorsFinding[] = [];
  let openRedirectFindings: OpenRedirectFinding[] = [];

  // ═══ PHASE 1: RECON ═══
  onLog('═══════════════════════════════════════');
  onLog('[PHASE GROUP 1/3] Reconnaissance');
  onLog('═══════════════════════════════════════');
  onPhaseChange(0, 10);

  const reconTimer = startProgressTimer(RECON_PROGRESS, onLog, onPhaseChange);
  try {
    const { data, error } = await supabase.functions.invoke('scan-target', {
      body: { target, phase: 'recon' },
    });
    reconTimer.stop();

    if (error) throw new Error(error.message || 'Recon phase failed');
    if (!data?.success) throw new Error(data?.error || 'Recon phase unsuccessful');

    const r = data.data;
    if (r.logs) for (const log of r.logs) { if (log != null) onLog(log); }

    dnsRecords = r.dnsRecords || [];
    subdomains = r.subdomains || [];
    headers = r.headers || [];
    technologies = r.technologies || [];
    redirectChain = r.redirectChain || [];

    onLog('');
    onLog(`[RECON] ✓ Phase 1 complete: ${dnsRecords.length} DNS records, ${subdomains.length} subdomains, ${headers.length} headers`);
  } catch (err) {
    reconTimer.stop();
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    onLog(`[ERROR] Recon phase failed: ${errMsg}`);
    throw err;
  }

  // ═══ PHASE 2: ACTIVE ═══
  onLog('');
  onLog('═══════════════════════════════════════');
  onLog('[PHASE GROUP 2/3] Active Scanning');
  onLog('═══════════════════════════════════════');
  onPhaseChange(4, 10);

  const activeTimer = startProgressTimer(ACTIVE_PROGRESS, onLog, onPhaseChange);
  try {
    const { data, error } = await supabase.functions.invoke('scan-target', {
      body: { target, phase: 'active' },
    });
    activeTimer.stop();

    if (error) throw new Error(error.message || 'Active phase failed');
    if (!data?.success) throw new Error(data?.error || 'Active phase unsuccessful');

    const r = data.data;
    if (r.logs) for (const log of r.logs) { if (log != null) onLog(log); }

    sensitiveFiles = r.sensitiveFiles || [];
    sslInfo = r.sslInfo || sslInfo;
    openPorts = r.openPorts || [];
    crawlStats = r.crawlStats || crawlStats;
    crawlData = r.crawlData || null;

    onLog('');
    onLog(`[ACTIVE] ✓ Phase 2 complete: ${sensitiveFiles.length} exposed files, SSL ${sslInfo.grade}, ${openPorts.length} ports, ${crawlStats.pagesDiscovered} pages crawled`);
  } catch (err) {
    activeTimer.stop();
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    onLog(`[ERROR] Active phase failed: ${errMsg}`);
    throw err;
  }

  // ═══ PHASE 3: ATTACK ═══
  onLog('');
  onLog('═══════════════════════════════════════');
  onLog('[PHASE GROUP 3/3] Attack Surface Testing');
  onLog('═══════════════════════════════════════');
  onPhaseChange(9, 10);

  const attackTimer = startProgressTimer(ATTACK_PROGRESS, onLog, onPhaseChange);
  try {
    const { data, error } = await supabase.functions.invoke('scan-target', {
      body: { target, phase: 'attack', crawlData },
    });
    attackTimer.stop();

    if (error) throw new Error(error.message || 'Attack phase failed');
    if (!data?.success) throw new Error(data?.error || 'Attack phase unsuccessful');

    const r = data.data;
    if (r.logs) for (const log of r.logs) { if (log != null) onLog(log); }

    injectionFindings = r.injectionFindings || [];
    corsFindings = r.corsFindings || [];
    openRedirectFindings = r.openRedirectFindings || [];

    onLog('');
    onLog(`[ATTACK] ✓ Phase 3 complete: ${injectionFindings.length} injection, ${corsFindings.length} CORS, ${openRedirectFindings.length} redirect findings`);
  } catch (err) {
    attackTimer.stop();
    const errMsg = err instanceof Error ? err.message : 'Unknown error';
    onLog(`[ERROR] Attack phase failed: ${errMsg}`);
    throw err;
  }

  // ═══ REPORT GENERATION ═══
  onPhaseChange(12, 50);
  onLog('');
  onLog('═══════════════════════════════════════');
  onLog('[REPORT] Compiling final report...');
  onLog('═══════════════════════════════════════');

  const vulnerabilities = generateVulnerabilities({
    headers, dnsRecords, sslInfo, sensitiveFiles, redirectChain,
    openPorts, injectionFindings, corsFindings, openRedirectFindings,
  }, target);

  onLog(`[REPORT] Found ${vulnerabilities.length} vulnerabilities`);
  onLog(`[REPORT] ${headers.length} headers, ${dnsRecords.length} DNS, ${subdomains.length} subdomains`);
  onLog(`[REPORT] ${openPorts.length} ports, ${sensitiveFiles.length} files, SSL: ${sslInfo.grade}`);
  onLog(`[REPORT] Crawled: ${crawlStats.pagesDiscovered} pages, ${crawlStats.paramsFound} params, ${crawlStats.formsFound} forms`);
  onLog(`[REPORT] Injection: ${injectionFindings.length}, CORS: ${corsFindings.length}, Redirect: ${openRedirectFindings.length}`);

  onPhaseChange(12, 100);
  onLog('[REPORT] Report generation complete.');

  return {
    target,
    startTime,
    endTime: new Date(),
    vulnerabilities,
    openPorts,
    headers,
    sslInfo: { ...sslInfo, expiry: sslInfo.expiry || 'N/A', protocol: sslInfo.protocol || 'N/A', cipher: sslInfo.cipher || 'N/A' },
    technologies,
    dnsRecords,
    subdomains,
    sensitiveFiles,
    redirectChain,
    injectionFindings,
    corsFindings,
    openRedirectFindings,
    crawlStats,
  };
}
