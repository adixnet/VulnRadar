import { supabase } from '@/integrations/supabase/client';
import type { ScanResult, Vulnerability } from '@/lib/scanner-data';
import type {
  CrawlData,
  DNSRecord,
  SecurityHeader,
  Technology,
  RedirectChainEntry,
  ExposedFile,
  OpenPort,
  SSLInfo,
  ScanResponse,
  ReconData,
  ActiveData,
  AttackData,
  InjectionFinding,
  CorsFinding,
  OpenRedirectFinding
} from '../../supabase/functions/scan-target/types/scan';

// Client-side vulnerability generation from merged phase data
function generateVulnerabilities(data: {
  headers: SecurityHeader[];
  dnsRecords: DNSRecord[];
  sslInfo: { grade: string; issues: string[] };
  sensitiveFiles: ExposedFile[];
  redirectChain: RedirectChainEntry[];
  openPorts: OpenPort[];
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

function mapRealtimeProgress(
  phaseGroup: string,
  overallProgress: number,
  onPhaseChange: (phase: number, progress: number) => void
) {
  if (phaseGroup === 'recon') {
    if (overallProgress <= 25) {
      const p = Math.round((overallProgress / 25) * 100);
      onPhaseChange(0, p);
    } else if (overallProgress <= 50) {
      const p = Math.round(((overallProgress - 25) / 25) * 100);
      onPhaseChange(1, p);
    } else if (overallProgress <= 75) {
      const p = Math.round(((overallProgress - 50) / 25) * 100);
      onPhaseChange(2, p);
    } else {
      const p = Math.round(((overallProgress - 75) / 25) * 100);
      onPhaseChange(3, p);
    }
  } else if (phaseGroup === 'active') {
    if (overallProgress <= 25) {
      const p = Math.round((overallProgress / 25) * 100);
      onPhaseChange(4, p);
    } else if (overallProgress <= 50) {
      const p = Math.round(((overallProgress - 25) / 25) * 100);
      onPhaseChange(5, p);
    } else if (overallProgress <= 75) {
      const p = Math.round(((overallProgress - 50) / 25) * 100);
      onPhaseChange(7, p);
    } else {
      const p = Math.round(((overallProgress - 75) / 25) * 100);
      onPhaseChange(8, p);
    }
  } else if (phaseGroup === 'attack') {
    if (overallProgress <= 40) {
      const p = Math.round((overallProgress / 40) * 100);
      onPhaseChange(9, p);
    } else if (overallProgress <= 70) {
      const p = Math.round(((overallProgress - 40) / 30) * 100);
      onPhaseChange(10, p);
    } else {
      const p = Math.round(((overallProgress - 70) / 30) * 100);
      onPhaseChange(11, p);
    }
  }
}

export async function performRealScan(
  target: string,
  onLog: (log: string) => void,
  onPhaseChange: (phase: number, progress: number) => void
): Promise<ScanResult> {
  const loggedMessages = new Set<string>();
  const safeOnLog = (msg: string) => {
    if (!msg) return;
    const trimmed = msg.trim();
    if (loggedMessages.has(trimmed)) return;
    loggedMessages.add(trimmed);
    onLog(msg);
  };

  safeOnLog(`[INIT] Target: ${target}`);
  safeOnLog('[INIT] VulnRadar Engine v1.0.0 — DEEP SCAN MODE');
  safeOnLog('[INIT] Connecting to scan backend...');
  safeOnLog('[INIT] Scan split into 3 phase groups for maximum depth');
  safeOnLog('');

  const startTime = new Date();

  // Generate unique scanId for client/server connection
  const scanId = 'scan_' + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);

  let isConnected = true;

  // Subscribe to dedicated realtime channel
  const channel = supabase.channel(`scan:${scanId}`, {
    config: {
      broadcast: { self: true },
    },
  });

  channel
    .on('broadcast', { event: 'progress' }, ({ payload }) => {
      if (payload) {
        const { message, progress, phase } = payload;
        if (message) safeOnLog(message);
        if (progress !== undefined && phase) {
          mapRealtimeProgress(phase, progress, onPhaseChange);
        }
      }
    });

  // Helper to wait for the channel subscription status
  const waitForSubscription = (timeoutMs = 5000): Promise<boolean> => {
    return new Promise((resolve) => {
      let resolved = false;
      const timer = setTimeout(() => {
        if (!resolved) {
          resolved = true;
          resolve(false);
        }
      }, timeoutMs);

      channel.subscribe((status: string) => {
        console.log(`Frontend channel status for ${scanId}:`, status);
        if (status === 'SUBSCRIBED' && !resolved) {
          clearTimeout(timer);
          resolved = true;
          resolve(true);
        } else if ((status === 'CLOSED' || status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') && !resolved) {
          clearTimeout(timer);
          resolved = true;
          resolve(false);
        }

        if (status === 'CLOSED' || status === 'CHANNEL_ERROR') {
          if (isConnected) {
            isConnected = false;
            safeOnLog('[SYSTEM] Realtime channel disconnected. Streaming is paused; falling back to buffered phase logs.');
          }
        }
      });
    });
  };

  // Helper to wrap promise with client-side timeout
  const withTimeout = <T>(promise: Promise<T>, timeoutMs: number, errorMsg: string): Promise<T> => {
    return Promise.race([
      promise,
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(errorMsg)), timeoutMs)
      ),
    ]);
  };

  const hasSubscribed = await waitForSubscription();
  if (hasSubscribed) {
    safeOnLog('[SYSTEM] Realtime channel established. Streaming backend progress...');
  } else {
    isConnected = false;
    safeOnLog('[SYSTEM] Realtime channel failed to connect. Falling back to buffered logs.');
  }

  // Accumulated results across phases
  let dnsRecords: DNSRecord[] = [];
  let subdomains: string[] = [];
  let headers: SecurityHeader[] = [];
  let technologies: Technology[] = [];
  let redirectChain: RedirectChainEntry[] = [];
  let sensitiveFiles: ExposedFile[] = [];
  let sslInfo: SSLInfo = { grade: 'N/A', expiry: 'N/A', protocol: 'N/A', cipher: 'N/A', issues: [] };
  let openPorts: OpenPort[] = [];
  let crawlStats = { pagesDiscovered: 0, paramsFound: 0, formsFound: 0 };
  let crawlData: CrawlData | null = null;
  let injectionFindings: InjectionFinding[] = [];
  let corsFindings: CorsFinding[] = [];
  let openRedirectFindings: OpenRedirectFinding[] = [];

  try {
    // ═══ PHASE 1: RECON ═══
    safeOnLog('═══════════════════════════════════════');
    safeOnLog('[PHASE GROUP 1/3] Reconnaissance');
    safeOnLog('═══════════════════════════════════════');
    onPhaseChange(0, 10);

    try {
      const { data, error } = await withTimeout(
        supabase.functions.invoke<ScanResponse>('scan-target', {
          body: { target, phase: 'recon', scanId },
        }),
        60000,
        'Reconnaissance phase timed out'
      );

      if (error) throw new Error(error.message || 'Recon phase failed');
      if (!data || !data.success) {
        throw new Error((data as any)?.error || 'Recon phase unsuccessful');
      }

      if (data.phase !== 'recon') {
        throw new Error('Mismatched phase response');
      }

      const r: ReconData = data.data;
      if (r.logs) {
        for (const log of r.logs) {
          if (log != null) safeOnLog(log);
        }
      }

      dnsRecords = r.dnsRecords || [];
      subdomains = r.subdomains || [];
      headers = r.headers || [];
      technologies = r.technologies || [];
      redirectChain = r.redirectChain || [];

      // Force UI updates to 100% complete for all recon sub-phases upon phase resolution
      onPhaseChange(0, 100);
      onPhaseChange(1, 100);
      onPhaseChange(2, 100);
      onPhaseChange(3, 100);

      safeOnLog('');
      safeOnLog(`[RECON] ✓ Phase 1 complete: ${dnsRecords.length} DNS records, ${subdomains.length} subdomains, ${headers.length} headers`);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Unknown error';
      safeOnLog(`[ERROR] Recon phase failed: ${errMsg}`);
      throw err;
    }

    // ═══ PHASE 2: ACTIVE ═══
    safeOnLog('');
    safeOnLog('═══════════════════════════════════════');
    safeOnLog('[PHASE GROUP 2/3] Active Scanning');
    safeOnLog('═══════════════════════════════════════');
    onPhaseChange(4, 10);

    try {
      const { data, error } = await withTimeout(
        supabase.functions.invoke<ScanResponse>('scan-target', {
          body: { target, phase: 'active', scanId },
        }),
        60000,
        'Active scanning phase timed out'
      );

      if (error) throw new Error(error.message || 'Active phase failed');
      if (!data || !data.success) {
        throw new Error((data as any)?.error || 'Active phase unsuccessful');
      }

      if (data.phase !== 'active') {
        throw new Error('Mismatched phase response');
      }

      const r: ActiveData = data.data;
      if (r.logs) {
        for (const log of r.logs) {
          if (log != null) safeOnLog(log);
        }
      }

      sensitiveFiles = r.sensitiveFiles || [];
      sslInfo = r.sslInfo || sslInfo;
      openPorts = r.openPorts || [];
      crawlStats = r.crawlStats || crawlStats;
      crawlData = r.crawlData || null;

      // Force UI updates to 100% complete for all active sub-phases upon phase resolution
      onPhaseChange(4, 100);
      onPhaseChange(5, 100);
      onPhaseChange(7, 100);
      onPhaseChange(8, 100);

      safeOnLog('');
      safeOnLog(`[ACTIVE] ✓ Phase 2 complete: ${sensitiveFiles.length} exposed files, SSL ${sslInfo.grade}, ${openPorts.length} ports, ${crawlStats.pagesDiscovered} pages crawled`);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Unknown error';
      safeOnLog(`[ERROR] Active phase failed: ${errMsg}`);
      throw err;
    }

    // ═══ PHASE 3: ATTACK ═══
    safeOnLog('');
    safeOnLog('═══════════════════════════════════════');
    safeOnLog('[PHASE GROUP 3/3] Attack Surface Testing');
    safeOnLog('═══════════════════════════════════════');
    onPhaseChange(9, 10);

    try {
      const { data, error } = await withTimeout(
        supabase.functions.invoke<ScanResponse>('scan-target', {
          body: { target, phase: 'attack', crawlData, scanId },
        }),
        90000,
        'Attack testing phase timed out'
      );

      if (error) throw new Error(error.message || 'Attack phase failed');
      if (!data || !data.success) {
        throw new Error((data as any)?.error || 'Attack phase unsuccessful');
      }

      if (data.phase !== 'attack') {
        throw new Error('Mismatched phase response');
      }

      const r: AttackData = data.data;
      if (r.logs) {
        for (const log of r.logs) {
          if (log != null) safeOnLog(log);
        }
      }

      injectionFindings = r.injectionFindings || [];
      corsFindings = r.corsFindings || [];
      openRedirectFindings = r.openRedirectFindings || [];

      // Force UI updates to 100% complete for all attack sub-phases upon phase resolution
      onPhaseChange(9, 100);
      onPhaseChange(10, 100);
      onPhaseChange(11, 100);

      safeOnLog('');
      safeOnLog(`[ATTACK] ✓ Phase 3 complete: ${injectionFindings.length} injection, ${corsFindings.length} CORS, ${openRedirectFindings.length} redirect findings`);
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : 'Unknown error';
      safeOnLog(`[ERROR] Attack phase failed: ${errMsg}`);
      throw err;
    }

    // ═══ REPORT GENERATION ═══
    onPhaseChange(12, 50);
    safeOnLog('');
    safeOnLog('═══════════════════════════════════════');
    safeOnLog('[REPORT] Compiling final report...');
    safeOnLog('═══════════════════════════════════════');

    const vulnerabilities = generateVulnerabilities({
      headers, dnsRecords, sslInfo, sensitiveFiles, redirectChain,
      openPorts, injectionFindings, corsFindings, openRedirectFindings,
    }, target);

    safeOnLog(`[REPORT] Found ${vulnerabilities.length} vulnerabilities`);
    safeOnLog(`[REPORT] ${headers.length} headers, ${dnsRecords.length} DNS, ${subdomains.length} subdomains`);
    safeOnLog(`[REPORT] ${openPorts.length} ports, ${sensitiveFiles.length} files, SSL: ${sslInfo.grade}`);
    safeOnLog(`[REPORT] Crawled: ${crawlStats.pagesDiscovered} pages, ${crawlStats.paramsFound} params, ${crawlStats.formsFound} forms`);
    safeOnLog(`[REPORT] Injection: ${injectionFindings.length}, CORS: ${corsFindings.length}, Redirect: ${openRedirectFindings.length}`);

    onPhaseChange(12, 100);
    safeOnLog('[REPORT] Report generation complete.');

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
  } finally {
    try {
      supabase.removeChannel(channel);
    } catch (err) {
      console.error('Error removing channel:', err);
    }
  }
}
