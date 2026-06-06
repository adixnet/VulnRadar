import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.39.8';
import { DOMParser } from "https://esm.sh/linkedom@0.18.12";
import { ScanRequest } from './types/scan.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

// ==================== SSRF PREVENTION UTILITIES ====================

function isIPv4(ip: string): boolean {
  const parts = ip.split('.');
  if (parts.length !== 4) return false;
  return parts.every(part => {
    const num = parseInt(part, 10);
    return !isNaN(num) && num >= 0 && num <= 255 && String(num) === part.trim();
  });
}

function ipToLong(ip: string): number {
  const parts = ip.split('.').map(p => parseInt(p, 10));
  return parts[0] * 16777216 + parts[1] * 65536 + parts[2] * 256 + parts[3];
}

const ipv4PrivateRanges = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
  '255.255.255.255/32',
];

function isPrivateIPv4Long(ipLong: number): boolean {
  for (const subnet of ipv4PrivateRanges) {
    const [subnetIp, maskStr] = subnet.split('/');
    const mask = parseInt(maskStr, 10);
    const subnetLong = ipToLong(subnetIp);
    const shift = 32 - mask;
    if ((ipLong >>> shift) === (subnetLong >>> shift)) {
      return true;
    }
  }
  return false;
}

function isPrivateIPv4(ip: string): boolean {
  if (!isIPv4(ip)) return false;
  return isPrivateIPv4Long(ipToLong(ip));
}

function cleanIPv6(ip: string): string {
  ip = ip.trim().toLowerCase();
  if (ip.startsWith('[') && ip.endsWith(']')) {
    ip = ip.slice(1, -1);
  }
  return ip;
}

function isPrivateIPv6(ip: string): boolean {
  const cleaned = cleanIPv6(ip);
  if (cleaned === '::1' || cleaned === '::' || cleaned === '0:0:0:0:0:0:0:1' || cleaned === '0:0:0:0:0:0:0:0') {
    return true;
  }
  if (cleaned.startsWith('fe8') || cleaned.startsWith('fe9') || cleaned.startsWith('fea') || cleaned.startsWith('feb')) {
    return true;
  }
  if (cleaned.startsWith('fc') || cleaned.startsWith('fd')) {
    return true;
  }
  if (cleaned.startsWith('fec') || cleaned.startsWith('fed') || cleaned.startsWith('fee') || cleaned.startsWith('fef')) {
    return true;
  }
  if (cleaned.startsWith('::ffff:')) {
    const ipv4Part = cleaned.substring(7);
    if (isIPv4(ipv4Part)) {
      return isPrivateIPv4(ipv4Part);
    }
    const hexParts = ipv4Part.split(':');
    if (hexParts.length === 2) {
      const high = parseInt(hexParts[0], 16);
      const low = parseInt(hexParts[1], 16);
      if (!isNaN(high) && !isNaN(low)) {
        const ipLong = (high << 16) + low;
        return isPrivateIPv4Long(ipLong);
      }
    }
  }
  return false;
}

async function resolveDNSHTTP(domain: string, type: 'A' | 'AAAA'): Promise<string[]> {
  try {
    const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
    if (!resp.ok) return [];
    const data = await resp.json();
    const ips: string[] = [];
    if (data.Answer && data.Answer.length > 0) {
      for (const answer of data.Answer) {
        if (answer.type === 1 || answer.type === 28) {
          ips.push(String(answer.data || answer.rdata || '').trim());
        }
      }
    }
    return ips;
  } catch {
    return [];
  }
}

async function resolveDNSNatively(domain: string, type: 'A' | 'AAAA'): Promise<string[]> {
  if (typeof Deno !== 'undefined' && typeof Deno.resolveDns === 'function') {
    try {
      return await Deno.resolveDns(domain, type);
    } catch {
      // ignore
    }
  }
  return [];
}

async function resolveDNS(domain: string, type: 'A' | 'AAAA'): Promise<string[]> {
  const nativeResults = await resolveDNSNatively(domain, type);
  if (nativeResults.length > 0) {
    return nativeResults;
  }
  return await resolveDNSHTTP(domain, type);
}

async function validateTarget(domain: string): Promise<{ valid: boolean; reason?: string }> {
  const cleaned = domain.trim();
  
  let checkIp = cleaned;
  if (checkIp.startsWith('[') && checkIp.endsWith(']')) {
    checkIp = checkIp.slice(1, -1);
  }
  
  if (isIPv4(checkIp)) {
    if (isPrivateIPv4(checkIp)) {
      return { valid: false, reason: `Target IP ${checkIp} is a private/reserved address.` };
    }
    return { valid: true };
  }
  
  if (checkIp.includes(':')) {
    if (isPrivateIPv6(checkIp)) {
      return { valid: false, reason: `Target IP ${checkIp} is a private/reserved address.` };
    }
    return { valid: true };
  }
  
  try {
    const aRecords = await resolveDNS(cleaned, 'A');
    const aaaaRecords = await resolveDNS(cleaned, 'AAAA');
    const allIPs = [...aRecords, ...aaaaRecords];
    
    for (const ip of allIPs) {
      if (isIPv4(ip)) {
        if (isPrivateIPv4(ip)) {
          return { valid: false, reason: `Domain resolves to a private IP: ${ip}` };
        }
      } else if (ip.includes(':')) {
        if (isPrivateIPv6(ip)) {
          return { valid: false, reason: `Domain resolves to a private IP: ${ip}` };
        }
      }
    }
  } catch (err) {
    // skip
  }
  
  const lowerDomain = cleaned.toLowerCase();
  const localSuffixes = ['.local', '.internal', '.lan', '.localdomain', '.home', '.onion', '.i2p', '.invalid', '.test', '.example'];
  if (lowerDomain === 'localhost' || localSuffixes.some(suffix => lowerDomain.endsWith(suffix))) {
    return { valid: false, reason: `Target matches a private or local domain.` };
  }
  
  if (!lowerDomain.includes('.')) {
    return { valid: false, reason: `Single-label hostnames are not allowed.` };
  }
  
  return { valid: true };
}

async function safeFetch(url: string, init?: RequestInit): Promise<Response> {
  let currentUrl = url;
  let redirects = 0;
  const maxRedirects = 5;
  const originalRedirect = init?.redirect || 'follow';
  
  if (originalRedirect === 'manual' || originalRedirect === 'error') {
    let urlObj;
    try {
      urlObj = new URL(currentUrl);
    } catch {
      throw new Error(`Invalid URL: ${currentUrl}`);
    }
    const validation = await validateTarget(urlObj.hostname);
    if (!validation.valid) {
      throw new Error(`SSRF blocked: ${validation.reason}`);
    }
    return await fetch(currentUrl, init);
  }
  
  const fetchInit = { ...init, redirect: 'manual' as const };
  
  while (redirects < maxRedirects) {
    let urlObj;
    try {
      urlObj = new URL(currentUrl);
    } catch {
      throw new Error(`Invalid URL: ${currentUrl}`);
    }
    
    const domain = urlObj.hostname;
    const validation = await validateTarget(domain);
    if (!validation.valid) {
      throw new Error(`SSRF blocked: ${validation.reason}`);
    }
    
    const response = await fetch(currentUrl, fetchInit);
    
    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) {
        return response;
      }
      
      const nextUrl = new URL(location, currentUrl).toString();
      currentUrl = nextUrl;
      redirects++;
      continue;
    }
    
    return response;
  }
  
  throw new Error('Too many redirects');
}

interface ScanRequest {
  target: string;
  phase: 'recon' | 'active' | 'attack' | 'all';
  // For attack phase, pass crawl data from active phase
  crawlData?: {
    discoveredParams: { path: string; param: string }[];
    discoveredForms: { action: string; method: string; fields: string[] }[];
  };
}

const SECURITY_HEADERS = [
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'content-security-policy',
  'permissions-policy',
  'referrer-policy',
  'x-xss-protection',
  'cross-origin-opener-policy',
  'cross-origin-resource-policy',
  'cross-origin-embedder-policy',
];

const SENSITIVE_PATHS = [
  { path: '/.env', name: 'Environment File', severity: 'critical' as const, cwe: 'CWE-200' },
  { path: '/.git/config', name: 'Git Repository', severity: 'high' as const, cwe: 'CWE-538' },
  { path: '/.git/HEAD', name: 'Git HEAD', severity: 'high' as const, cwe: 'CWE-538' },
  { path: '/robots.txt', name: 'Robots.txt', severity: 'info' as const, cwe: '' },
  { path: '/.well-known/security.txt', name: 'Security.txt', severity: 'info' as const, cwe: '' },
  { path: '/sitemap.xml', name: 'Sitemap', severity: 'info' as const, cwe: '' },
  { path: '/wp-login.php', name: 'WordPress Login', severity: 'low' as const, cwe: 'CWE-200' },
  { path: '/admin', name: 'Admin Panel', severity: 'medium' as const, cwe: 'CWE-200' },
  { path: '/administrator', name: 'Admin Panel Alt', severity: 'medium' as const, cwe: 'CWE-200' },
  { path: '/.htaccess', name: 'Apache Config', severity: 'high' as const, cwe: 'CWE-538' },
  { path: '/phpinfo.php', name: 'PHP Info', severity: 'high' as const, cwe: 'CWE-200' },
  { path: '/server-status', name: 'Server Status', severity: 'medium' as const, cwe: 'CWE-200' },
  { path: '/wp-config.php.bak', name: 'WordPress Config Backup', severity: 'critical' as const, cwe: 'CWE-530' },
  { path: '/backup.sql', name: 'SQL Backup', severity: 'critical' as const, cwe: 'CWE-530' },
  { path: '/config.php', name: 'PHP Config', severity: 'high' as const, cwe: 'CWE-200' },
  { path: '/web.config', name: 'IIS Config', severity: 'high' as const, cwe: 'CWE-200' },
  { path: '/.DS_Store', name: 'macOS DS_Store', severity: 'medium' as const, cwe: 'CWE-538' },
  { path: '/crossdomain.xml', name: 'Flash Crossdomain', severity: 'medium' as const, cwe: 'CWE-942' },
  { path: '/.svn/entries', name: 'SVN Repository', severity: 'high' as const, cwe: 'CWE-538' },
  { path: '/elmah.axd', name: 'ELMAH Error Log', severity: 'high' as const, cwe: 'CWE-200' },
  { path: '/debug.log', name: 'Debug Log', severity: 'high' as const, cwe: 'CWE-200' },
  { path: '/error.log', name: 'Error Log', severity: 'high' as const, cwe: 'CWE-200' },
];

// EXPANDED subdomain wordlist (100 entries)
const COMMON_SUBDOMAINS = [
  'www', 'mail', 'webmail', 'email', 'api', 'app', 'm', 'mobile',
  'dev', 'develop', 'development', 'staging', 'stg', 'stage',
  'test', 'testing', 'beta', 'sandbox', 'demo', 'alpha',
  'admin', 'panel', 'dashboard', 'portal', 'manage', 'console',
  'blog', 'shop', 'store', 'docs', 'doc', 'documentation',
  'help', 'support', 'kb', 'wiki', 'faq',
  'cdn', 'static', 'assets', 'media', 'img', 'images',
  'ftp', 'sftp', 'git', 'gitlab', 'github', 'bitbucket',
  'vpn', 'remote', 'gateway',
  'auth', 'login', 'sso', 'oauth', 'id', 'identity',
  'status', 'monitor', 'grafana', 'prometheus', 'kibana',
  'ns1', 'ns2', 'ns3', 'ns4', 'mx', 'mx1', 'mx2',
  'smtp', 'imap', 'pop', 'pop3',
  'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
  'ci', 'cd', 'jenkins', 'travis', 'build',
  'staging1', 'staging2', 'uat', 'qa', 'preprod', 'pre-prod',
  'internal', 'intranet', 'private', 'corp', 'office',
  'backup', 'bak', 'old', 'legacy', 'archive',
  'proxy', 'lb', 'loadbalancer', 'cache',
  'ws', 'websocket', 'socket', 'realtime',
  'v1', 'v2', 'v3', 'api-v1', 'api-v2',
  'pay', 'payment', 'checkout', 'billing',
  'crm', 'erp', 'jira', 'confluence',
  'web', 'www1', 'www2',
];

// EXPANDED port list (20 ports)
const COMMON_PORTS = [
  { port: 80, service: 'HTTP' },
  { port: 443, service: 'HTTPS' },
  { port: 8080, service: 'HTTP Proxy' },
  { port: 8443, service: 'HTTPS Alt' },
  { port: 3000, service: 'Node.js/Dev' },
  { port: 5000, service: 'Flask/Dev' },
  { port: 5432, service: 'PostgreSQL' },
  { port: 8000, service: 'Django/Dev' },
  { port: 9200, service: 'Elasticsearch' },
  { port: 9090, service: 'Prometheus' },
  { port: 3306, service: 'MySQL' },
  { port: 6379, service: 'Redis' },
  { port: 27017, service: 'MongoDB' },
  { port: 4443, service: 'HTTPS Alt 2' },
  { port: 8888, service: 'Jupyter/Dev' },
  { port: 2083, service: 'cPanel SSL' },
  { port: 2087, service: 'WHM SSL' },
  { port: 10000, service: 'Webmin' },
  { port: 4200, service: 'Angular Dev' },
  { port: 5173, service: 'Vite Dev' },
];

// EXPANDED injection payloads
const SQLI_PAYLOADS = [
  { payload: "'", name: 'Single Quote' },
  { payload: "1' OR '1'='1", name: 'OR-based (string)' },
  { payload: "1 OR 1=1", name: 'OR-based (numeric)' },
  { payload: "' UNION SELECT NULL--", name: 'UNION NULL' },
  { payload: "admin'--", name: 'Comment Bypass' },
  { payload: "1%27%20OR%20%271%27%3D%271", name: 'URL-encoded OR' },
  { payload: "1'; WAITFOR DELAY '0:0:5'--", name: 'Time-based (MSSQL)' },
  { payload: "1' AND SLEEP(5)--", name: 'Time-based (MySQL)' },
  { payload: "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", name: 'Subquery Sleep' },
  { payload: "' OR ''='", name: 'Empty string OR' },
  { payload: "1) OR (1=1", name: 'Parenthesis bypass' },
  { payload: "' UNION SELECT NULL,NULL--", name: 'UNION 2-col' },
  { payload: "1;SELECT * FROM information_schema.tables--", name: 'Stacked query' },
  { payload: "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--", name: 'Error-based (MSSQL)' },
  { payload: "1' AND extractvalue(1,concat(0x7e,version()))--", name: 'Error-based (MySQL)' },
];

const XSS_PAYLOADS = [
  { payload: '<script>alert(1)</script>', name: 'Basic Script Tag' },
  { payload: '"><script>alert(1)</script>', name: 'Quote Break Script' },
  { payload: "'>alert(1)</script>", name: 'Single Quote Break' },
  { payload: '"><img src=x onerror=alert(1)>', name: 'IMG Onerror' },
  { payload: '<svg/onload=alert(1)>', name: 'SVG Onload' },
  { payload: '{{7*7}}', name: 'Template Injection (SSTI)' },
  { payload: '<body onload=alert(1)>', name: 'Body Onload' },
  { payload: '<input onfocus=alert(1) autofocus>', name: 'Input Autofocus' },
  { payload: '<details open ontoggle=alert(1)>', name: 'Details Toggle' },
  { payload: 'javascript:alert(1)', name: 'JS Protocol' },
  { payload: '<iframe src="javascript:alert(1)">', name: 'Iframe JS' },
  { payload: '${alert(1)}', name: 'Template Literal' },
  { payload: '<marquee onstart=alert(1)>', name: 'Marquee Onstart' },
  { payload: '%3Cscript%3Ealert(1)%3C/script%3E', name: 'URL-encoded Script' },
];

// EXPANDED GET test paths
const INJECTION_TEST_PATHS = [
  '/?q=FUZZ',
  '/?id=FUZZ',
  '/?search=FUZZ',
  '/?redirect=FUZZ',
  '/search?q=FUZZ',
  '/api?query=FUZZ',
  '/page?id=FUZZ',
  '/login?redirect=FUZZ',
  '/?p=FUZZ',
  '/?page=FUZZ',
  '/?cat=FUZZ',
  '/?s=FUZZ',
  '/?action=FUZZ',
  '/product?id=FUZZ',
  '/user?id=FUZZ',
  '/view?file=FUZZ',
  '/download?path=FUZZ',
  '/api/v1/search?q=FUZZ',
  '/api/v2/query?term=FUZZ',
  '/wp-content/?p=FUZZ',
];

const POST_TEST_ENDPOINTS = [
  '/login',
  '/register',
  '/signup',
  '/api/login',
  '/api/auth',
  '/api/search',
  '/contact',
  '/comment',
  '/feedback',
  '/subscribe',
  '/api/user',
  '/api/data',
];

const POST_FIELD_SETS = [
  { fields: { username: 'FUZZ', password: 'test' }, name: 'login-user' },
  { fields: { email: 'FUZZ', password: 'test' }, name: 'login-email' },
  { fields: { q: 'FUZZ' }, name: 'search' },
  { fields: { name: 'FUZZ', email: 'test@test.com', message: 'test' }, name: 'contact-name' },
  { fields: { email: 'FUZZ' }, name: 'subscribe' },
];

const REDIRECT_PARAMS = [
  'url', 'redirect', 'redirect_url', 'redirect_uri', 'return', 'return_url', 'return_to',
  'next', 'dest', 'destination', 'goto', 'callback', 'continue', 'rurl', 'target',
  'forward', 'out', 'link', 'to', 'ref',
];

const REDIRECT_TEST_PAYLOADS = [
  { payload: 'https://evil.com', name: 'Direct external URL' },
  { payload: '//evil.com', name: 'Protocol-relative' },
  { payload: '/\\evil.com', name: 'Backslash bypass' },
  { payload: 'https://evil.com@legitimate.com', name: 'Auth confusion' },
  { payload: '///evil.com', name: 'Triple-slash bypass' },
  { payload: 'https:evil.com', name: 'Missing slashes' },
  { payload: '/redirect?url=https://evil.com', name: 'Chained redirect' },
  { payload: 'javascript:alert(1)', name: 'JS protocol' },
  { payload: 'data:text/html,<h1>test</h1>', name: 'Data URI' },
  { payload: 'https://evil.com%00.legitimate.com', name: 'Null byte bypass' },
  { payload: 'https://evil.com%2F.legitimate.com', name: 'URL-encoded slash' },
  { payload: 'https://evil%E3%80%82com', name: 'Unicode dot bypass' },
  { payload: 'https://evil.com#@legitimate.com', name: 'Fragment confusion' },
];

const REDIRECT_ENDPOINTS = [
  '/login',
  '/logout',
  '/auth',
  '/redirect',
  '/go',
  '/out',
  '/link',
  '/external',
  '/callback',
  '/oauth/callback',
];

const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql_fetch/i,
  /pg_query/i,
  /ORA-\d{5}/,
  /sqlite3?\./i,
  /you have an error in your sql/i,
  /PostgreSQL.*ERROR/i,
  /Warning.*mysql/i,
  /PDOException/i,
  /syntax error at or near/i,
  /unterminated string/i,
];

interface SubdomainInfo {
  subdomain: string;
  ips: string[];
  source: 'dns' | 'crt.sh' | 'both';
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

// ==================== DNS ====================
async function scanDNS(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const records: { type: string; value: string }[] = [];
  const recordTypes = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA'];

  onProgress?.('[RECON] Querying DNS servers...', 10);

  for (let i = 0; i < recordTypes.length; i++) {
    const type = recordTypes[i];
    const pct = Math.round(10 + (i / recordTypes.length) * 70);
    onProgress?.(`[RECON] Querying DNS: Checking ${type} record...`, pct);
    try {
      const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`);
      const data = await resp.json();
      if (data.Answer && data.Answer.length > 0) {
        for (const answer of data.Answer) {
          const value = answer.data || answer.rdata || '';
          records.push({ type, value: String(value) });
          const msg = `[DNS] ${type} record: ${value}`;
          logs.push(msg);
          onProgress?.(msg, pct);
        }
      } else {
        const msg = `[DNS] ${type} record: not found`;
        logs.push(msg);
        onProgress?.(msg, pct);
      }
    } catch (e) {
      const msg = `[DNS] ${type} lookup failed: ${e instanceof Error ? e.message : 'unknown error'}`;
      logs.push(msg);
      onProgress?.(msg, pct);
    }
  }

  // SPF
  onProgress?.('[RECON] Checking SPF/DMARC/DNSSEC records...', 80);
  const spfRecord = records.find(r => r.type === 'TXT' && r.value.includes('v=spf1'));
  if (spfRecord) {
    const msg = `[DNS] ✓ SPF record found: ${spfRecord.value}`;
    logs.push(msg);
    onProgress?.(msg, 82);
    if (spfRecord.value.includes('+all')) {
      const w = '[DNS] WARNING: SPF uses +all (allows ANY server)';
      logs.push(w);
      onProgress?.(w, 83);
    } else if (spfRecord.value.includes('~all')) {
      const w = '[DNS] WARNING: SPF uses ~all (soft fail)';
      logs.push(w);
      onProgress?.(w, 83);
    } else if (spfRecord.value.includes('-all')) {
      const g = '[DNS] ✓ SPF uses -all (strict)';
      logs.push(g);
      onProgress?.(g, 83);
    }
  } else {
    const w = '[DNS] ✗ No SPF record found (email spoofing risk)';
    logs.push(w);
    onProgress?.(w, 83);
  }

  // DMARC
  try {
    const dmarcResp = await fetch(`https://dns.google/resolve?name=_dmarc.${encodeURIComponent(domain)}&type=TXT`);
    const dmarcData = await dmarcResp.json();
    if (dmarcData.Answer && dmarcData.Answer.length > 0) {
      const dmarcValue = dmarcData.Answer[0].data || '';
      records.push({ type: 'DMARC', value: String(dmarcValue) });
      const msg = `[DNS] DMARC record: ${dmarcValue}`;
      logs.push(msg);
      onProgress?.(msg, 85);
      if (String(dmarcValue).includes('p=none')) {
        const w = '[DNS] WARNING: DMARC policy is "none"';
        logs.push(w);
        onProgress?.(w, 86);
      } else if (String(dmarcValue).includes('p=quarantine')) {
        const g = '[DNS] ✓ DMARC policy: quarantine';
        logs.push(g);
        onProgress?.(g, 86);
      } else if (String(dmarcValue).includes('p=reject')) {
        const g = '[DNS] ✓ DMARC policy: reject (strongest)';
        logs.push(g);
        onProgress?.(g, 86);
      }
    } else {
      const w = '[DNS] ✗ No DMARC record found';
      logs.push(w);
      onProgress?.(w, 85);
    }
  } catch {
    logs.push('[DNS] DMARC lookup failed');
    onProgress?.('[DNS] DMARC lookup failed', 85);
  }

  // DNSSEC
  try {
    const dnssecResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=DNSKEY`);
    const dnssecData = await dnssecResp.json();
    if (dnssecData.Answer && dnssecData.Answer.length > 0) {
      const g = '[DNS] ✓ DNSSEC: DNSKEY record found';
      logs.push(g);
      onProgress?.(g, 88);
      records.push({ type: 'DNSSEC', value: 'Enabled' });
    } else if (dnssecData.AD) {
      const g = '[DNS] ✓ DNSSEC: Authenticated response';
      logs.push(g);
      onProgress?.(g, 88);
      records.push({ type: 'DNSSEC', value: 'Enabled (AD flag)' });
    } else {
      const w = '[DNS] ✗ DNSSEC: Not enabled';
      logs.push(w);
      onProgress?.(w, 88);
      records.push({ type: 'DNSSEC', value: 'Not enabled' });
    }
  } catch {
    logs.push('[DNS] DNSSEC check failed');
    onProgress?.('[DNS] DNSSEC check failed', 88);
  }

  // CAA
  onProgress?.('[RECON] Checking CAA records...', 90);
  try {
    const caaResp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=CAA`);
    const caaData = await caaResp.json();
    if (caaData.Answer && caaData.Answer.length > 0) {
      for (const answer of caaData.Answer) {
        records.push({ type: 'CAA', value: String(answer.data || '') });
        const g = `[DNS] ✓ CAA record: ${answer.data}`;
        logs.push(g);
        onProgress?.(g, 95);
      }
    } else {
      const w = '[DNS] ✗ No CAA record';
      logs.push(w);
      onProgress?.(w, 95);
    }
  } catch {
    logs.push('[DNS] CAA lookup failed');
    onProgress?.('[DNS] CAA lookup failed', 95);
  }

  onProgress?.('[RECON] DNS Reconnaissance complete.', 100);
  return { logs, records };
}

// ==================== SUBDOMAINS ====================
async function queryCertTransparency(domain: string, onProgress?: ProgressCallback): Promise<{ logs: string[]; subdomains: string[] }> {
  const logs: string[] = [];
  const found = new Set<string>();
  try {
    const m = '[SUBDOMAIN] Querying Certificate Transparency logs (crt.sh)...';
    logs.push(m);
    onProgress?.(m, 20);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const resp = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { signal: controller.signal });
    clearTimeout(timeout);
    if (resp.ok) {
      const entries: { name_value: string }[] = await resp.json();
      for (const entry of entries) {
        for (const name of entry.name_value.split('\n')) {
          const clean = name.trim().toLowerCase().replace(/^\*\./, '');
          if (clean.endsWith(`.${domain}`) && clean !== domain && !clean.includes('*')) found.add(clean);
        }
      }
      const m2 = `[SUBDOMAIN] CT logs returned ${found.size} unique subdomains`;
      logs.push(m2);
      onProgress?.(m2, 40);
    } else {
      const m2 = `[SUBDOMAIN] CT log query returned ${resp.status}`;
      logs.push(m2);
      onProgress?.(m2, 40);
    }
  } catch (e) {
    const msg = e instanceof Error ? e.message : 'unknown';
    const m = msg.includes('abort') ? '[SUBDOMAIN] CT log query timed out (10s)' : `[SUBDOMAIN] CT log query failed: ${msg}`;
    logs.push(m);
    onProgress?.(m, 40);
  }
  return { logs, subdomains: Array.from(found) };
}

async function resolveSubdomain(sub: string, domain: string): Promise<{ subdomain: string; ips: string[] } | null> {
  try {
    const resp = await fetch(`https://dns.google/resolve?name=${sub}.${domain}&type=A`);
    const data = await resp.json();
    if (data.Answer && data.Answer.length > 0) {
      const ips = data.Answer.filter((a: any) => a.type === 1).map((a: any) => String(a.data));
      return { subdomain: `${sub}.${domain}`, ips };
    }
  } catch { /* skip */ }
  return null;
}

async function enumerateSubdomains(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const subdomainMap = new Map<string, SubdomainInfo>();

  const m1 = '[SUBDOMAIN] Starting comprehensive subdomain enumeration...';
  logs.push(m1);
  onProgress?.(m1, 10);
  const m2 = `[SUBDOMAIN] Wordlist: ${COMMON_SUBDOMAINS.length} prefixes`;
  logs.push(m2);
  onProgress?.(m2, 12);

  // Run CT + DNS in parallel, but batch DNS to avoid overwhelming
  onProgress?.('[SUBDOMAIN] Querying Certificate Transparency and resolving common prefixes...', 15);

  const batches = chunkArray(COMMON_SUBDOMAINS, 25);

  const [ctResult, ...dnsResults] = await Promise.all([
    queryCertTransparency(domain, (msg, pct) => {
      // Map 20-40% of queryCertTransparency to 15-35% of enumerateSubdomains
      const mappedPct = pct ? Math.round(15 + (pct / 100) * 20) : 25;
      onProgress?.(msg, mappedPct);
    }),
    ...batches.map(async (batch, batchIdx) => {
      const results: { subdomain: string; ips: string[] }[] = [];
      const batchResults = await Promise.all(batch.map(sub => resolveSubdomain(sub, domain)));
      for (const r of batchResults) { if (r) results.push(r); }

      const pct = Math.round(35 + (batchIdx / batches.length) * 25);
      onProgress?.(`[SUBDOMAIN] Resolved batch ${batchIdx + 1}/${batches.length}...`, pct);
      return results;
    }),
  ]);

  logs.push(...ctResult.logs);
  for (const batch of dnsResults) {
    for (const item of batch) {
      subdomainMap.set(item.subdomain, { subdomain: item.subdomain, ips: item.ips, source: 'dns' });
    }
  }

  // Resolve CT-only subs
  const ctOnlySubs = ctResult.subdomains.filter(s => !subdomainMap.has(s));
  if (ctOnlySubs.length > 0) {
    const m3 = `[SUBDOMAIN] Resolving ${ctOnlySubs.length} CT-only subdomains...`;
    logs.push(m3);
    onProgress?.(m3, 60);

    const sliceCount = 80;
    const subsToResolve = ctOnlySubs.slice(0, sliceCount);
    const ctResolveResults = await Promise.all(
      subsToResolve.map(async (sub, subIdx) => {
        try {
          const resp = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(sub)}&type=A`);
          const data = await resp.json();
          if (data.Answer && data.Answer.length > 0) {
            const ips = data.Answer.filter((a: any) => a.type === 1).map((a: any) => String(a.data));

            if (subIdx % 10 === 0) {
              const pct = Math.round(60 + (subIdx / subsToResolve.length) * 20);
              onProgress?.(`[SUBDOMAIN] Resolving CT subdomains: ${subIdx}/${subsToResolve.length}...`, pct);
            }
            return { subdomain: sub, ips };
          }
        } catch { /* skip */ }
        return null;
      })
    );
    for (const r of ctResolveResults) {
      if (r) {
        const existing = subdomainMap.get(r.subdomain);
        if (existing) existing.source = 'both';
        else subdomainMap.set(r.subdomain, { subdomain: r.subdomain, ips: r.ips, source: 'crt.sh' });
      }
    }
  }

  for (const ctSub of ctResult.subdomains) {
    const existing = subdomainMap.get(ctSub);
    if (existing && existing.source === 'dns') existing.source = 'both';
  }

  const allSubs = Array.from(subdomainMap.values());
  const uniqueIPs = new Set(allSubs.flatMap(s => s.ips));

  logs.push('');
  logs.push(`[SUBDOMAIN] ═══ Results ═══`);
  logs.push(`[SUBDOMAIN] Total unique subdomains: ${allSubs.length}`);
  logs.push(`[SUBDOMAIN] Unique IPs: ${uniqueIPs.size}`);

  onProgress?.(`[SUBDOMAIN] Enumerated ${allSubs.length} subdomains on ${uniqueIPs.size} unique IPs`, 85);

  for (const info of allSubs.slice(0, 50)) {
    const ipStr = info.ips.length > 0 ? ` → ${info.ips.join(', ')}` : '';
    const srcTag = info.source === 'both' ? '[DNS+CT]' : info.source === 'crt.sh' ? '[CT]' : '[DNS]';
    const msg = `[SUBDOMAIN]   ${srcTag} ${info.subdomain}${ipStr}`;
    logs.push(msg);
    onProgress?.(msg, 90);
  }
  if (allSubs.length > 50) {
    const msg = `[SUBDOMAIN]   ... and ${allSubs.length - 50} more`;
    logs.push(msg);
    onProgress?.(msg, 92);
  }

  const devSubs = allSubs.filter(s => /\b(dev|test|staging|stg|qa|uat|sandbox|demo|beta|alpha|tmp|temp|old|legacy|backup)\b/i.test(s.subdomain));
  if (devSubs.length > 0) {
    const msg = `[SUBDOMAIN] ⚠️ ${devSubs.length} development/staging subdomains detected`;
    logs.push(msg);
    onProgress?.(msg, 95);
    for (const d of devSubs.slice(0, 10)) {
      const w = `[SUBDOMAIN]   WARNING: ${d.subdomain}`;
      logs.push(w);
      onProgress?.(w, 96);
    }
  }

  const adminSubs = allSubs.filter(s => /\b(admin|panel|dashboard|manage|cpanel|whm|webmin|console)\b/i.test(s.subdomain));
  if (adminSubs.length > 0) {
    const msg = `[SUBDOMAIN] ⚠️ ${adminSubs.length} admin panel subdomains`;
    logs.push(msg);
    onProgress?.(msg, 98);
    for (const a of adminSubs.slice(0, 5)) {
      const w = `[SUBDOMAIN]   WARNING: ${a.subdomain}`;
      logs.push(w);
      onProgress?.(w, 99);
    }
  }

  onProgress?.('[SUBDOMAIN] Subdomain enumeration complete.', 100);
  return { logs, subdomains: allSubs.map(s => s.subdomain), subdomainDetails: allSubs };
}

// ==================== HEADERS ====================
async function scanHeaders(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const headers: { name: string; value: string; status: 'secure' | 'warning' | 'missing' }[] = [];
  const technologies: { name: string; version: string; category: string }[] = [];
  const targetUrl = domain.startsWith('http') ? domain : `https://${domain}`;

  try {
    logs.push(`[HEADERS] Fetching ${targetUrl}...`);
    const resp = await safeFetch(targetUrl, { redirect: 'follow', headers: { 'User-Agent': 'VulnRadar/1.0.0 Security Scanner' } });
    logs.push(`[HEADERS] Response: ${resp.status} ${resp.statusText}`);
    await resp.text();

    const headerMap: Record<string, string> = {};
    resp.headers.forEach((value, key) => { headerMap[key.toLowerCase()] = value; });

    onProgress?.('[HEADERS] Analyzing security headers...', 50);
    for (let i = 0; i < SECURITY_HEADERS.length; i++) {
      const headerName = SECURITY_HEADERS[i];
      const pct = Math.round(50 + (i / SECURITY_HEADERS.length) * 30);
      const displayName = headerName.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join('-');
      if (headerMap[headerName]) {
        headers.push({ name: displayName, value: headerMap[headerName], status: 'secure' });
        const g = `[HEADERS] ✓ ${displayName}: ${headerMap[headerName]}`;
        logs.push(g);
        onProgress?.(g, pct);
      } else {
        headers.push({ name: displayName, value: '', status: 'missing' });
        const w = `[HEADERS] ✗ ${displayName}: MISSING`;
        logs.push(w);
        onProgress?.(w, pct);
      }
    }

    // HSTS analysis
    const hstsVal = headerMap['strict-transport-security'] || '';
    if (hstsVal) {
      const maxAge = hstsVal.match(/max-age=(\d+)/)?.[1];
      if (maxAge && parseInt(maxAge) < 31536000) {
        const w = `[HEADERS] WARNING: HSTS max-age is ${maxAge}s (should be ≥31536000)`;
        logs.push(w);
        onProgress?.(w, 82);
      }
      if (!hstsVal.includes('includeSubDomains')) {
        const w = '[HEADERS] WARNING: HSTS missing includeSubDomains';
        logs.push(w);
        onProgress?.(w, 83);
      }
      if (!hstsVal.includes('preload')) {
        const inf = '[HEADERS] INFO: HSTS missing preload';
        logs.push(inf);
        onProgress?.(inf, 84);
      }
    }

    // Info-leaking headers
    onProgress?.('[HEADERS] Fingerprinting technologies and framework signatures...', 85);
    const serverHeader = headerMap['server'];
    if (serverHeader) {
      headers.push({ name: 'Server', value: serverHeader, status: 'warning' });
      const w = `[HEADERS] WARNING: Server header reveals: ${serverHeader}`;
      logs.push(w);
      onProgress?.(w, 87);
      if (serverHeader.toLowerCase().includes('nginx')) technologies.push({ name: 'nginx', version: serverHeader.match(/nginx\/([\d.]+)/)?.[1] || 'unknown', category: 'Web Server' });
      if (serverHeader.toLowerCase().includes('apache')) technologies.push({ name: 'Apache', version: serverHeader.match(/Apache\/([\d.]+)/)?.[1] || 'unknown', category: 'Web Server' });
      if (serverHeader.toLowerCase().includes('cloudflare')) technologies.push({ name: 'Cloudflare', version: '-', category: 'CDN' });
      if (serverHeader.toLowerCase().includes('iis')) technologies.push({ name: 'Microsoft IIS', version: serverHeader.match(/IIS\/([\d.]+)/)?.[1] || 'unknown', category: 'Web Server' });
    }

    const poweredBy = headerMap['x-powered-by'];
    if (poweredBy) {
      const w = `[HEADERS] WARNING: X-Powered-By reveals: ${poweredBy}`;
      logs.push(w);
      onProgress?.(w, 89);
      technologies.push({ name: poweredBy.split('/')[0], version: poweredBy.split('/')[1] || 'unknown', category: 'Framework' });
    }

    if (headerMap['x-drupal-cache']) technologies.push({ name: 'Drupal', version: 'detected', category: 'CMS' });
    if (headerMap['x-wordpress-cache'] || headerMap['x-wp-super-cache']) technologies.push({ name: 'WordPress', version: 'detected', category: 'CMS' });
    if (headerMap['x-shopify-stage']) technologies.push({ name: 'Shopify', version: 'detected', category: 'E-commerce' });
    if (headerMap['x-vercel-id']) technologies.push({ name: 'Vercel', version: '-', category: 'Platform' });
    if (headerMap['x-amz-cf-id']) technologies.push({ name: 'AWS CloudFront', version: '-', category: 'CDN' });
    if (headerMap['cf-ray']) technologies.push({ name: 'Cloudflare', version: '-', category: 'CDN' });

    const cors = headerMap['access-control-allow-origin'];
    if (cors === '*') {
      const w = '[HEADERS] WARNING: CORS allows all origins (*)';
      logs.push(w);
      onProgress?.(w, 92);
    } else if (cors) {
      const inf = `[HEADERS] CORS origin: ${cors}`;
      logs.push(inf);
      onProgress?.(inf, 92);
    }

    const setCookie = headerMap['set-cookie'];
    if (setCookie) {
      if (!setCookie.toLowerCase().includes('httponly')) {
        const w = '[HEADERS] WARNING: Cookie missing HttpOnly flag';
        logs.push(w);
        onProgress?.(w, 94);
      }
      if (!setCookie.toLowerCase().includes('secure')) {
        const w = '[HEADERS] WARNING: Cookie missing Secure flag';
        logs.push(w);
        onProgress?.(w, 95);
      }
      if (!setCookie.toLowerCase().includes('samesite')) {
        const w = '[HEADERS] WARNING: Cookie missing SameSite';
        logs.push(w);
        onProgress?.(w, 96);
      }
    }

    const missingCount = headers.filter(h => h.status === 'missing').length;
    const m3 = `[HEADERS] Summary: ${headers.filter(h => h.status === 'secure').length} secure, ${missingCount} missing, ${headers.filter(h => h.status === 'warning').length} warnings`;
    logs.push(m3);
    onProgress?.(m3, 98);
  } catch (e) {
    const errM = `[HEADERS] ERROR: Failed to fetch target — ${e instanceof Error ? e.message : 'unknown'}`;
    logs.push(errM);
    onProgress?.(errM, 98);
  }

  onProgress?.('[HEADERS] HTTP Security Headers analysis complete.', 100);
  return { logs, headers, technologies };
}

// ==================== REDIRECT CHAIN ====================
async function checkRedirectChain(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const chain: { url: string; status: number }[] = [];

  try {
    const httpUrl = `http://${domain.replace(/^https?:\/\//, '')}`;
    const m1 = `[REDIRECT] Checking HTTP → HTTPS redirect from ${httpUrl}...`;
    logs.push(m1);
    onProgress?.(m1, 20);
    const resp = await fetch(httpUrl, { redirect: 'manual' });
    chain.push({ url: httpUrl, status: resp.status });
    if (resp.status >= 300 && resp.status < 400) {
      const location = resp.headers.get('location') || '';
      chain.push({ url: location, status: 0 });
      if (location.startsWith('https://')) {
        const g = `[REDIRECT] ✓ HTTP redirects to HTTPS: ${location}`;
        logs.push(g);
        onProgress?.(g, 40);
      } else {
        const w = `[REDIRECT] WARNING: HTTP redirects but NOT to HTTPS: ${location}`;
        logs.push(w);
        onProgress?.(w, 40);
      }
    } else if (resp.status === 200) {
      const w = '[REDIRECT] ✗ HTTP responds with 200 — no redirect to HTTPS!';
      logs.push(w);
      onProgress?.(w, 40);
    }
  } catch (e) {
    const errM = `[REDIRECT] HTTP check failed: ${e instanceof Error ? e.message : 'unknown'}`;
    logs.push(errM);
    onProgress?.(errM, 40);
  }

  try {
    let url = `https://${domain.replace(/^https?:\/\//, '')}`;
    let redirectCount = 0;
    onProgress?.('[REDIRECT] Tracing redirect chain...', 50);
    while (redirectCount < 10) {
      const pct = Math.round(50 + (redirectCount / 10) * 40);
      const resp = await fetch(url, { redirect: 'manual' });
      if (resp.status >= 300 && resp.status < 400) {
        const location = resp.headers.get('location') || '';
        chain.push({ url, status: resp.status });
        url = location.startsWith('http') ? location : `https://${domain}${location}`;
        redirectCount++;
        onProgress?.(`[REDIRECT] Redirect ${redirectCount}: ${resp.status} → ${url}`, pct);
      } else {
        chain.push({ url, status: resp.status });
        break;
      }
    }
    if (redirectCount > 3) {
      const w = `[REDIRECT] WARNING: ${redirectCount} redirects detected`;
      logs.push(w);
      onProgress?.(w, 95);
    } else if (redirectCount > 0) {
      const g = `[REDIRECT] ${redirectCount} redirect(s) in chain`;
      logs.push(g);
      onProgress?.(g, 95);
    }
  } catch {
    logs.push('[REDIRECT] Could not trace full redirect chain');
    onProgress?.('[REDIRECT] Could not trace full redirect chain', 95);
  }

  onProgress?.('[REDIRECT] Redirect chain analysis complete.', 100);
  return { logs, chain };
}

// ==================== SENSITIVE FILES ====================
async function scanSensitiveFiles(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const exposed: { path: string; name: string; status: number; severity: string }[] = [];
  const baseUrl = `https://${domain.replace(/^https?:\/\//, '')}`;

  const m1 = `[FILES] Checking ${SENSITIVE_PATHS.length} paths for exposed files...`;
  logs.push(m1);
  onProgress?.(m1, 10);

  // Batch in groups to avoid too many concurrent requests
  const batches = chunkArray(SENSITIVE_PATHS, 8);
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const pct = Math.round(10 + (i / batches.length) * 80);
    onProgress?.(`[FILES] Probing files batch ${i+1}/${batches.length}...`, pct);
    const results = await Promise.all(batch.map(async (item) => {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);
        const resp = await safeFetch(`${baseUrl}${item.path}`, {
          signal: controller.signal,
          redirect: 'follow',
          headers: { 'User-Agent': 'VulnRadar/1.0.0 Security Scanner' },
        });
        clearTimeout(timeout);
        const text = await resp.text();
        if (resp.status === 200 && text.length > 10 && !text.toLowerCase().includes('not found') && !text.toLowerCase().includes('404')) {
          return { ...item, status: resp.status, found: true };
        }
        return { ...item, status: resp.status, found: false };
      } catch {
        return { ...item, status: 0, found: false };
      }
    }));

    for (const r of results) {
      if (r.found && r.severity !== 'info') {
        exposed.push({ path: r.path, name: r.name, status: r.status, severity: r.severity });
        const icon = r.severity === 'critical' ? '‼️' : r.severity === 'high' ? '⚠️' : 'ℹ️';
        const msg = `[FILES] ${icon} EXPOSED: ${r.name} at ${r.path} — ${r.severity.toUpperCase()}`;
        logs.push(msg);
        onProgress?.(msg, pct);
      } else if (r.found) {
        const msg = `[FILES] ℹ️ Found: ${r.name} at ${r.path}`;
        logs.push(msg);
        onProgress?.(msg, pct);
      }
    }
  }

  if (exposed.length === 0) {
    const g = '[FILES] ✓ No critical sensitive files exposed';
    logs.push(g);
    onProgress?.(g, 95);
  } else {
    const w = `[FILES] ✗ ${exposed.length} sensitive file(s) exposed!`;
    logs.push(w);
    onProgress?.(w, 95);
  }

  onProgress?.('[FILES] Sensitive file check complete.', 100);
  return { logs, exposed };
}

// ==================== SSL ====================
async function scanSSL(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const sslInfo = { grade: 'Unknown', expiry: 'Unknown', protocol: 'Unknown', cipher: 'Unknown', issues: [] as string[], issuer: 'Unknown', subject: 'Unknown' };
  const targetUrl = `https://${domain.replace(/^https?:\/\//, '')}`;

  try {
    logs.push(`[SSL] Connecting to ${targetUrl}...`);
    const resp = await safeFetch(targetUrl, { headers: { 'User-Agent': 'VulnRadar/1.0.0' } });
    await resp.text();
    if (resp.ok || resp.status < 500) {
      const g = `[SSL] ✓ HTTPS connection successful (${resp.status})`;
      logs.push(g);
      onProgress?.(g, 30);
    }

    onProgress?.('[SSL] Analyzing certificate chain and validity...', 40);
    try {
      const sslResp = await fetch(`https://ssl-checker.io/api/v1/check/${domain.replace(/^https?:\/\//, '')}`);
      const sslText = await sslResp.text();
      try {
        const sslData = JSON.parse(sslText);
        if (sslData.result) {
          const r = sslData.result;
          sslInfo.subject = r.subject || r.common_name || domain;
          sslInfo.issuer = r.issuer || 'Unknown';
          sslInfo.expiry = r.valid_till || r.not_after || 'Unknown';
          sslInfo.protocol = r.protocol || 'TLS 1.2+';

          const m1 = `[SSL] Certificate: ${sslInfo.subject}`;
          const m2 = `[SSL] Issuer: ${sslInfo.issuer}`;
          const m3 = `[SSL] Expires: ${sslInfo.expiry}`;
          logs.push(m1, m2, m3);
          onProgress?.(m1, 60);
          onProgress?.(m2, 70);
          onProgress?.(m3, 80);

          if (r.valid === false || r.expired) {
            sslInfo.issues.push('Certificate expired or invalid');
            sslInfo.grade = 'F';
            const w = '[SSL] ✗ Certificate is EXPIRED or INVALID';
            logs.push(w);
            onProgress?.(w, 85);
          }
        }
      } catch {
        logs.push('[SSL] Could not parse SSL checker response');
        onProgress?.('[SSL] Could not parse SSL checker response', 80);
      }
    } catch {
      logs.push('[SSL] External SSL check unavailable');
      onProgress?.('[SSL] External SSL check unavailable', 80);
    }

    if (sslInfo.grade === 'Unknown') {
      sslInfo.grade = 'B+';
      const g1 = '[SSL] ✓ HTTPS works correctly';
      const g2 = '[SSL] Grade: B+ (based on successful HTTPS connection)';
      logs.push(g1, g2);
      onProgress?.(g1, 90);
      onProgress?.(g2, 95);
    }
  } catch (e) {
    const errMsg = e instanceof Error ? e.message : 'unknown';
    if (errMsg.includes('certificate') || errMsg.includes('SSL') || errMsg.includes('TLS')) {
      sslInfo.grade = 'F';
      sslInfo.issues.push(`SSL/TLS error: ${errMsg}`);
      const w = `[SSL] ✗ SSL ERROR: ${errMsg}`;
      logs.push(w);
      onProgress?.(w, 90);
    } else {
      const w = `[SSL] Connection failed: ${errMsg}`;
      logs.push(w);
      onProgress?.(w, 70);
      try {
        const httpResp = await safeFetch(`http://${domain.replace(/^https?:\/\//, '')}`);
        await httpResp.text();
        sslInfo.grade = 'F';
        sslInfo.issues.push('Site accessible via HTTP only');
        const w2 = '[SSL] ✗ No HTTPS available';
        logs.push(w2);
        onProgress?.(w2, 85);
      } catch {
        const w2 = '[SSL] Target not reachable';
        logs.push(w2);
        onProgress?.(w2, 85);
        sslInfo.grade = 'N/A';
      }
    }
  }

  onProgress?.('[SSL] SSL/TLS configuration analysis complete.', 100);
  return { logs, sslInfo };
}

// ==================== PORTS ====================
async function probePort(domain: string, port: number, service: string): Promise<{ port: number; service: string; version: string; state: string } | null> {
  const protocol = [443, 8443, 4443, 2083, 2087].includes(port) ? 'https' : 'http';
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3000);
    const resp = await safeFetch(`${protocol}://${domain}:${port}/`, {
      signal: controller.signal, redirect: 'follow', headers: { 'User-Agent': 'VulnRadar/1.0.0' },
    });
    clearTimeout(timeout);
    const server = resp.headers.get('server') || '';
    const poweredBy = resp.headers.get('x-powered-by') || '';
    return { port, service, version: server || poweredBy || `HTTP ${resp.status}`, state: 'open' };
  } catch { return null; }
}

async function scanPorts(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const openPorts: { port: number; service: string; version: string; state: string }[] = [];
  
  const m = `[PORTS] Probing ${COMMON_PORTS.length} ports...`;
  logs.push(m);
  onProgress?.(m, 10);

  // Batch ports to avoid too many concurrent
  const batches = chunkArray(COMMON_PORTS, 10);
  for (let i = 0; i < batches.length; i++) {
    const batch = batches[i];
    const pct = Math.round(10 + (i / batches.length) * 80);
    onProgress?.(`[PORTS] Scanning ports batch ${i+1}/${batches.length}...`, pct);
    const results = await Promise.all(batch.map(p => probePort(domain, p.port, p.service)));
    for (const r of results) {
      if (r) {
        openPorts.push(r);
        const msg = `[PORTS] ✓ OPEN: port ${r.port} (${r.service}) — ${r.version}`;
        logs.push(msg);
        onProgress?.(msg, pct);
      }
    }
  }

  if (openPorts.length === 0) {
    const msg = '[PORTS] No open web service ports detected';
    logs.push(msg);
    onProgress?.(msg, 95);
  } else {
    const msg = `[PORTS] ${openPorts.length} open port(s) found`;
    logs.push(msg);
    onProgress?.(msg, 95);
  }

  const riskyPorts = openPorts.filter(p => [5432, 3306, 6379, 27017, 9200, 8888, 10000, 3000, 5000, 8000, 9090].includes(p.port));
  if (riskyPorts.length > 0) {
    const w = `[PORTS] ⚠️ ${riskyPorts.length} potentially risky service(s) exposed`;
    logs.push(w);
    onProgress?.(w, 98);
    for (const rp of riskyPorts) {
      const w2 = `[PORTS]   WARNING: Port ${rp.port} (${rp.service})`;
      logs.push(w2);
      onProgress?.(w2, 99);
    }
  }

  onProgress?.('[PORTS] Port probing complete.', 100);
  return { logs, openPorts };
}

// ==================== SPIDER ====================
interface CrawlResult {
  logs: string[];
  discoveredUrls: string[];
  discoveredParams: { path: string; param: string }[];
  discoveredForms: { action: string; method: string; fields: string[] }[];
}

function extractLinks(html: string, baseUrl: string, domain: string): string[] {
  const links = new Set<string>();
  try {
    const document = new DOMParser().parseFromString(html, "text/html");
    const aTags = document.querySelectorAll("a[href]");
    for (const a of aTags) {
      let href = a.getAttribute("href")?.trim();
      if (!href) continue;
      if (href.startsWith('mailto:') || href.startsWith('tel:') || href.startsWith('javascript:') || href.startsWith('data:')) continue;
      if (href.startsWith('/')) href = `${baseUrl}${href}`;
      else if (!href.startsWith('http')) href = `${baseUrl}/${href}`;
      try {
        const urlObj = new URL(href);
        if (urlObj.hostname === domain || urlObj.hostname.endsWith(`.${domain}`)) {
          links.add(`${urlObj.origin}${urlObj.pathname}${urlObj.search}`);
        }
      } catch { /* invalid URL */ }
    }
  } catch { /* invalid html or URL */ }
  return Array.from(links);
}

function extractParams(url: string): { path: string; param: string }[] {
  try {
    const urlObj = new URL(url);
    const params: { path: string; param: string }[] = [];
    urlObj.searchParams.forEach((_, key) => { params.push({ path: urlObj.pathname + '?' + key + '=FUZZ', param: key }); });
    return params;
  } catch { return []; }
}

function extractForms(html: string, pageUrl: string, baseUrl: string): { action: string; method: string; fields: string[] }[] {
  const forms: { action: string; method: string; fields: string[] }[] = [];
  try {
    const document = new DOMParser().parseFromString(html, "text/html");
    const formElements = document.querySelectorAll("form");
    for (const form of formElements) {
      let action = form.getAttribute("action") || pageUrl;
      if (action.startsWith('/')) action = `${baseUrl}${action}`;
      else if (!action.startsWith('http')) action = `${baseUrl}/${action}`;
      const method = (form.getAttribute("method") || 'GET').toUpperCase();
      const fields: string[] = [];
      const inputs = form.querySelectorAll("input[name], textarea[name], select[name]");
      for (const input of inputs) {
        const name = input.getAttribute("name");
        if (name) fields.push(name);
      }
      if (fields.length > 0) forms.push({ action, method, fields });
    }
  } catch { /* parse error */ }
  return forms;
}

async function crawlUrl(url: string, domain: string, baseUrl: string) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(url, { signal: controller.signal, redirect: 'follow', headers: { 'User-Agent': 'VulnRadar/1.0.0 Security Spider' } });
    clearTimeout(timeout);
    const contentType = resp.headers.get('content-type') || '';
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
      if (resp.body) await resp.body.cancel();
      return null;
    }
    
    const MAX_SIZE = 1024 * 1024; // 1MB limit
    let size = 0;
    const reader = resp.body?.getReader();
    if (!reader) return null;
    
    const chunks: Uint8Array[] = [];
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        size += value.length;
        if (size > MAX_SIZE) {
          await reader.cancel('Response too large');
          break;
        }
        chunks.push(value);
      }
    }
    
    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const fullBuffer = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      fullBuffer.set(chunk, offset);
      offset += chunk.length;
    }
    const html = new TextDecoder().decode(fullBuffer);

    const links = extractLinks(html, baseUrl, domain);
    const params = extractParams(url);
    for (const link of links) params.push(...extractParams(link));
    const forms = extractForms(html, url, baseUrl);
    return { url, links, params, forms };
  } catch { return null; }
}

// EXPANDED: depth 2, 20 pages
async function spiderTarget(domain: string, onProgress?: ProgressCallback): Promise<CrawlResult> {
  const logs: string[] = [];
  const baseUrl = `https://${domain}`;
  const visited = new Set<string>();
  const allParams = new Map<string, { path: string; param: string }>();
  const allForms: { action: string; method: string; fields: string[] }[] = [];
  const maxPages = 20;
  const maxDepth = 2;

  const m1 = '[SPIDER] Starting active URL crawling...';
  const m2 = `[SPIDER] Target: ${baseUrl}`;
  const m3 = `[SPIDER] Max depth: ${maxDepth}, Max pages: ${maxPages}`;
  logs.push(m1, m2, m3);
  onProgress?.(m1, 5);
  onProgress?.(m2, 7);
  onProgress?.(m3, 10);

  const queue: { url: string; depth: number }[] = [{ url: baseUrl, depth: 0 }];
  const seedPaths = ['/', '/login', '/search', '/contact', '/api', '/sitemap.xml', '/about', '/register', '/signup', '/dashboard', '/admin', '/help'];
  for (const sp of seedPaths) queue.push({ url: `${baseUrl}${sp}`, depth: 0 });

  let pagesProcessed = 0;
  onProgress?.('[SPIDER] Crawling seed URLs and discovering local links...', 15);
  while (queue.length > 0 && pagesProcessed < maxPages) {
    const pct = Math.round(15 + (pagesProcessed / maxPages) * 70);
    const batch = queue.splice(0, 5);
    const newBatch = batch.filter(item => {
      const normalized = item.url.split('?')[0];
      if (visited.has(normalized) || item.depth > maxDepth) return false;
      visited.add(normalized);
      return true;
    });
    if (newBatch.length === 0) continue;

    const results = await Promise.all(newBatch.map(item => crawlUrl(item.url, domain, baseUrl)));
    for (let i = 0; i < results.length; i++) {
      const page = results[i];
      if (!page) continue;
      pagesProcessed++;
      const depth = newBatch[i].depth;
      const msg = `[SPIDER] [depth:${depth}] Crawled: ${page.url} → ${page.links.length} links, ${page.forms.length} forms`;
      logs.push(msg);
      onProgress?.(msg, pct);
      for (const p of page.params) allParams.set(`${p.path}:${p.param}`, p);
      for (const f of page.forms) allForms.push(f);
      if (depth < maxDepth) {
        for (const link of page.links) {
          if (!visited.has(link.split('?')[0])) queue.push({ url: link, depth: depth + 1 });
        }
      }
    }
  }

  const uniqueParams = Array.from(allParams.values());
  const formKeys = new Set<string>();
  const uniqueForms = allForms.filter(f => {
    const key = `${f.method}:${f.action}`;
    if (formKeys.has(key)) return false;
    formKeys.add(key);
    return true;
  });

  logs.push('');
  logs.push('[SPIDER] ═══ Crawl Results ═══');
  logs.push(`[SPIDER] Pages crawled: ${pagesProcessed}`);
  logs.push(`[SPIDER] Unique URLs discovered: ${visited.size}`);
  logs.push(`[SPIDER] Parameters found: ${uniqueParams.length}`);
  logs.push(`[SPIDER] Forms discovered: ${uniqueForms.length}`);

  onProgress?.(`[SPIDER] Crawl complete: ${pagesProcessed} pages, ${visited.size} URLs, ${uniqueParams.length} params, ${uniqueForms.length} forms`, 88);

  if (uniqueParams.length > 0) {
    const msg = '[SPIDER] Discovered parameters:';
    logs.push(msg);
    onProgress?.(msg, 90);
    for (const p of uniqueParams.slice(0, 25)) {
      const inf = `[SPIDER]   ${p.param} → ${p.path}`;
      logs.push(inf);
      onProgress?.(inf, 91);
    }
    if (uniqueParams.length > 25) {
      const inf = `[SPIDER]   ... and ${uniqueParams.length - 25} more`;
      logs.push(inf);
      onProgress?.(inf, 92);
    }
  }
  if (uniqueForms.length > 0) {
    const msg = '[SPIDER] Discovered forms:';
    logs.push(msg);
    onProgress?.(msg, 93);
    for (const f of uniqueForms.slice(0, 15)) {
      const inf = `[SPIDER]   ${f.method} ${f.action} [${f.fields.join(', ')}]`;
      logs.push(inf);
      onProgress?.(inf, 94);
    }
    if (uniqueForms.length > 15) {
      const inf = `[SPIDER]   ... and ${uniqueForms.length - 15} more`;
      logs.push(inf);
      onProgress?.(inf, 95);
    }
  }

  const loginForms = uniqueForms.filter(f => f.fields.some(field => /password|passwd|pass/i.test(field)));
  if (loginForms.length > 0) {
    const w = `[SPIDER] ⚠️ ${loginForms.length} login/authentication form(s) discovered`;
    logs.push(w);
    onProgress?.(w, 98);
    for (const lf of loginForms) {
      const w2 = `[SPIDER]   ${lf.method} ${lf.action} [${lf.fields.join(', ')}]`;
      logs.push(w2);
      onProgress?.(w2, 99);
    }
  }

  onProgress?.('[SPIDER] Spider crawling complete.', 100);
  return { logs, discoveredUrls: Array.from(visited), discoveredParams: uniqueParams, discoveredForms: uniqueForms };
}

// ==================== INJECTION ====================
interface InjectionFinding {
  type: 'sqli' | 'xss';
  payloadName: string;
  url: string;
  param: string;
  evidence: string;
  severity: 'critical' | 'high' | 'medium';
}

async function testSingleInjection(url: string, param: string, payload: string, payloadName: string, type: 'sqli' | 'xss', logs: string[], findings: InjectionFinding[]) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(url, { signal: controller.signal, headers: { 'User-Agent': 'VulnRadar/1.0.0' }, redirect: 'follow' });
    clearTimeout(timeout);
    const body = await resp.text();

    if (type === 'xss') {
      if (body.includes(payload)) {
        findings.push({ type: 'xss', payloadName, url, param, evidence: `Payload "${payload}" reflected unencoded`, severity: 'high' });
        logs.push(`[XSS] ⚠️ REFLECTED: ${payloadName} in "${param}"`);
      }
      if ((payload === '{{7*7}}' && body.includes('49')) || (payload === '${alert(1)}' && body.includes('49'))) {
        findings.push({ type: 'xss', payloadName: `SSTI via ${payloadName}`, url, param, evidence: 'Template expression evaluated', severity: 'critical' });
        logs.push(`[SSTI] ‼️ TEMPLATE INJECTION: ${payloadName} in "${param}"`);
      }
    } else {
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(body)) {
          findings.push({ type: 'sqli', payloadName, url, param, evidence: `SQL error pattern "${pattern.source}" detected`, severity: 'critical' });
          logs.push(`[SQLi] ‼️ SQL ERROR: ${payloadName} triggered (param: ${param})`);
          break;
        }
      }
      if (/stack\s*trace/i.test(body) || /traceback/i.test(body) || /exception in/i.test(body)) {
        findings.push({ type: 'sqli', payloadName: `Error Disclosure via ${payloadName}`, url, param, evidence: 'Verbose error/stack trace detected', severity: 'high' });
        logs.push(`[SQLi] ⚠️ VERBOSE ERROR: Stack trace exposed (param: ${param})`);
      }
    }
  } catch { /* timeout */ }
}

async function testPostInjection(baseUrl: string, endpoint: string, fields: Record<string, string>, fieldSetName: string, payload: string, payloadName: string, type: 'sqli' | 'xss', logs: string[], findings: InjectionFinding[]) {
  const url = `${baseUrl}${endpoint}`;
  const fuzzedFields: Record<string, string> = {};
  let fuzzedParam = '';
  for (const [k, v] of Object.entries(fields)) {
    if (v === 'FUZZ') { fuzzedFields[k] = payload; fuzzedParam = k; }
    else fuzzedFields[k] = v;
  }
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(url, {
      method: 'POST', signal: controller.signal, redirect: 'follow',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': 'VulnRadar/1.0.0' },
      body: new URLSearchParams(fuzzedFields).toString(),
    });
    clearTimeout(timeout);
    const body = await resp.text();

    if (type === 'xss' && body.includes(payload)) {
      findings.push({ type: 'xss', payloadName: `POST ${payloadName}`, url: `${url} [POST:${fieldSetName}]`, param: fuzzedParam, evidence: `Payload reflected in POST response`, severity: 'high' });
      logs.push(`[XSS] ⚠️ POST REFLECTED: ${payloadName} in ${endpoint} field "${fuzzedParam}"`);
    } else if (type === 'sqli') {
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(body)) {
          findings.push({ type: 'sqli', payloadName: `POST ${payloadName}`, url: `${url} [POST:${fieldSetName}]`, param: fuzzedParam, evidence: `SQL error in POST response`, severity: 'critical' });
          logs.push(`[SQLi] ‼️ POST SQL ERROR: ${payloadName} in ${endpoint} field "${fuzzedParam}"`);
          break;
        }
      }
    }
  } catch { /* skip */ }
}

async function testInjection(domain: string, crawlData?: { discoveredParams: { path: string; param: string }[]; discoveredForms: { action: string; method: string; fields: string[] }[] }, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const findings: InjectionFinding[] = [];
  const baseUrl = `https://${domain.replace(/^https?:\/\//, '')}`;

  const crawledPaths: string[] = [];
  if (crawlData) {
    for (const p of crawlData.discoveredParams) crawledPaths.push(p.path);
  }
  const uniqueGetPaths = [...new Set([...INJECTION_TEST_PATHS, ...crawledPaths])];

  const crawledFormTests: { endpoint: string; fields: Record<string, string>; name: string }[] = [];
  if (crawlData) {
    for (const f of crawlData.discoveredForms) {
      const fields: Record<string, string> = {};
      for (const field of f.fields) fields[field] = 'FUZZ';
      try {
        const formUrl = new URL(f.action);
        crawledFormTests.push({ endpoint: formUrl.pathname, fields, name: `crawled:${formUrl.pathname}` });
      } catch {
        crawledFormTests.push({ endpoint: f.action, fields, name: `crawled:${f.action}` });
      }
    }
  }

  const m1 = '[INJECTION] Starting deep injection testing...';
  const m2 = `[INJECTION] ${uniqueGetPaths.length} GET paths (${INJECTION_TEST_PATHS.length} static + ${crawledPaths.length} crawled)`;
  const m3 = `[INJECTION] ${POST_TEST_ENDPOINTS.length + crawledFormTests.length} POST endpoints`;
  const m4 = `[INJECTION] ${SQLI_PAYLOADS.length} SQLi + ${XSS_PAYLOADS.length} XSS payloads`;
  logs.push(m1, m2, m3, m4, '');
  onProgress?.(m1, 2);
  onProgress?.(m2, 4);
  onProgress?.(m3, 6);
  onProgress?.(m4, 8);

  // Phase 1: GET fuzzing
  const mPhase1 = '[INJECTION] ── Phase 1: GET Parameter Fuzzing ──';
  logs.push(mPhase1);
  onProgress?.(mPhase1, 10);
  const getTasks: Promise<void>[] = [];
  for (const path of uniqueGetPaths) {
    const param = path.match(/[?&](\w+)=/)?.[1] || 'unknown';
    for (const sqli of SQLI_PAYLOADS.slice(0, 6)) {
      const testUrl = `${baseUrl}${path.replace('FUZZ', encodeURIComponent(sqli.payload))}`;
      getTasks.push(testSingleInjection(testUrl, param, sqli.payload, sqli.name, 'sqli', logs, findings));
    }
    for (const xss of XSS_PAYLOADS.slice(0, 5)) {
      const testUrl = `${baseUrl}${path.replace('FUZZ', encodeURIComponent(xss.payload))}`;
      getTasks.push(testSingleInjection(testUrl, param, xss.payload, xss.name, 'xss', logs, findings));
    }
  }
  const getBatches = chunkArray(getTasks, 12);
  for (let i = 0; i < getBatches.length; i++) {
    const pct = Math.round(10 + (i / getBatches.length) * 35);
    onProgress?.(`[INJECTION] Running GET fuzzing batch ${i+1}/${getBatches.length}...`, pct);
    await Promise.all(getBatches[i]);
  }

  // Phase 2: POST fuzzing
  logs.push('');
  const mPhase2 = '[INJECTION] ── Phase 2: POST Form Fuzzing ──';
  logs.push(mPhase2);
  onProgress?.(mPhase2, 45);
  const postTasks: Promise<void>[] = [];
  for (const endpoint of POST_TEST_ENDPOINTS) {
    for (const fieldSet of POST_FIELD_SETS) {
      for (const sqli of SQLI_PAYLOADS.slice(0, 3)) {
        postTasks.push(testPostInjection(baseUrl, endpoint, fieldSet.fields, fieldSet.name, sqli.payload, sqli.name, 'sqli', logs, findings));
      }
      for (const xss of XSS_PAYLOADS.slice(0, 3)) {
        postTasks.push(testPostInjection(baseUrl, endpoint, fieldSet.fields, fieldSet.name, xss.payload, xss.name, 'xss', logs, findings));
      }
    }
  }
  const postBatches = chunkArray(postTasks, 10);
  for (let i = 0; i < postBatches.length; i++) {
    const pct = Math.round(45 + (i / postBatches.length) * 25);
    onProgress?.(`[INJECTION] Running POST fuzzing batch ${i+1}/${postBatches.length}...`, pct);
    await Promise.all(postBatches[i]);
  }

  // Phase 2b: Crawled form fuzzing
  if (crawledFormTests.length > 0) {
    logs.push('');
    const mPhase2b = `[INJECTION] ── Phase 2b: Crawled Form Fuzzing (${crawledFormTests.length} forms) ──`;
    logs.push(mPhase2b);
    onProgress?.(mPhase2b, 70);
    const crawlPostTasks: Promise<void>[] = [];
    for (const cf of crawledFormTests) {
      for (const [fieldName] of Object.entries(cf.fields)) {
        const fuzzFields: Record<string, string> = {};
        for (const [k] of Object.entries(cf.fields)) fuzzFields[k] = k === fieldName ? 'FUZZ' : 'test';
        for (const sqli of SQLI_PAYLOADS.slice(0, 3)) {
          crawlPostTasks.push(testPostInjection(baseUrl, cf.endpoint, fuzzFields, cf.name, sqli.payload, sqli.name, 'sqli', logs, findings));
        }
        for (const xss of XSS_PAYLOADS.slice(0, 3)) {
          crawlPostTasks.push(testPostInjection(baseUrl, cf.endpoint, fuzzFields, cf.name, xss.payload, xss.name, 'xss', logs, findings));
        }
      }
    }
    const crawlPostBatches = chunkArray(crawlPostTasks, 10);
    for (let i = 0; i < crawlPostBatches.length; i++) {
      const pct = Math.round(70 + (i / crawlPostBatches.length) * 15);
      onProgress?.(`[INJECTION] Running crawled form fuzzing batch ${i+1}/${crawlPostBatches.length}...`, pct);
      await Promise.all(crawlPostBatches[i]);
    }
  }

  // Phase 3: Header injection
  logs.push('');
  const mPhase3 = '[INJECTION] ── Phase 3: Header Injection ──';
  logs.push(mPhase3);
  onProgress?.(mPhase3, 85);
  const headerPayloads = [
    { header: 'X-Forwarded-For', value: "127.0.0.1' OR '1'='1", name: 'XFF SQLi' },
    { header: 'Referer', value: '<script>alert(1)</script>', name: 'Referer XSS' },
    { header: 'User-Agent', value: "' OR '1'='1", name: 'UA SQLi' },
    { header: 'X-Forwarded-Host', value: 'evil.com', name: 'Host Header Injection' },
    { header: 'X-Custom-IP-Authorization', value: '127.0.0.1', name: 'IP Auth Bypass' },
    { header: 'X-Original-URL', value: '/admin', name: 'URL Override' },
  ];
  await Promise.all(headerPayloads.map(async (hp, idx) => {
    try {
      const pct = Math.round(85 + (idx / headerPayloads.length) * 10);
      onProgress?.(`[INJECTION] Testing injected header: ${hp.header}...`, pct);
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      const resp = await safeFetch(baseUrl, { signal: controller.signal, headers: { [hp.header]: hp.value, 'User-Agent': 'VulnRadar/1.0.0' }, redirect: 'follow' });
      clearTimeout(timeout);
      const body = await resp.text();
      if (body.includes(hp.value)) {
        findings.push({ type: 'xss', payloadName: `Header: ${hp.name}`, url: baseUrl, param: hp.header, evidence: `${hp.header} value reflected`, severity: 'high' });
        const w = `[INJECTION] ⚠️ HEADER REFLECTED: ${hp.name} via ${hp.header}`;
        logs.push(w);
        onProgress?.(w, pct);
      }
      for (const pattern of SQL_ERROR_PATTERNS) {
        if (pattern.test(body)) {
          findings.push({ type: 'sqli', payloadName: `Header: ${hp.name}`, url: baseUrl, param: hp.header, evidence: `SQL error via ${hp.header}`, severity: 'critical' });
          const w = `[SQLi] ‼️ HEADER SQLi: ${hp.name} via ${hp.header}`;
          logs.push(w);
          onProgress?.(w, pct);
          break;
        }
      }
    } catch { /* skip */ }
  }));

  // Deduplicate
  const seen = new Set<string>();
  const uniqueFindings = findings.filter(f => {
    const key = `${f.type}:${f.param}:${f.payloadName}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const sqliCount = uniqueFindings.filter(f => f.type === 'sqli').length;
  const xssCount = uniqueFindings.filter(f => f.type === 'xss').length;
  logs.push('');
  logs.push('[INJECTION] ═══ Results ═══');
  logs.push(`[INJECTION] Tested ${uniqueGetPaths.length} GET + ${POST_TEST_ENDPOINTS.length + crawledFormTests.length} POST + ${headerPayloads.length} headers`);
  if (sqliCount > 0) logs.push(`[SQLi] ‼️ ${sqliCount} potential SQL injection point(s)!`);
  else logs.push('[SQLi] ✓ No SQL injection indicators detected');
  if (xssCount > 0) logs.push(`[XSS] ⚠️ ${xssCount} reflected XSS point(s)!`);
  else logs.push('[XSS] ✓ No reflected XSS detected');

  onProgress?.(`[INJECTION] Complete. Findings: ${sqliCount} SQLi, ${xssCount} XSS`, 100);
  return { logs, findings: uniqueFindings };
}

// ==================== CORS ====================
interface CorsFinding {
  type: 'wildcard' | 'reflection' | 'null_origin' | 'credentials_wildcard' | 'subdomain_bypass' | 'insecure_scheme';
  description: string;
  severity: 'critical' | 'high' | 'medium';
  evidence: string;
}

async function testCORS(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const findings: CorsFinding[] = [];
  const baseUrl = `https://${domain.replace(/^https?:\/\//, '')}`;
  const m = '[CORS] Starting CORS misconfiguration analysis...';
  logs.push(m);
  onProgress?.(m, 10);

  // Test 1: evil.com origin
  try {
    onProgress?.('[CORS] Testing arbitrary origin reflection (https://evil.com)...', 25);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(baseUrl, { signal: controller.signal, headers: { 'User-Agent': 'VulnRadar/1.0.0', 'Origin': 'https://evil.com' } });
    clearTimeout(timeout);
    const acao = resp.headers.get('access-control-allow-origin');
    const acac = resp.headers.get('access-control-allow-credentials');
    if (acao === '*' && acac === 'true') {
      findings.push({ type: 'credentials_wildcard', description: 'CORS allows any origin (*) WITH credentials', severity: 'critical', evidence: 'ACAO: *, ACAC: true' });
      const w = '[CORS] ‼️ CRITICAL: Wildcard origin with credentials!';
      logs.push(w);
      onProgress?.(w, 35);
    } else if (acao === '*') {
      findings.push({ type: 'wildcard', description: 'CORS allows any origin (*)', severity: 'medium', evidence: 'Access-Control-Allow-Origin: *' });
      const w = '[CORS] ⚠️ Wildcard origin (*) detected';
      logs.push(w);
      onProgress?.(w, 35);
    }
    if (acao === 'https://evil.com') {
      findings.push({ type: 'reflection', description: 'CORS reflects arbitrary Origin header', severity: 'critical', evidence: 'Sent Origin: https://evil.com, received same' });
      const w = '[CORS] ‼️ CRITICAL: Origin reflection detected!';
      logs.push(w);
      onProgress?.(w, 35);
    }
  } catch (e) { logs.push(`[CORS] Default test failed: ${e instanceof Error ? e.message : 'unknown'}`); }

  // Test 2: null origin
  try {
    onProgress?.('[CORS] Testing null origin acceptance...', 45);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(baseUrl, { signal: controller.signal, headers: { 'User-Agent': 'VulnRadar/1.0.0', 'Origin': 'null' } });
    clearTimeout(timeout);
    if (resp.headers.get('access-control-allow-origin') === 'null') {
      findings.push({ type: 'null_origin', description: 'CORS accepts "null" origin', severity: 'high', evidence: 'Sent Origin: null, received ACAO: null' });
      const w = '[CORS] ⚠️ Null origin accepted!';
      logs.push(w);
      onProgress?.(w, 55);
    }
  } catch { /* skip */ }

  // Test 3: subdomain bypass
  try {
    const attackerOrigin = `https://attacker.${domain.replace(/^https?:\/\//, '')}`;
    onProgress?.(`[CORS] Testing subdomain wildcard trust (${attackerOrigin})...`, 65);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(baseUrl, { signal: controller.signal, headers: { 'User-Agent': 'VulnRadar/1.0.0', 'Origin': attackerOrigin } });
    clearTimeout(timeout);
    if (resp.headers.get('access-control-allow-origin') === attackerOrigin) {
      findings.push({ type: 'subdomain_bypass', description: 'CORS trusts arbitrary subdomains', severity: 'high', evidence: `Origin: ${attackerOrigin} accepted` });
      const w = `[CORS] ⚠️ Subdomain wildcard trust: ${attackerOrigin} accepted`;
      logs.push(w);
      onProgress?.(w, 75);
    }
  } catch { /* skip */ }

  // Test 4: HTTP scheme bypass
  try {
    const httpOrigin = `http://${domain.replace(/^https?:\/\//, '')}`;
    onProgress?.(`[CORS] Testing insecure HTTP scheme trust (${httpOrigin})...`, 80);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(baseUrl, { signal: controller.signal, headers: { 'User-Agent': 'VulnRadar/1.0.0', 'Origin': httpOrigin } });
    clearTimeout(timeout);
    if (resp.headers.get('access-control-allow-origin') === httpOrigin) {
      findings.push({ type: 'insecure_scheme', description: 'CORS trusts HTTP origin on HTTPS site', severity: 'medium', evidence: `HTTPS site accepts HTTP origin: ${httpOrigin}` });
      const w = '[CORS] ⚠️ HTTP origin accepted on HTTPS site';
      logs.push(w);
      onProgress?.(w, 85);
    }
  } catch { /* skip */ }

  // Test 5: Preflight
  try {
    onProgress?.('[CORS] Testing preflight OPTIONS handling...', 90);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    const resp = await safeFetch(baseUrl, {
      method: 'OPTIONS', signal: controller.signal,
      headers: { 'User-Agent': 'VulnRadar/1.0.0', 'Origin': 'https://evil.com', 'Access-Control-Request-Method': 'PUT', 'Access-Control-Request-Headers': 'X-Custom-Header' },
    });
    clearTimeout(timeout);
    const allowMethods = resp.headers.get('access-control-allow-methods') || '';
    const allowHeaders = resp.headers.get('access-control-allow-headers') || '';
    if (allowMethods.includes('*') || allowHeaders.includes('*')) {
      const w = '[CORS] ⚠️ Preflight allows wildcard methods/headers';
      logs.push(w);
      onProgress?.(w, 95);
    }
  } catch { /* skip */ }

  logs.push('');
  logs.push('[CORS] ═══ Results ═══');
  if (findings.length > 0) {
    logs.push(`[CORS] ‼️ ${findings.length} CORS misconfiguration(s) found!`);
    for (const f of findings) logs.push(`[CORS]   ${f.severity === 'critical' ? '‼️' : '⚠️'} ${f.type}: ${f.description}`);
  } else {
    logs.push('[CORS] ✓ No CORS misconfigurations detected');
  }

  onProgress?.('[CORS] CORS configuration analysis complete.', 100);
  return { logs, findings };
}

// ==================== OPEN REDIRECT ====================
interface OpenRedirectFinding {
  url: string;
  param: string;
  redirectedTo: string;
  severity: 'high' | 'medium';
}

async function testOpenRedirects(domain: string, onProgress?: ProgressCallback) {
  const logs: string[] = [];
  const findings: OpenRedirectFinding[] = [];
  const baseUrl = `https://${domain.replace(/^https?:\/\//, '')}`;
  const m1 = '[REDIRECT-VULN] Starting open redirect detection...';
  const m2 = `[REDIRECT-VULN] Testing ${REDIRECT_ENDPOINTS.length} endpoints × ${REDIRECT_PARAMS.length} params × ${REDIRECT_TEST_PAYLOADS.length} payloads`;
  logs.push(m1, m2);
  onProgress?.(m1, 5);
  onProgress?.(m2, 10);

  const tasks: Promise<void>[] = [];
  for (const endpoint of REDIRECT_ENDPOINTS) {
    for (const param of REDIRECT_PARAMS) {
      for (const pl of REDIRECT_TEST_PAYLOADS.slice(0, 5)) {
        tasks.push((async () => {
          const testUrl = `${baseUrl}${endpoint}?${param}=${encodeURIComponent(pl.payload)}`;
          try {
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), 5000);
            const resp = await safeFetch(testUrl, { signal: controller.signal, redirect: 'manual', headers: { 'User-Agent': 'VulnRadar/1.0.0' } });
            clearTimeout(timeout);
            if (resp.status >= 300 && resp.status < 400) {
              const location = resp.headers.get('location') || '';
              if (location.includes('evil.com') || location.startsWith('javascript:') || location.startsWith('data:')) {
                findings.push({ url: testUrl, param, redirectedTo: location, severity: 'high' });
                const w = `[REDIRECT-VULN] ‼️ OPEN REDIRECT: ${endpoint}?${param} → ${location} (${pl.name})`;
                logs.push(w);
                onProgress?.(w, 50);
              }
            }
            if (resp.status === 200) {
              const body = await resp.text();
              const metaRefresh = body.match(/meta\s+http-equiv=["']refresh["'][^>]*url=([^"'\s>]+)/i)?.[1] || '';
              if (metaRefresh.includes('evil.com')) {
                findings.push({ url: testUrl, param, redirectedTo: `meta-refresh: ${metaRefresh}`, severity: 'medium' });
                const w = `[REDIRECT-VULN] ⚠️ META REDIRECT: ${endpoint}?${param} → ${metaRefresh}`;
                logs.push(w);
                onProgress?.(w, 60);
              }
              if (body.includes('window.location') && body.includes(pl.payload)) {
                findings.push({ url: testUrl, param, redirectedTo: 'JS redirect with payload', severity: 'high' });
                const w = `[REDIRECT-VULN] ‼️ JS REDIRECT: ${endpoint}?${param}`;
                logs.push(w);
                onProgress?.(w, 70);
              }
            }
          } catch { /* skip */ }
        })());
      }
    }
  }

  const batches = chunkArray(tasks, 10);
  for (let i = 0; i < batches.length; i++) {
    const pct = Math.round(10 + (i / batches.length) * 85);
    onProgress?.(`[REDIRECT-VULN] Running redirect checks batch ${i+1}/${batches.length}...`, pct);
    await Promise.all(batches[i]);
  }

  const seen = new Set<string>();
  const uniqueFindings = findings.filter(f => {
    const key = `${f.param}:${f.redirectedTo}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  logs.push('');
  logs.push('[REDIRECT-VULN] ═══ Results ═══');
  if (uniqueFindings.length > 0) logs.push(`[REDIRECT-VULN] ‼️ ${uniqueFindings.length} open redirect(s)!`);
  else logs.push('[REDIRECT-VULN] ✓ No open redirects detected');

  onProgress?.('[REDIRECT-VULN] Open redirect vulnerability checks complete.', 100);
  return { logs, findings: uniqueFindings };
}

// ==================== VULN GENERATION ====================
function generateVulnerabilitiesFromFindings(
  headerResult: Awaited<ReturnType<typeof scanHeaders>>,
  dnsResult: Awaited<ReturnType<typeof scanDNS>>,
  sslResult: Awaited<ReturnType<typeof scanSSL>>,
  sensitiveFiles: Awaited<ReturnType<typeof scanSensitiveFiles>>,
  redirectResult: Awaited<ReturnType<typeof checkRedirectChain>>,
  portResult: Awaited<ReturnType<typeof scanPorts>>,
  injectionResult: Awaited<ReturnType<typeof testInjection>>,
  corsResult: Awaited<ReturnType<typeof testCORS>>,
  openRedirectResult: Awaited<ReturnType<typeof testOpenRedirects>>,
  domain: string
) {
  const vulns: any[] = [];
  let vulnId = 1;

  const missingHeaders = headerResult.headers.filter(h => h.status === 'missing');
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
      description: 'CSP header not set.', impact: 'No protection against inline script injection.',
      remediation: "Implement strict CSP", cvss: 6.1, cwe: 'CWE-79', evidence: 'CSP header not present' });
  }

  if (missingHeaders.find(h => h.name.toLowerCase().includes('x-frame'))) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'Clickjacking — Missing X-Frame-Options', severity: 'medium', category: 'UI Redress',
      description: 'X-Frame-Options not set.', impact: 'Iframe overlay attacks possible.',
      remediation: "Set X-Frame-Options: DENY or SAMEORIGIN", cvss: 4.3, cwe: 'CWE-1021', evidence: 'X-Frame-Options not present' });
  }

  const serverWarning = headerResult.headers.find(h => h.name === 'Server' && h.status === 'warning');
  if (serverWarning) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'Server Version Information Disclosure', severity: 'low', category: 'Information Disclosure',
      description: `Server header reveals: "${serverWarning.value}".`, impact: 'Attackers can look up known CVEs.',
      remediation: 'Remove or obfuscate the Server header.', cvss: 3.7, cwe: 'CWE-200', evidence: `Server: ${serverWarning.value}` });
  }

  const hasSPF = dnsResult.records.some(r => r.type === 'TXT' && r.value.includes('v=spf1'));
  const hasDMARC = dnsResult.records.some(r => r.type === 'DMARC');
  if (!hasSPF || !hasDMARC) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `Email Spoofing Risk — Missing ${!hasSPF && !hasDMARC ? 'SPF & DMARC' : !hasSPF ? 'SPF' : 'DMARC'}`,
      severity: 'medium', category: 'Email Security',
      description: `${!hasSPF ? 'SPF missing. ' : ''}${!hasDMARC ? 'DMARC missing. ' : ''}`,
      impact: 'Domain can be used for phishing.', remediation: `Add ${!hasSPF ? 'SPF' : ''} ${!hasDMARC ? 'DMARC' : ''} records.`,
      cvss: 5.0, cwe: 'CWE-290', evidence: `${!hasSPF ? 'No SPF. ' : ''}${!hasDMARC ? 'No DMARC.' : ''}` });
  }

  if (!dnsResult.records.some(r => r.type === 'DNSSEC' && r.value.includes('Enabled'))) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'DNSSEC Not Enabled', severity: 'low', category: 'DNS Security',
      description: 'DNSSEC not enabled.', impact: 'Vulnerable to DNS cache poisoning.',
      remediation: 'Enable DNSSEC.', cvss: 3.7, cwe: 'CWE-350', evidence: 'No DNSKEY record' });
  }

  if (!dnsResult.records.some(r => r.type === 'CAA')) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'No CAA Records', severity: 'low', category: 'Certificate Security',
      description: 'No CAA DNS records.', impact: 'Any CA can issue certificates.',
      remediation: 'Add CAA records.', cvss: 3.0, cwe: 'CWE-295', evidence: 'No CAA records' });
  }

  if (sslResult.sslInfo.grade === 'F') {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'SSL/TLS Critical Failure', severity: 'critical', category: 'Encryption',
      description: `SSL grade F. Issues: ${sslResult.sslInfo.issues.join(', ')}`,
      impact: 'Data can be intercepted.', remediation: 'Fix SSL certificate.',
      cvss: 9.1, cwe: 'CWE-326', evidence: `SSL Grade: F` });
  }

  for (const issue of sslResult.sslInfo.issues) {
    if (issue.toLowerCase().includes('expired')) {
      vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'SSL Certificate Expired', severity: 'critical', category: 'Encryption',
        description: 'SSL certificate expired.', impact: 'MITM attacks possible.',
        remediation: 'Renew SSL certificate.', cvss: 8.6, cwe: 'CWE-295', evidence: issue });
    }
  }

  for (const file of sensitiveFiles.exposed) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `Exposed: ${file.name}`, severity: file.severity as any, category: 'Information Disclosure',
      description: `${file.name} accessible at ${file.path}.`,
      impact: file.severity === 'critical' ? 'Full compromise via leaked secrets.' : 'Information disclosure.',
      remediation: `Block access to ${file.path}.`,
      cvss: file.severity === 'critical' ? 9.1 : file.severity === 'high' ? 7.5 : 5.3, cwe: 'CWE-200', evidence: `HTTP 200 at ${file.path}` });
  }

  const httpNoRedirect = redirectResult.chain.find(c => c.url.startsWith('http://') && c.status === 200);
  if (httpNoRedirect) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: 'No HTTP to HTTPS Redirect', severity: 'medium', category: 'Transport Security',
      description: 'HTTP responds with 200 instead of redirecting.', impact: 'Data sent unencrypted.',
      remediation: 'Configure 301 redirect.', cvss: 5.3, cwe: 'CWE-319', evidence: `HTTP returned 200` });
  }

  for (const finding of injectionResult.findings) {
    if (finding.type === 'sqli') {
      vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `SQL Injection — ${finding.payloadName} (${finding.param})`, severity: 'critical', category: 'Injection',
        description: `SQLi detected via ${finding.payloadName} on "${finding.param}". ${finding.evidence}`,
        impact: 'Full database compromise.', remediation: 'Use parameterized queries.',
        cvss: 9.8, cwe: 'CWE-89', evidence: finding.evidence });
    } else {
      vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `Reflected XSS — ${finding.payloadName} (${finding.param})`, severity: 'high', category: 'Cross-Site Scripting',
        description: `XSS detected: ${finding.payloadName} reflected in "${finding.param}".`,
        impact: 'Session theft, page defacement.', remediation: 'Encode output. Implement CSP.',
        cvss: 6.1, cwe: 'CWE-79', evidence: finding.evidence });
    }
  }

  const riskyPorts = portResult.openPorts.filter(p => [5432, 3306, 6379, 27017, 9200, 8888, 10000, 3000, 5000, 8000, 9090].includes(p.port));
  if (riskyPorts.length > 0) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `${riskyPorts.length} Risky Port(s) Exposed`, severity: riskyPorts.some(p => [5432, 3306, 6379, 27017, 9200].includes(p.port)) ? 'high' : 'medium',
      category: 'Network Security', description: `Risky ports: ${riskyPorts.map(p => `${p.port} (${p.service})`).join(', ')}.`,
      impact: 'Internal services exposed.', remediation: 'Restrict via firewall.',
      cvss: riskyPorts.some(p => [5432, 3306, 6379, 27017, 9200].includes(p.port)) ? 7.5 : 5.3, cwe: 'CWE-200',
      evidence: `Open: ${riskyPorts.map(p => p.port).join(', ')}` });
  }

  for (const cf of corsResult.findings) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `CORS — ${cf.type.replace(/_/g, ' ')}`, severity: cf.severity, category: 'CORS',
      description: cf.description, impact: cf.severity === 'critical' ? 'Any site can read responses.' : 'Cross-origin data leakage.',
      remediation: 'Restrict CORS to trusted origins.', cvss: cf.severity === 'critical' ? 9.1 : cf.severity === 'high' ? 7.5 : 5.3,
      cwe: 'CWE-942', evidence: cf.evidence });
  }

  for (const orf of openRedirectResult.findings) {
    vulns.push({ id: `VULN-${String(vulnId++).padStart(3, '0')}`, title: `Open Redirect — "${orf.param}"`, severity: orf.severity, category: 'Open Redirect',
      description: `Parameter "${orf.param}" allows redirecting to external URLs.`,
      impact: 'Phishing via trusted domain.', remediation: 'Validate redirect URLs against whitelist.',
      cvss: orf.severity === 'high' ? 6.1 : 4.3, cwe: 'CWE-601', evidence: `${orf.url} → ${orf.redirectedTo}` });
  }

  return vulns;
}

// ==================== MAIN HANDLER ====================
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  let channel: any = null;

  try {
    const body = await req.json();
    const { target, phase = 'all', crawlData, scanId }: ScanRequest = body;

    if (!target) {
      return new Response(JSON.stringify({ success: false, error: 'Target is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    const domain = target.replace(/^https?:\/\//, '').replace(/\/.*$/, '').trim();
    console.log(`Scanning target: ${domain}, phase: ${phase}, scanId: ${scanId}`);

    if (scanId) {
      channel = supabase.channel(`scan:${scanId}`, {
        config: {
          broadcast: { self: true },
        },
      });
      
      // Wait for backend channel subscription to be ready to avoid dropping initial messages
      await new Promise<void>((resolve) => {
        let resolved = false;
        const timer = setTimeout(() => {
          if (!resolved) {
            resolved = true;
            resolve();
          }
        }, 3000);

        channel.subscribe((status: string) => {
          console.log(`Realtime channel status for scan:${scanId}: ${status}`);
          if (status === 'SUBSCRIBED' && !resolved) {
            clearTimeout(timer);
            resolved = true;
            resolve();
          }
        });
      });
    }

    const broadcastProgress = (message: string, progress: number, currentPhase: string) => {
      if (channel) {
        channel.send({
          type: 'broadcast',
          event: 'progress',
          payload: {
            message,
            progress: Math.min(100, Math.max(0, progress)),
            phase: currentPhase,
            timestamp: new Date().toISOString(),
          },
        }).catch((err: any) => console.error('Realtime broadcast error:', err));
      }
    };

    const allLogs: string[] = [];
    const logAndBroadcast = (msg: string, progress: number, currentPhase: string) => {
      allLogs.push(msg);
      broadcastProgress(msg, progress, currentPhase);
    };

    logAndBroadcast(`[INIT] Target: ${domain}`, 0, phase);
    logAndBroadcast(`[INIT] VulnRadar Engine v1.0.0 — Phase: ${phase}`, 2, phase);
    logAndBroadcast(`[INIT] Started at ${new Date().toISOString()}`, 4, phase);
    allLogs.push('');

    if (phase === 'recon') {
      // PHASE GROUP 1: DNS + Subdomains + Headers + Redirect
      logAndBroadcast('[PHASE] DNS Reconnaissance...', 5, 'recon');
      const dnsResult = await scanDNS(domain, (msg, pct) => {
        const overallPct = Math.round((pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'recon');
      });
      allLogs.push(...dnsResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] Subdomain Enumeration...', 25, 'recon');
      const subdomainResult = await enumerateSubdomains(domain, (msg, pct) => {
        const overallPct = Math.round(25 + (pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'recon');
      });
      allLogs.push(...subdomainResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] HTTP Security Headers...', 50, 'recon');
      const headerResult = await scanHeaders(domain, (msg, pct) => {
        const overallPct = Math.round(50 + (pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'recon');
      });
      allLogs.push(...headerResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] Redirect Chain Analysis...', 75, 'recon');
      const redirectResult = await checkRedirectChain(domain, (msg, pct) => {
        const overallPct = Math.round(75 + (pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'recon');
      });
      allLogs.push(...redirectResult.logs);

      logAndBroadcast('[PHASE] Reconnaissance phase complete.', 100, 'recon');

      return new Response(JSON.stringify({
        success: true,
        phase: 'recon',
        data: {
          logs: allLogs,
          dnsRecords: dnsResult.records,
          subdomains: subdomainResult.subdomains,
          headers: headerResult.headers,
          technologies: headerResult.technologies,
          redirectChain: redirectResult.chain,
        },
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

    } else if (phase === 'active') {
      // PHASE GROUP 2: Sensitive Files + SSL + Spider + Ports
      logAndBroadcast('[PHASE] Sensitive File Check...', 5, 'active');
      const sensitiveResult = await scanSensitiveFiles(domain, (msg, pct) => {
        const overallPct = Math.round((pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'active');
      });
      allLogs.push(...sensitiveResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] SSL/TLS Analysis...', 25, 'active');
      const sslResult = await scanSSL(domain, (msg, pct) => {
        const overallPct = Math.round(25 + (pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'active');
      });
      allLogs.push(...sslResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] URL Spider/Crawler...', 50, 'active');
      const crawlResult = await spiderTarget(domain, (msg, pct) => {
        const overallPct = Math.round(50 + (pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'active');
      });
      allLogs.push(...crawlResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] Port Probing...', 75, 'active');
      const portResult = await scanPorts(domain, (msg, pct) => {
        const overallPct = Math.round(75 + (pct * 25) / 100);
        logAndBroadcast(msg, overallPct, 'active');
      });
      allLogs.push(...portResult.logs);

      logAndBroadcast('[PHASE] Active scanning phase complete.', 100, 'active');

      return new Response(JSON.stringify({
        success: true,
        phase: 'active',
        data: {
          logs: allLogs,
          sensitiveFiles: sensitiveResult.exposed,
          sslInfo: sslResult.sslInfo,
          openPorts: portResult.openPorts,
          crawlStats: {
            pagesDiscovered: crawlResult.discoveredUrls.length,
            paramsFound: crawlResult.discoveredParams.length,
            formsFound: crawlResult.discoveredForms.length,
          },
          crawlData: {
            discoveredParams: crawlResult.discoveredParams,
            discoveredForms: crawlResult.discoveredForms,
          },
        },
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

    } else if (phase === 'attack') {
      // PHASE GROUP 3: Injection + CORS + Open Redirect
      logAndBroadcast('[PHASE] Injection Testing (SQLi/XSS)...', 5, 'attack');
      const injectionResult = await testInjection(domain, crawlData, (msg, pct) => {
        const overallPct = Math.round((pct * 40) / 100);
        logAndBroadcast(msg, overallPct, 'attack');
      });
      allLogs.push(...injectionResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] CORS Misconfiguration Testing...', 40, 'attack');
      const corsResult = await testCORS(domain, (msg, pct) => {
        const overallPct = Math.round(40 + (pct * 30) / 100);
        logAndBroadcast(msg, overallPct, 'attack');
      });
      allLogs.push(...corsResult.logs);
      allLogs.push('');

      logAndBroadcast('[PHASE] Open Redirect Detection...', 70, 'attack');
      const openRedirectResult = await testOpenRedirects(domain, (msg, pct) => {
        const overallPct = Math.round(70 + (pct * 30) / 100);
        logAndBroadcast(msg, overallPct, 'attack');
      });
      allLogs.push(...openRedirectResult.logs);

      logAndBroadcast('[PHASE] Attack/Vulnerability scanning phase complete.', 100, 'attack');

      return new Response(JSON.stringify({
        success: true,
        phase: 'attack',
        data: {
          logs: allLogs,
          injectionFindings: injectionResult.findings,
          corsFindings: corsResult.findings,
          openRedirectFindings: openRedirectResult.findings,
        },
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });

    } else {
      // LEGACY 'all' mode
      logAndBroadcast('[PHASE] Starting full vulnerability scan...', 2, 'all');

      const dnsResult = await scanDNS(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round((pct * 9) / 100), 'all');
      });
      allLogs.push(...dnsResult.logs, '');

      const subdomainResult = await enumerateSubdomains(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(9 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...subdomainResult.logs, '');

      const headerResult = await scanHeaders(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(18 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...headerResult.logs, '');

      const redirectResult = await checkRedirectChain(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(27 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...redirectResult.logs, '');

      const sensitiveResult = await scanSensitiveFiles(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(36 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...sensitiveResult.logs, '');

      const sslResult = await scanSSL(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(45 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...sslResult.logs, '');

      const crawlResult = await spiderTarget(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(54 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...crawlResult.logs, '');

      const portResult = await scanPorts(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(63 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...portResult.logs, '');

      const injectionResult = await testInjection(domain, crawlResult, (msg, pct) => {
        logAndBroadcast(msg, Math.round(72 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...injectionResult.logs, '');

      const corsResult = await testCORS(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(81 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...corsResult.logs, '');

      const openRedirectResult = await testOpenRedirects(domain, (msg, pct) => {
        logAndBroadcast(msg, Math.round(90 + (pct * 9) / 100), 'all');
      });
      allLogs.push(...openRedirectResult.logs, '');

      logAndBroadcast('Generating final vulnerability report...', 99, 'all');
      const vulns = generateVulnerabilitiesFromFindings(headerResult, dnsResult, sslResult, sensitiveResult, redirectResult, portResult, injectionResult, corsResult, openRedirectResult, domain);
      for (const v of vulns) allLogs.push(`[VULN] ${v.severity === 'critical' ? '‼️' : v.severity === 'high' ? '⚠️' : 'ℹ️'} ${v.severity.toUpperCase()}: ${v.title}`);

      logAndBroadcast('Scan successfully completed!', 100, 'all');

      return new Response(JSON.stringify({
        success: true,
        data: {
          target: domain, startTime: new Date().toISOString(), endTime: new Date().toISOString(),
          vulnerabilities: vulns, openPorts: portResult.openPorts, headers: headerResult.headers,
          sslInfo: sslResult.sslInfo, technologies: headerResult.technologies, dnsRecords: dnsResult.records,
          subdomains: subdomainResult.subdomains, sensitiveFiles: sensitiveResult.exposed,
          redirectChain: redirectResult.chain, injectionFindings: injectionResult.findings,
          corsFindings: corsResult.findings, openRedirectFindings: openRedirectResult.findings,
          crawlStats: { pagesDiscovered: crawlResult.discoveredUrls.length, paramsFound: crawlResult.discoveredParams.length, formsFound: crawlResult.discoveredForms.length },
          logs: allLogs,
        },
      }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

  } catch (error) {
    console.error('Scan error:', error);
    return new Response(JSON.stringify({ success: false, error: error instanceof Error ? error.message : 'Unknown error' }),
      { status: 500, headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
  } finally {
    if (channel) {
      try {
        supabase.removeChannel(channel);
      } catch (err) {
        console.error('Error removing channel:', err);
      }
    }
  }
});
