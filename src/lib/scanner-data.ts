export interface ScanPhase {
  id: string;
  name: string;
  description: string;
  duration: number;
  logs: string[];
}

export interface Vulnerability {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  category: string;
  description: string;
  impact: string;
  remediation: string;
  cvss: number;
  cwe: string;
  evidence: string;
}

export interface InjectionFinding {
  type: 'sqli' | 'xss';
  payloadName: string;
  url: string;
  param: string;
  evidence: string;
  severity: 'critical' | 'high' | 'medium';
}

export interface CorsFinding {
  type: 'wildcard' | 'reflection' | 'null_origin' | 'credentials_wildcard' | 'subdomain_bypass' | 'insecure_scheme';
  description: string;
  severity: 'critical' | 'high' | 'medium';
  evidence: string;
}

export interface OpenRedirectFinding {
  url: string;
  param: string;
  redirectedTo: string;
  severity: 'high' | 'medium';
}

export interface ScanResult {
  target: string;
  startTime: Date;
  endTime?: Date;
  vulnerabilities: Vulnerability[];
  openPorts: { port: number; service: string; version: string; state: string }[];
  headers: { name: string; value: string; status: 'secure' | 'warning' | 'missing' }[];
  sslInfo: { grade: string; expiry: string; protocol: string; cipher: string; issues: string[] };
  technologies: { name: string; version: string; category: string }[];
  dnsRecords: { type: string; value: string }[];
  subdomains?: string[];
  sensitiveFiles?: { path: string; name: string; status: number; severity: string }[];
  redirectChain?: { url: string; status: number }[];
  injectionFindings?: InjectionFinding[];
  corsFindings?: CorsFinding[];
  openRedirectFindings?: OpenRedirectFinding[];
  crawlStats?: { pagesDiscovered: number; paramsFound: number; formsFound: number };
}

export const SCAN_PHASES: ScanPhase[] = [
  {
    id: 'recon',
    name: 'DNS Reconnaissance',
    description: 'Querying DNS records, SPF, DMARC, DNSSEC...',
    duration: 3000,
    logs: [],
  },
  {
    id: 'subdomains',
    name: 'Subdomain Enumeration',
    description: 'Discovering subdomains via DNS...',
    duration: 2000,
    logs: [],
  },
  {
    id: 'headers',
    name: 'HTTP Header Analysis',
    description: 'Analyzing security headers and technologies...',
    duration: 2500,
    logs: [],
  },
  {
    id: 'redirect',
    name: 'Redirect Chain Analysis',
    description: 'Checking HTTP→HTTPS redirect and chain...',
    duration: 1500,
    logs: [],
  },
  {
    id: 'files',
    name: 'Sensitive File Check',
    description: 'Probing for exposed config and backup files...',
    duration: 3000,
    logs: [],
  },
  {
    id: 'ssl',
    name: 'SSL/TLS Analysis',
    description: 'Testing encryption configuration...',
    duration: 3000,
    logs: [],
  },
  {
    id: 'vulnscan',
    name: 'Vulnerability Analysis',
    description: 'Correlating findings with vulnerability database...',
    duration: 2000,
    logs: [],
  },
  {
    id: 'spider',
    name: 'URL Spider / Crawler',
    description: 'Crawling target to discover pages, forms, and parameters...',
    duration: 4000,
    logs: [],
  },
  {
    id: 'ports',
    name: 'Port Probing',
    description: 'Probing common web service ports...',
    duration: 3000,
    logs: [],
  },
  {
    id: 'injection',
    name: 'SQLi / XSS Testing',
    description: 'Testing for injection vulnerabilities...',
    duration: 4000,
    logs: [],
  },
  {
    id: 'cors',
    name: 'CORS Misconfiguration',
    description: 'Testing CORS policy for misconfigurations...',
    duration: 2000,
    logs: [],
  },
  {
    id: 'openredirect',
    name: 'Open Redirect Detection',
    description: 'Testing for open redirect vulnerabilities...',
    duration: 3000,
    logs: [],
  },
  {
    id: 'report',
    name: 'Report Generation',
    description: 'Compiling findings...',
    duration: 1500,
    logs: [],
  },
];
