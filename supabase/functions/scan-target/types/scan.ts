// Shared TypeScript interfaces between Supabase Edge Function (Deno) and React frontend

export interface CrawlData {
  discoveredParams: { path: string; param: string }[];
  discoveredForms: {
    path: string;
    action: string;
    method: string;
    inputs: { name: string; type: string }[];
  }[];
}

export interface ScanRequest {
  target: string;
  phase: 'recon' | 'active' | 'attack' | 'all';
  scanId?: string;
  crawlData?: CrawlData;
}

export interface DNSRecord {
  type: string;
  value: string;
}

export interface SecurityHeader {
  name: string;
  value: string;
  status: 'secure' | 'warning' | 'missing';
}

export interface Technology {
  name: string;
  version: string;
  category: string;
}

export interface RedirectChainEntry {
  url: string;
  status: number;
}

export interface ExposedFile {
  path: string;
  name: string;
  status: number;
  severity: string;
}

export interface OpenPort {
  port: number;
  service: string;
  version: string;
  state: string;
}

export interface SSLInfo {
  grade: string;
  expiry: string;
  protocol: string;
  cipher: string;
  issues: string[];
  issuer?: string;
  subject?: string;
}

export interface CrawlStats {
  pagesDiscovered: number;
  paramsFound: number;
  formsFound: number;
}

export interface InjectionFinding {
  type: 'sqli' | 'xss';
  payloadName?: string;
  url: string;
  param: string;
  evidence: string;
  severity: 'critical' | 'high' | 'medium';
  description?: string;
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

export interface ReconData {
  logs: string[];
  dnsRecords: DNSRecord[];
  subdomains: string[];
  headers: SecurityHeader[];
  technologies: Technology[];
  redirectChain: RedirectChainEntry[];
}

export interface ActiveData {
  logs: string[];
  sensitiveFiles: ExposedFile[];
  sslInfo: SSLInfo;
  openPorts: OpenPort[];
  crawlStats: CrawlStats;
  crawlData: CrawlData;
}

export interface AttackData {
  logs: string[];
  injectionFindings: InjectionFinding[];
  corsFindings: CorsFinding[];
  openRedirectFindings: OpenRedirectFinding[];
}

export type ScanResponse =
  | { success: true; phase: 'recon'; data: ReconData }
  | { success: true; phase: 'active'; data: ActiveData }
  | { success: true; phase: 'attack'; data: AttackData }
  | { success: false; error: string };
