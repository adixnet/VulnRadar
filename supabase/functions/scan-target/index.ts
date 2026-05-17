import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response('ok', { headers: corsHeaders });
  }

  try {
    const { targetUrl } = await req.json();

    if (!targetUrl) {
      throw new Error("Target URL is required");
    }

    const urlToScan = targetUrl.startsWith('http') ? targetUrl : `https://${targetUrl}`;
    
    const response = await fetch(urlToScan, {
      method: 'GET',
      headers: { 'User-Agent': 'VulnRadar-Real-Scanner/1.0' }
    });

    const headers = Object.fromEntries(response.headers.entries());
    const vulnerabilities = [];

    if (!headers['strict-transport-security']) {
      vulnerabilities.push({
        id: 'vuln-hsts',
        title: 'Missing HSTS Header',
        severity: 'High',
        description: 'HTTP Strict Transport Security is not enforced. Vulnerable to MITM attacks.',
      });
    }

    if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
      vulnerabilities.push({
        id: 'vuln-clickjack',
        title: 'Missing Clickjacking Protection',
        severity: 'Medium',
        description: 'Site is missing X-Frame-Options. Vulnerable to UI redressing.',
      });
    }

    if (headers['server']) {
      vulnerabilities.push({
        id: 'vuln-server-disclosure',
        title: 'Server Version Disclosure',
        severity: 'Low',
        description: `Server header exposes backend infrastructure: ${headers['server']}`,
      });
    }

    return new Response(
      JSON.stringify({ 
        success: true, 
        scannedUrl: urlToScan,
        status: response.status,
        vulnerabilities 
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );

  } catch (error) {
    return new Response(
      JSON.stringify({ success: false, error: error.message }),
      { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
