import { serve } from 'https://deno.land/std@0.168.0/http/server.ts';

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version',
};

const AI_GATEWAY_URL = 'https://ai.gateway.lovable.dev/v1/chat/completions';
const GEMINI_API_URL = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent';

function buildPrompt(scanResult: any): string {
  const vulnSummary = scanResult.vulnerabilities?.map((v: any) =>
    `- [${v.severity.toUpperCase()}] ${v.title} (CVSS: ${v.cvss}, ${v.cwe}): ${v.description}`
  ).join('\n') || 'No vulnerabilities found.';

  const corsSummary = scanResult.corsFindings?.length
    ? scanResult.corsFindings.map((f: any) => `- [${f.severity.toUpperCase()}] ${f.type}: ${f.description}`).join('\n')
    : 'No CORS issues.';

  const injectionSummary = scanResult.injectionFindings?.length
    ? `${scanResult.injectionFindings.length} injection finding(s) detected across parameters: ${[...new Set(scanResult.injectionFindings.map((f: any) => f.param))].join(', ')}`
    : 'No injection vulnerabilities.';

  const sslGrade = scanResult.sslInfo?.grade || 'N/A';
  const headersMissing = scanResult.headers?.filter((h: any) => h.status === 'missing').length || 0;
  const headersTotal = scanResult.headers?.length || 0;
  const openPorts = scanResult.openPorts?.map((p: any) => `${p.port}/${p.service}`).join(', ') || 'None';
  const subdomainCount = scanResult.subdomains?.length || 0;
  const crawlStats = scanResult.crawlStats;

  return `You are a senior penetration tester writing an executive security assessment report. Analyze the following scan results for "${scanResult.target}" and produce a structured report.

## Scan Data

**Target:** ${scanResult.target}
**SSL Grade:** ${sslGrade}
**Security Headers:** ${headersMissing}/${headersTotal} missing
**Open Ports:** ${openPorts}
**Subdomains Found:** ${subdomainCount}
**Crawl Stats:** ${crawlStats ? `${crawlStats.pagesDiscovered} pages, ${crawlStats.paramsFound} params, ${crawlStats.formsFound} forms` : 'N/A'}

### Vulnerabilities
${vulnSummary}

### CORS Findings
${corsSummary}

### Injection Testing
${injectionSummary}

### Open Redirects
${scanResult.openRedirectFindings?.length ? scanResult.openRedirectFindings.map((f: any) => `- ${f.url} → ${f.redirectedTo}`).join('\n') : 'No open redirects.'}

## Instructions

Produce the following sections in Markdown:

### 🔴 Executive Summary
2-3 sentences summarizing the overall security posture and most critical risks.

### 📊 Risk Assessment
Rate overall risk as CRITICAL / HIGH / MEDIUM / LOW with a brief justification.

### 🏆 Top 5 Priority Actions
Numbered list of the most impactful remediation steps, ordered by priority. Be specific and actionable.

### 🔍 Detailed Analysis
For each major finding category (headers, SSL, injection, CORS, etc.), provide:
- What was found
- Why it matters
- Specific fix

### ✅ What's Working Well
Mention any positive security measures detected.

Be concise, professional, and actionable. Use technical terms but explain impact in business terms.`;
}

async function callLovableAI(prompt: string): Promise<string> {
  const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
  if (!LOVABLE_API_KEY) throw new Error('LOVABLE_API_KEY not configured');

  const response = await fetch(AI_GATEWAY_URL, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${LOVABLE_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      model: 'google/gemini-2.5-flash',
      messages: [
        { role: 'system', content: 'You are a cybersecurity expert producing professional vulnerability assessment reports.' },
        { role: 'user', content: prompt },
      ],
      max_tokens: 2000,
      temperature: 0.3,
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Lovable AI error [${response.status}]: ${errorBody}`);
  }

  const data = await response.json();
  return data.choices?.[0]?.message?.content || '';
}

async function callGeminiDirect(prompt: string): Promise<string> {
  const GEMINI_API_KEY = Deno.env.get('GEMINI_API_KEY');
  if (!GEMINI_API_KEY) throw new Error('GEMINI_API_KEY not configured');

  const response = await fetch(`${GEMINI_API_URL}?key=${GEMINI_API_KEY}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      contents: [
        {
          parts: [
            { text: 'You are a cybersecurity expert producing professional vulnerability assessment reports.\n\n' + prompt }
          ]
        }
      ],
      generationConfig: {
        temperature: 0.3,
        maxOutputTokens: 2000,
      },
    }),
  });

  if (!response.ok) {
    const errorBody = await response.text();
    throw new Error(`Gemini API error [${response.status}]: ${errorBody}`);
  }

  const data = await response.json();
  return data.candidates?.[0]?.content?.parts?.[0]?.text || '';
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { scanResult } = await req.json();
    if (!scanResult) {
      return new Response(JSON.stringify({ error: 'Missing scanResult' }), {
        status: 400,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' },
      });
    }

    const prompt = buildPrompt(scanResult);
    let analysis = '';
    let provider = '';

    // Try Lovable AI first, fall back to direct Gemini API
    try {
      analysis = await callLovableAI(prompt);
      provider = 'lovable-ai';
      console.log('AI analysis generated via Lovable AI');
    } catch (lovableErr) {
      console.warn('Lovable AI failed, falling back to Gemini API:', lovableErr);
      try {
        analysis = await callGeminiDirect(prompt);
        provider = 'gemini-direct';
        console.log('AI analysis generated via Gemini API fallback');
      } catch (geminiErr) {
        console.error('Both AI providers failed:', geminiErr);
        throw new Error(`All AI providers failed. Lovable AI: ${lovableErr instanceof Error ? lovableErr.message : 'unknown'}. Gemini: ${geminiErr instanceof Error ? geminiErr.message : 'unknown'}`);
      }
    }

    if (!analysis) {
      throw new Error('AI returned empty analysis');
    }

    return new Response(JSON.stringify({ success: true, analysis, provider }), {
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.error('AI analysis error:', err);
    const msg = err instanceof Error ? err.message : 'Unknown error';
    return new Response(JSON.stringify({ error: msg }), {
      status: 500,
      headers: { ...corsHeaders, 'Content-Type': 'application/json' },
    });
  }
});
