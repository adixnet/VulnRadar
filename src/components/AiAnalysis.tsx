import { useState } from 'react';
import DOMPurify from 'dompurify';
import { Brain, Loader2, RefreshCw } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { supabase } from '@/integrations/supabase/client';
import type { ScanResult } from '@/lib/scanner-data';

interface AiAnalysisProps {
  result: ScanResult;
}

const AiAnalysis = ({ result }: AiAnalysisProps) => {
  const [analysis, setAnalysis] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const runAnalysis = async () => {
    setLoading(true);
    setError(null);
    try {
      const { data, error: fnError } = await supabase.functions.invoke('ai-analyze', {
        body: { scanResult: result },
      });
      if (fnError) throw new Error(fnError.message);
      if (!data?.success) throw new Error(data?.error || 'Analysis failed');
      setAnalysis(data.analysis);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  };

  if (!analysis && !loading && !error) {
    return (
      <div className="flex flex-col items-center justify-center py-12 space-y-4">
        <Brain className="w-12 h-12 text-primary/40" />
        <p className="text-sm text-muted-foreground text-center max-w-md">
          Generate an AI-powered executive security assessment with prioritized remediation steps.
        </p>
        <Button onClick={runAnalysis} className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
          <Brain className="w-4 h-4" /> Generate AI Analysis
        </Button>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-16 space-y-3">
        <Loader2 className="w-8 h-8 text-primary animate-spin" />
        <p className="text-sm text-muted-foreground">Analyzing {result.vulnerabilities.length} findings with AI...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-4">
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {error}
        </div>
        <Button onClick={runAnalysis} variant="outline" size="sm" className="gap-2">
          <RefreshCw className="w-3.5 h-3.5" /> Retry
        </Button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm font-medium text-foreground">
          <Brain className="w-4 h-4 text-primary" /> AI Security Assessment
        </div>
        <Button onClick={runAnalysis} variant="outline" size="sm" className="gap-1.5 text-xs">
          <RefreshCw className="w-3 h-3" /> Regenerate
        </Button>
      </div>
      <div className="rounded-md border border-border bg-card p-4 sm:p-6 prose prose-sm prose-invert max-w-none
        [&_h3]:text-base [&_h3]:font-bold [&_h3]:text-foreground [&_h3]:mt-6 [&_h3]:mb-2
        [&_h4]:text-sm [&_h4]:font-semibold [&_h4]:text-foreground [&_h4]:mt-4 [&_h4]:mb-1
        [&_p]:text-sm [&_p]:text-muted-foreground [&_p]:leading-relaxed
        [&_li]:text-sm [&_li]:text-muted-foreground
        [&_strong]:text-foreground
        [&_ol]:space-y-1 [&_ul]:space-y-1
        [&_code]:text-primary [&_code]:bg-primary/10 [&_code]:px-1 [&_code]:rounded [&_code]:text-xs
      ">
        {/* Sanitize AI-generated HTML to mitigate XSS */}
        <div
          dangerouslySetInnerHTML={{
            __html: DOMPurify.sanitize(markdownToHtml(analysis || '')),
          }}
        />
      </div>
    </div>
  );
};

function markdownToHtml(md: string): string {
  return md
    .replace(/### (.+)/g, '<h3>$1</h3>')
    .replace(/#### (.+)/g, '<h4>$1</h4>')
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^\d+\.\s+(.+)$/gm, '<li>$1</li>')
    .replace(/^[-•]\s+(.+)$/gm, '<li>$1</li>')
    .replace(/(<li>[\s\S]*?<\/li>)/g, (match) => {
      if (!match.startsWith('<ul>') && !match.startsWith('<ol>')) return match;
      return match;
    })
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br/>')
    .replace(/^/, '<p>')
    .replace(/$/, '</p>');
}

export default AiAnalysis;
