import { useState } from "react";
import { executeScan } from "@/lib/scanner-api";
import { ScanResult } from "@/lib/scanner-data";
import ScanProgress from "@/components/ScanProgress";
import ScanReport from "@/components/ScanReport";
import TerminalOutput from "@/components/TerminalOutput";
import AiAnalysis from "@/components/AiAnalysis";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Shield, AlertTriangle } from "lucide-react";
import { useToast } from "@/hooks/use-toast";

export default function Index() {
  const [url, setUrl] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanResults, setScanResults] = useState<ScanResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const { toast } = useToast();

  const handleStartScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url) {
      toast({
        variant: "destructive",
        title: "Input Required",
        description: "Please enter a target URL to scan.",
      });
      return;
    }

    setIsScanning(true);
    setScanResults(null);
    setErrorMessage(null);

    try {
      const result = await executeScan(url);

      if (result.success) {
        setScanResults(result);
        toast({
          title: "Scan Complete",
          description: `Successfully analyzed target architecture.`,
        });
      } else {
        setErrorMessage(result.error || "Scan failed");
        toast({
          variant: "destructive",
          title: "Scan Failed",
          description: result.error || "An unknown error occurred during analysis.",
        });
      }
    } catch (error: any) {
      setErrorMessage(error.message || "An unexpected system error occurred.");
      toast({
        variant: "destructive",
        title: "System Error",
        description: error.message,
      });
    } finally {
      setIsScanning(false);
    }
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-50 p-6 font-mono">
      <div className="max-w-5xl mx-auto space-y-8">
        
        <header className="flex flex-col items-center text-center space-y-4 pt-12">
          <div className="flex items-center gap-3 text-emerald-400">
            <Shield className="w-12 h-12" />
            <h1 className="text-4xl font-bold tracking-tighter">VulnRadar</h1>
          </div>
          <p className="text-zinc-400 max-w-xl text-lg">
            Production-grade vulnerability scanner.
          </p>
        </header>

        <form onSubmit={handleStartScan} className="flex gap-4 max-w-2xl mx-auto">
          <Input
            type="url"
            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isScanning}
            className="bg-zinc-900 border-zinc-800 text-emerald-400 placeholder:text-zinc-600 focus-visible:ring-emerald-500 h-14 text-lg"
            required
          />
          <Button 
            type="submit" 
            disabled={isScanning}
            className="h-14 px-8 bg-emerald-500 hover:bg-emerald-600 text-zinc-950 font-bold text-lg"
          >
            {isScanning ? "SCANNING..." : "SCAN"}
          </Button>
        </form>

        {errorMessage && (
          <div className="bg-red-500/10 border border-red-500/50 text-red-400 p-4 rounded-lg flex items-start gap-3 max-w-2xl mx-auto">
            <AlertTriangle className="w-5 h-5 mt-0.5 flex-shrink-0" />
            <p>{errorMessage}</p>
          </div>
        )}

        {isScanning && (
          <div className="space-y-6">
            <ScanProgress />
            <TerminalOutput isScanning={isScanning} />
          </div>
        )}

        {scanResults && !isScanning && (
          <div className="space-y-8 animate-in fade-in slide-in-from-bottom-4 duration-700">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              <div className="bg-zinc-900 border border-zinc-800 p-6 rounded-lg col-span-1 md:col-span-2">
                <h3 className="text-zinc-400 mb-2">Target</h3>
                <p className="text-emerald-400 text-xl font-bold break-all">
                  {scanResults.scannedUrl}
                </p>
              </div>
              <div className="bg-zinc-900 border border-zinc-800 p-6 rounded-lg">
                <h3 className="text-zinc-400 mb-2">Status Code</h3>
                <p className="text-emerald-400 text-xl font-bold">
                  {scanResults.status || "N/A"}
                </p>
              </div>
            </div>

            <ScanReport results={scanResults} />
            <AiAnalysis results={scanResults} />
          </div>
        )}

      </div>
    </div>
  );
}
