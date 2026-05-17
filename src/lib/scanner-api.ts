import { supabase } from './supabase';
import { ScanResult } from './scanner-data';

export const executeScan = async (url: string): Promise<ScanResult> => {
  if (!import.meta.env.VITE_SUPABASE_URL || !import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY) {
    throw new Error("CRITICAL: Supabase Environment Variables are missing. Add them to Lovable/Vercel.");
  }

  try {
    const { data, error } = await supabase.functions.invoke('scan-target', {
      body: { targetUrl: url }
    });

    if (error) {
      throw new Error(`Backend Error: ${error.message || 'Failed to execute scan via Supabase.'}`);
    }

    return data;
  } catch (err: any) {
    return { 
      success: false, 
      error: err.message || "Failed to contact the scan server. Check your backend deployment." 
    };
  }
};
