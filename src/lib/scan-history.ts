import type { ScanResult } from './scanner-data';
import { supabase } from '@/integrations/supabase/client';

export interface StoredScan {
  id: string;
  result: ScanResult;
  timestamp: string;
}

export async function saveScan(result: ScanResult): Promise<StoredScan> {
  const entry: StoredScan = {
    id: `scan-${Date.now()}`,
    result: {
      ...result,
      startTime: result.startTime instanceof Date ? result.startTime : new Date(result.startTime),
      endTime: result.endTime instanceof Date ? result.endTime : new Date(result.endTime || Date.now()),
    },
    timestamp: new Date().toISOString(),
  };

  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error } = await (supabase.from as any)('scan_history').insert([
      {
        id: entry.id,
        target: result.target,
        result: entry.result,
        timestamp: entry.timestamp,
      }
    ]);
    
    if (error) {
      console.error('Failed to save to Supabase:', error);
      // Fallback to local storage if DB is not configured yet
      saveToLocalStorage(entry);
    }
  } catch (err) {
    console.error('Error saving scan:', err);
    saveToLocalStorage(entry);
  }

  return entry;
}

export async function getHistory(): Promise<StoredScan[]> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data, error } = await (supabase.from as any)('scan_history')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(20);

    if (error || !data) {
      console.error('Failed to get history from Supabase:', error);
      return getFromLocalStorage();
    }

    // Migration logic: If Supabase is empty but local storage has data, migrate it!
    if (data.length === 0) {
      const localHistory = getFromLocalStorage();
      if (localHistory.length > 0) {
        try {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          await (supabase.from as any)('scan_history').insert(
            localHistory.map(entry => ({
              id: entry.id,
              target: entry.result.target,
              result: entry.result,
              timestamp: entry.timestamp,
            }))
          );
          return localHistory;
        } catch (e) {
          console.error('Migration failed:', e);
          return localHistory;
        }
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return data.map((row: any) => ({
      id: row.id,
      timestamp: row.timestamp,
      result: {
        ...row.result,
        startTime: new Date(row.result.startTime),
        endTime: row.result.endTime ? new Date(row.result.endTime) : undefined,
      }
    }));
  } catch (err) {
    console.error('Error fetching history:', err);
    return getFromLocalStorage();
  }
}

export async function clearHistory(): Promise<void> {
  try {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error } = await (supabase.from as any)('scan_history')
      .delete()
      .neq('id', '0'); // Delete all rows
      
    if (error) {
      console.error('Failed to clear history from Supabase:', error);
    }
    // Always clear fallback too
    localStorage.removeItem('vulnradar_history');
  } catch (err) {
    console.error('Error clearing history:', err);
    localStorage.removeItem('vulnradar_history');
  }
}

// Fallback mechanisms for when Supabase table isn't created yet
function saveToLocalStorage(entry: StoredScan) {
  const history = getFromLocalStorage();

  history.unshift(entry);

  if (history.length > 20) {
    history.pop();
  }

  try {
    localStorage.setItem(
      'vulnradar_history',
      JSON.stringify(history)
    );
  } catch (err) {
    if (
  err instanceof DOMException &&
  err.name === 'QuotaExceededError'
) {
    console.warn(
      'Local storage quota exceeded. Trimming old scan history.'
    );

    let recovered = false;

    // Remove oldest entries until storage succeeds
    while (history.length > 1) {
        history.pop();

        try {
          localStorage.setItem(
            'vulnradar_history',
            JSON.stringify(history)
          );

          console.info(
            'Recovered by trimming old scan history.'
          );

          recovered = true;
          break;
        } catch (retryErr) {
          if (
            !(
              retryErr instanceof DOMException &&
              retryErr.name === 'QuotaExceededError'
            )
          ) {
            throw retryErr;
          }
        }
      }

      // Recovery failed completely
      if (!recovered) {
        throw new Error(
          'Unable to recover from localStorage quota exceeded error.'
        );
      }
  } else {
    throw err;
    }
  }
}

function getFromLocalStorage(): StoredScan[] {
  try {
    const raw = localStorage.getItem('vulnradar_history');
    if (!raw) return [];
    const parsed = JSON.parse(raw) as StoredScan[];
    return parsed.map(s => ({
      ...s,
      result: {
        ...s.result,
        startTime: new Date(s.result.startTime),
        endTime: s.result.endTime ? new Date(s.result.endTime) : undefined,
      },
    }));
  } catch {
    return [];
  }
}
