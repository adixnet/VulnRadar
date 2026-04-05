import type { ScanResult } from './scanner-data';

const STORAGE_KEY = 'vulnradar_history';
const MAX_HISTORY = 20;

export interface StoredScan {
  id: string;
  result: ScanResult;
  timestamp: string;
}

export function saveScan(result: ScanResult): StoredScan {
  const history = getHistory();
  const entry: StoredScan = {
    id: `scan-${Date.now()}`,
    result: {
      ...result,
      startTime: result.startTime instanceof Date ? result.startTime : new Date(result.startTime),
      endTime: result.endTime instanceof Date ? result.endTime : new Date(result.endTime || Date.now()),
    },
    timestamp: new Date().toISOString(),
  };
  history.unshift(entry);
  if (history.length > MAX_HISTORY) history.pop();
  localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
  return entry;
}

export function getHistory(): StoredScan[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
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

export function clearHistory() {
  localStorage.removeItem(STORAGE_KEY);
}
