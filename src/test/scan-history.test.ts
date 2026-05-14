import { describe, it, expect, beforeEach, vi } from 'vitest';
import { getHistory, saveScan, clearHistory } from '../lib/scan-history';
import type { ScanResult } from '../lib/scanner-data';

const STORAGE_KEY = 'vulnradar_history';

// Mock data
const mockScanResult: ScanResult = {
  target: 'example.com',
  startTime: new Date('2024-05-14T10:00:00Z'),
  endTime: new Date('2024-05-14T10:05:00Z'),
  vulnerabilities: [],
  openPorts: [],
  headers: [],
  sslInfo: { grade: 'A', expiry: '2025-01-01', protocol: 'TLS 1.3', cipher: 'AES', issues: [] },
  technologies: [],
  dnsRecords: [],
};

describe('scan-history', () => {
  beforeEach(() => {
    localStorage.clear();
    vi.clearAllMocks();
  });

  describe('getHistory', () => {
    it('should return an empty array when localStorage is empty', () => {
      const history = getHistory();
      expect(history).toEqual([]);
    });

    it('should return an empty array when localStorage contains invalid JSON', () => {
      localStorage.setItem(STORAGE_KEY, 'invalid-json');
      const history = getHistory();
      expect(history).toEqual([]);
    });

    it('should return an empty array when localStorage contains null string', () => {
      localStorage.setItem(STORAGE_KEY, 'null');
      const history = getHistory();
      expect(history).toEqual([]);
    });

    it('should return parsed history when localStorage contains valid data', () => {
      const mockHistory = [
        {
          id: 'scan-1',
          result: { 
            ...mockScanResult, 
            startTime: mockScanResult.startTime.toISOString(), 
            endTime: mockScanResult.endTime?.toISOString() 
          },
          timestamp: new Date().toISOString(),
        }
      ];
      localStorage.setItem(STORAGE_KEY, JSON.stringify(mockHistory));
      
      const history = getHistory();
      expect(history.length).toBe(1);
      expect(history[0].result.target).toBe('example.com');
      expect(history[0].result.startTime).toBeInstanceOf(Date);
    });

    it('should handle malformed history items gracefully', () => {
      // History is an array, but items might be missing fields
      const mockHistory = [{ id: 'scan-1' }]; // missing result
      localStorage.setItem(STORAGE_KEY, JSON.stringify(mockHistory));
      
      const history = getHistory();
      // Current implementation will throw in .map because s.result is undefined
      // But the try-catch in getHistory should handle it
      expect(history).toEqual([]);
    });
  });

  describe('saveScan', () => {
    it('should save a scan to localStorage', () => {
      saveScan(mockScanResult);
      const raw = localStorage.getItem(STORAGE_KEY);
      const history = JSON.parse(raw || '[]');
      expect(history.length).toBe(1);
      expect(history[0].result.target).toBe('example.com');
    });

    it('should limit history to MAX_HISTORY (20)', () => {
      for (let i = 0; i < 25; i++) {
        saveScan({ ...mockScanResult, target: `example${i}.com` });
      }
      const raw = localStorage.getItem(STORAGE_KEY);
      const history = JSON.parse(raw || '[]');
      expect(history.length).toBe(20);
      expect(history[0].result.target).toBe('example24.com'); // Most recent first
    });
  });

  describe('clearHistory', () => {
    it('should remove the history from localStorage', () => {
      saveScan(mockScanResult);
      expect(localStorage.getItem(STORAGE_KEY)).not.toBeNull();
      clearHistory();
      expect(localStorage.getItem(STORAGE_KEY)).toBeNull();
    });
  });
});
