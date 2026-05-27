import "@testing-library/jest-dom";
import { vi } from 'vitest';

Object.defineProperty(window, "matchMedia", {
  writable: true,
  value: (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => {},
  }),
});
// Mock Supabase client exports to avoid environment key errors during tests
// Provide `getSupabase` that returns null so code paths fall back to localStorage
vi.mock("@/integrations/supabase/client", () => ({
  getSupabase: () => null,
  requireSupabase: () => {
    throw new Error('Supabase is not configured in test environment');
  },
}));
