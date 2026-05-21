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
// Mock Supabase client globally to avoid environment key errors during tests
// Forces fallback paths so that localStorage assertions in tests pass successfully
vi.mock("@/integrations/supabase/client", () => ({
  supabase: {
    from: vi.fn(() => ({
      insert: vi.fn().mockResolvedValue({ error: new Error("Supabase DB not configured in test environment") }),
      select: vi.fn(() => ({
        order: vi.fn(() => ({
          limit: vi.fn().mockResolvedValue({ data: null, error: new Error("Supabase DB not configured in test environment") }),
        })),
      })),
      delete: vi.fn(() => ({
        neq: vi.fn().mockResolvedValue({ error: new Error("Supabase DB not configured in test environment") }),
      })),
    })),
  },
}));
