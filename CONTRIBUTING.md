# Contributing to VulnRadar

Thanks for your interest in contributing! VulnRadar is a real-time web vulnerability scanner with AI-powered analysis. This guide will get you set up and contributing quickly.

---

## Table of Contents

- [Project Setup](#project-setup)
- [Environment Variables](#environment-variables)
- [Available Scripts](#available-scripts)
- [Code Style Guidelines](#code-style-guidelines)
- [Contribution Workflow](#contribution-workflow)
- [Scanning Ethics & Responsible Usage](#scanning-ethics--responsible-usage)

---

## Project Setup

### Prerequisites

- [Node.js](https://nodejs.org/) v18+
- [Bun](https://bun.sh/) (preferred, lockfile included) or npm
- [Supabase CLI](https://supabase.com/docs/guides/cli) — required to run/deploy edge functions locally

### Installation

```bash
# Clone the repo
git clone https://github.com/wtfadi/VulnRadar.git
cd VulnRadar

# Install dependencies (use bun or npm)
bun install
# or
npm install

# Start the dev server
bun run dev
# or
npm run dev
```

The app will be available at `http://localhost:5173`.

### Supabase Edge Functions (Local)

```bash
# Start Supabase locally
supabase start

# Serve edge functions locally
supabase functions serve scan-target
supabase functions serve ai-analyze
```

---

## Environment Variables

Create a `.env` file in the project root (copy from `.env.example` if available):

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your-anon-key
VITE_SUPABASE_PROJECT_ID=your-project-id
```

For AI analysis, add the Gemini API key as a Supabase secret:

```bash
supabase secrets set GEMINI_API_KEY=your-gemini-key
```

> **Note:** Never commit `.env` files or secrets. The `.gitignore` already excludes `.env`.

---

## Available Scripts

| Command | Description |
|---|---|
| `bun run dev` / `npm run dev` | Start Vite dev server |
| `bun run build` / `npm run build` | Production build |
| `bun run preview` / `npm run preview` | Preview production build locally |
| `bun run lint` / `npm run lint` | Run ESLint |
| `bun run test` / `npm run test` | Run Vitest unit tests |
| `supabase functions deploy scan-target` | Deploy scan edge function |
| `supabase functions deploy ai-analyze` | Deploy AI analysis edge function |

---

## Code Style Guidelines

- **Language:** TypeScript 5 — strict typing preferred, avoid `any`
- **Formatter:** Prettier (default config) — run before committing
- **Linter:** ESLint with the project's `eslint.config.js` — no lint errors on PRs
- **Components:** Functional React components with hooks; no class components
- **Styling:** Tailwind CSS utility classes; use `shadcn/ui` primitives for new UI elements
- **File naming:** `PascalCase` for components (`VulnerabilityCard.tsx`), `kebab-case` for utilities (`scanner-api.ts`)
- **Imports:** Absolute imports via `@/` alias; group external → internal → relative
- **Commits:** Use conventional commit format — `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`

Example:

```
feat: add SSRF detection module to active scan phase
fix: correct SSL cert expiry date parsing
docs: update env variable instructions in README
```

---

## Contribution Workflow

1. **Fork** the repository and create your branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```

2. **Make changes** — keep commits focused and atomic.

3. **Lint and test** before pushing:
   ```bash
   npm run lint
   npm run test
   ```

4. **Open a Pull Request** against `main`. Use the PR template provided. Draft PRs are welcome for early feedback.

5. **Describe your changes** clearly — what problem it solves, how to test it, any screenshots if UI changes.

6. **Address review feedback** and keep the PR up to date with `main`.

### What to contribute

- New scanner modules (new vulnerability checks)
- Bug fixes and edge case handling
- UI/UX improvements
- Documentation improvements
- Test coverage additions
- Performance optimizations in scan orchestration

### What to avoid

- Hardcoded targets or credentials in any file
- Bypassing the sequential phase orchestration without discussion
- Breaking changes to the `scanner-api.ts` public interface without a prior issue

---

## Scanning Ethics & Responsible Usage

VulnRadar is a security tool. All contributions must align with responsible disclosure principles.

### Rules for contributors

- **Never include real targets** in tests, examples, fixtures, or documentation. Use `example.com`, `localhost`, or clearly fictional domains.
- **No payload escalation** — do not add destructive, data-exfiltrating, or denial-of-service payloads. Detection and fingerprinting only.
- **Authorization checks** — if adding UI features, do not remove or weaken any warnings about scanning only authorized targets.
- **No credential harvesting** — contributions must not collect, log, or transmit user credentials or scan results to third parties.
- **Responsible disclosure** — if you discover a real vulnerability while working on VulnRadar, follow responsible disclosure practices. Do not exploit it.

### Legal reminder

Scanning systems without explicit written authorization is illegal in most jurisdictions. VulnRadar contributors are expected to test only against systems they own or have permission to test. The maintainers are not responsible for misuse.

---

## Questions?

Open an issue or start a discussion. Draft PRs for early feedback are always welcome.
