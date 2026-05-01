import { defineConfig } from 'vitest/config';

// Vitest setup for the binary-bridge layer (`src/crypto.ts`). The bridge
// imports `@sqlitewasmblazor/crypto-core` as a workspace package; npm
// resolves that to `packages/crypto-core/` via the workspaces field, and
// crypto-core's package.json `main` points at `./src/index.ts` directly,
// so vitest reads source — no `dist/` build needed.
//
// crypto-core's own vitest suite still runs from
// `packages/crypto-core/vitest.config.ts` via `npm test -w
// @sqlitewasmblazor/crypto-core`.
export default defineConfig({
    test: {
        include: ['tests/**/*.test.ts'],
    },
});
