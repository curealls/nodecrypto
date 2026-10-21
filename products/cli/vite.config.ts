import { defineConfig } from 'vitest/config';

// Single Node bundle: the engine and @noble/* are bundled, only node:* stays external (cli-spec.md §6).
export default defineConfig({
  ssr: { noExternal: true },
  build: {
    ssr: 'src/main.ts',
    target: 'node20',
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: { output: { entryFileNames: 'nodecrypto.mjs', banner: '#!/usr/bin/env node' } },
  },
  test: { environment: 'node', globalSetup: ['tests/globalSetup.ts'] },
});
