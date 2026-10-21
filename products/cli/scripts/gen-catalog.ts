// Generates ai/catalog.json from the node registry (authoring.md §3.4).
// Run: npm run gen:catalog. The output is committed; edit the node definitions, not the JSON.
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defaultNodeRegistry } from 'nodecrypto-engine/registry/nodeRegistry';
import { generateCatalog } from 'nodecrypto-engine/authoring/catalog';

const outDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'ai');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'catalog.json'), JSON.stringify(generateCatalog(defaultNodeRegistry), null, 2) + '\n');
