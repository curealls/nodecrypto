import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(__dirname, '..', '..', '..');
const cli = join(__dirname, '..');
const read = (...p: string[]) => readFileSync(join(...p), 'utf8');

// cli-spec.md §6: the published package carries the license and the notices of what it bundles.
describe('license files', () => {
  const pkg = JSON.parse(read(cli, 'package.json'));

  it('is Apache-2.0 and the package copy of LICENSE equals the repository one', () => {
    expect(pkg.license).toBe('Apache-2.0');
    expect(read(cli, 'LICENSE')).toBe(read(root, 'LICENSE'));
    expect(read(root, 'LICENSE')).toContain('Apache License');
  });

  it('ships the license files and nothing else besides dist and the README', () => {
    expect(pkg.files).toEqual(['dist', 'README.md', 'LICENSE', 'THIRD-PARTY-NOTICES']);
  });

  it('THIRD-PARTY-NOTICES lists every bundled engine dependency at its installed version', () => {
    const deps = Object.keys(JSON.parse(read(root, 'products', 'engine', 'package.json')).dependencies);
    const notices = read(cli, 'THIRD-PARTY-NOTICES');
    for (const d of deps) {
      const { version } = JSON.parse(read(root, 'node_modules', d, 'package.json'));
      expect(notices, d).toContain(`${d} ${version}`);
    }
  });
});
