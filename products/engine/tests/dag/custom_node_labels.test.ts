import { describe, it, expect } from 'vitest';
import { disambiguatedLabels } from 'nodecrypto-engine/dag/customNode';

const id = (c: string) => `sha256:${c.repeat(64)}`;

describe('disambiguatedLabels (package-format.md §3.6)', () => {
  it('adds version, then short id, only among same-name nodes in one category', () => {
    const labels = disambiguatedLabels([
      { id: id('a'), label: 'Signer', version: '1.0', category: 'X' },
      { id: id('b'), label: 'Signer', version: '2.0', category: 'X' },
      { id: id('c'), label: 'Signer', version: '2.0', category: 'X' },
      { id: id('d'), label: 'Signer', version: '1.0', category: 'Y' },
      { id: id('e'), label: 'Hasher', version: '', category: 'X' },
      { id: id('f'), label: 'Plain', version: '', category: 'Y' },
      { id: id('0'), label: 'Plain', version: '', category: 'Y' },
    ]);
    expect(labels.get(id('a'))).toBe('Signer (1.0)');
    expect(labels.get(id('b'))).toBe('Signer (2.0, bbbbbbbb)');
    expect(labels.get(id('c'))).toBe('Signer (2.0, cccccccc)');
    expect(labels.get(id('d'))).toBe('Signer');
    expect(labels.get(id('e'))).toBe('Hasher');
    expect(labels.get(id('f'))).toBe('Plain (ffffffff)');
    expect(labels.get(id('0'))).toBe('Plain (00000000)');
  });
});
