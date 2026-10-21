import type { NodePortDefinition } from '../types';

export type PortNameError = 'empty' | 'chars' | 'duplicate' | 'locked';

/**
 * Why `name` cannot be a port's name, or null (node-catalog.md §2.2-11, §2.2-14).
 * Only fixed ports are held to the character and same-side duplicate rules; variable ports keep their old freedom.
 */
export function portNameError(ports: NodePortDefinition[], portId: string, name: string, fixed: boolean): PortNameError | null {
  const n = name.trim();
  if (!n) return 'empty';
  if (!fixed) return null;
  if (/[/,()]/.test(n)) return 'chars';
  return ports.some((p) => p.id !== portId && p.name === n) ? 'duplicate' : null;
}
