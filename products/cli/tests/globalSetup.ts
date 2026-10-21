import { spawnSync } from 'node:child_process';

// Process tests run the built bundle: build it once before any test file starts, so it is never stale.
export default function build() {
  const b = spawnSync('npx', ['vite', 'build'], { shell: true, encoding: 'utf8' });
  if (b.status !== 0) throw new Error(b.stdout + b.stderr);
}
