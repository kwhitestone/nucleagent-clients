import { cpSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
const destination = fileURLToPath(new URL('../dist/shell/runner/', import.meta.url));
mkdirSync(destination, { recursive: true });
cpSync(fileURLToPath(new URL('../desktop/runner-panel/', import.meta.url)), destination, { recursive: true });
