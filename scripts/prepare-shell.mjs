import { readFileSync, writeFileSync, symlinkSync, rmSync } from 'node:fs';
import { resolve } from 'node:path';

// Apply client-only build settings to the exported shell, never its source repo.
const root = resolve(process.argv[2]);
const shell = resolve(root, '.shell-build/nucleagent-web');
const configPath = resolve(shell, 'vite.config.ts');
let config = readFileSync(configPath, 'utf8');
const anchor = 'plugins: [vue()],';
if (!config.includes(anchor)) throw new Error('Shell Vite configuration changed; review the client overlay');
config = `import VueI18nPlugin from "@intlify/unplugin-vue-i18n/vite";\n${config}`;
config = config.replace(anchor, `plugins: [vue(), VueI18nPlugin({
      include: [resolve(process.cwd(), "src/i18n/{zh,en}.ts")],
      runtimeOnly: true,
      jitCompilation: false,
    })],`);
writeFileSync(configPath, config);
const pluginLink = resolve(shell, 'node_modules/@intlify/unplugin-vue-i18n');
rmSync(pluginLink, { force: true, recursive: true });
symlinkSync(resolve(root, 'node_modules/@intlify/unplugin-vue-i18n'), pluginLink, 'dir');
