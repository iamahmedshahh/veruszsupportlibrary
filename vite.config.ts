import { defineConfig } from 'vite';
import { resolve } from 'path';
import wasm from 'vite-plugin-wasm';
import pkg from './package.json' with { type: 'json' };

// Everything in "dependencies" is installed by the app, so never bundle it,
// including subpath imports such as verus-typescript-primitives/dist/....
const external = Object.keys(pkg.dependencies).map(
  (name) => new RegExp(`^${name.replace(/[.]/g, '\\.')}(/.*)?$`),
);

export default defineConfig({
  plugins: [wasm()],
  build: {
    target: 'es2022',
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      fileName: (format) => `index.${format}.js`,
      formats: ['es'],
    },
    rollupOptions: {
      external,
    },
    copyPublicDir: false,
    assetsInlineLimit: 100_000_000,
  },
});