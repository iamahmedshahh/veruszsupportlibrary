import {resolve} from 'path'
import {defineConfig} from 'vite'

import pkg from './package.json' with {type: 'json'}

// Everything in "dependencies" is installed by the app, so never bundle it,
// including subpath imports such as verus-typescript-primitives/dist/....
const external = Object.keys(pkg.dependencies).map(
  name => new RegExp(`^${name.replace(/[.]/g, '\\.')}(/.*)?$`),
)

// The web build. React Native runs src/ itself, with engine.native.ts (see
// "react-native" in package.json).
export default defineConfig({
  build: {
    target: 'es2022',
    lib: {
      entry: resolve(__dirname, 'src/index.ts'),
      fileName: format => `index.${format}.js`,
      formats: ['es'],
    },
    rollupOptions: {external},
  },
})
