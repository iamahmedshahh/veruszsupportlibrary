// The build inlines the WebAssembly as a data URL (see engine.ts).
declare module '*.wasm?url' {
  const dataUrl: string
  export default dataUrl
}
