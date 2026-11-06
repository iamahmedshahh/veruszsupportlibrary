export function useThenWipe<T>(buf: Uint8Array, fn: (b: Uint8Array) => T): T {
  try {
    return fn(buf);
  } finally {
    buf.fill(0);
  }
}

