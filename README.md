# veruszsupportlib

Sapling encryption and key derivation for Verus DREAM apps: one TypeScript API for
the web and React Native, over one Rust core.

```ts
import {decryptData, encryptData, zGetEncryptionAddress} from 'veruszsupportlib'

const keys = await zGetEncryptionAddress({seed, fromId, toId})
const payload = await encryptData({address: keys.address, data})
const plaintext = await decryptData({...payload, ivk: keys.ivk})
```

The same code runs in a browser, in Node and in a React Native app.

## How it fits together

```
your app
   │
veruszsupportlib            src/  one TypeScript API: types, names, descriptors
   │
   ├── src/engine.ts         web and Node: the Rust as WebAssembly (veruszsupportweb)
   └── src/engine.native.ts  React Native: the Rust as native code (veruszsupportmobile)
                                    │
                             veruszsupportcore  every check and limit
                                    │
                             verus_zfunc        the cryptography, as the daemon does it
```

- **One API.** Everything an app calls lives in `src/`. Only the engine differs
  by platform: bundlers and Node load `engine.ts`, and Metro loads
  `engine.native.ts` on Android and iOS. That's the same platform-file pattern
  React Native apps use, so there is no second TypeScript layer to keep in step.
- **One set of rules.** The checks and limits run in Rust, in
  `veruszsupportcore`, so both engines accept the same inputs and fail with the
  same messages. The TypeScript only checks types (a `Uint8Array` where bytes
  go, a `boolean` for a flag), resolves `name@` IDs and wraps descriptors.
- **One error.** Both engines throw `VerusZSupportError`, with a `kind` and a
  readable `message`.

| Folder | What it is |
|---|---|
| `src/` | The TypeScript API (`veruszsupportlib`) |
| `veruszsupportcore/` | Rust: checks, limits, calls into `verus_zfunc` |
| `veruszsupportweb/` | Rust → WebAssembly (wasm-bindgen), the web engine |
| `veruszsupportmobile/` | Rust → Android and iOS (uniffi), the native engine |
| `modules/react-native-veruszsupport/` | The native engine as a React Native package (`@veruszsupportlib/react-native-veruszsupport`) |
| `veruszsupporttests/` | The Rust tests of all three crates, in one place |
| `test/` | The TypeScript tests both engines run |

## Install

### Web and Node

```bash
pnpm add github:iamahmedshahh/veruszsupportlibrary#veruscryptolibrary
```

The WebAssembly is inlined in `dist/` and compiled on first use, so there is
nothing to configure: no WebAssembly plugin, no top-level await, no file to
serve.

### React Native

Add the API and the native engine:

```bash
pnpm add github:iamahmedshahh/veruszsupportlibrary#veruscryptolibrary
pnpm add https://github.com/iamahmedshahh/veruszsupportlibrary/releases/download/<tag>/veruszsupportlib-react-native-veruszsupport-1.1.0.tgz
```

You import only from `veruszsupportlib`. The engine has to be a dependency of
the app itself, because React Native links native code only for the app's own
dependencies, and it ships as a release tarball because its compiled libraries
are too large for git. Nothing else is needed: random bytes come from Rust,
not from a JavaScript polyfill.

## Usage

Every function but `limits()` is async and returns a Promise, on every
platform, so the calls stay the same if the work moves off the JS thread
later. Bytes go in as `Uint8Array`s (a `Buffer` is one), `null` or `undefined`
means "not given", and results come back as `Uint8Array`s, with `undefined`
for a field that isn't set.

### Derive channel keys

```ts
import {zGetEncryptionAddress} from 'veruszsupportlib'

const keys = await zGetEncryptionAddress({
  seed, // 32 or 64 bytes; or spendingKey (169 bytes)
  hdIndex: 0, // the account under the seed; only with seed
  encryptionIndex: 0,
  fromId: 'i4Wbn1whE3AoxqyTuT2xdQMNE5Uz1BCSuQ', // an i-address, a name@ or 20 bytes
  toId: 'alice@',
  system: 'VRSCTEST', // VRSC or VRSCTEST, any case; needed for a name@
  returnSecret: false,
})

keys.address // 43 bytes
keys.ivk // 32 bytes
keys.extfvk // 169 bytes
keys.spendingKey // 169 bytes, only with returnSecret: true
```

### Encrypt and decrypt bytes

```ts
import {decryptData, encryptData} from 'veruszsupportlib'

const payload = await encryptData({address: keys.address, data, returnSsk: true})
// payload.encryptedData, payload.epk (32 bytes), payload.ssk (32 bytes, only with returnSsk)

await decryptData({encryptedData: payload.encryptedData, epk: payload.epk, ivk: keys.ivk})
await decryptData({encryptedData: payload.encryptedData, ssk: payload.ssk})
```

Decrypt with exactly one key: `ivk` with its `epk`, or `ssk`. A payload made
without `returnSsk` can be passed back as it is: `decryptData({...payload, ivk})`.

### Encrypt and decrypt a DataDescriptor

```ts
import {DataDescriptor, decryptDescriptor, encryptDescriptor} from 'veruszsupportlib'
import {Buffer} from 'buffer'

const {descriptor} = await encryptDescriptor({
  descriptor: new DataDescriptor({objectdata: Buffer.from('hello'), mimeType: 'text/plain'}),
  address: keys.address,
})

const original = await decryptDescriptor({descriptor, ivk: keys.ivk})
original.objectdata.toString() // "hello"
```

This wraps the descriptor the way the daemon's `signdata` does
(`CDataDescriptor::WrapEncrypted`), so the daemon's `decryptdata` opens it, and
`decryptDescriptor` opens what the daemon encrypts. A salt you set is used as
it is and must be 32 bytes; without one, a fresh one is made.

### Limits

```ts
import {limits} from 'veruszsupportlib'

limits().maxIndex // 2147483647
```

## Errors

Everything the library rejects is a `VerusZSupportError`:

```ts
import {VerusZSupportError} from 'veruszsupportlib'

try {
  await zGetEncryptionAddress({seed, hdIndex: 2 ** 32})
} catch (error) {
  if (error instanceof VerusZSupportError) {
    error.kind // "InvalidInput"
    error.message // "hdIndex must be an index between 0 and 2147483647"
  }
}
```

| `kind` | Means | Examples |
|---|---|---|
| `InvalidInput` | The arguments were rejected before any cryptography ran. The call must change. | `seed or spendingKey is required`, `seed must be 32 or 64 bytes`, `hdIndex can only be used with seed`, `fromId must be exactly 20 bytes`, `epk is required with ivk`, `ivk and ssk cannot both be set`, `system is required when toId is a name@`, `system must be VRSC or VRSCTEST`, `returnSecret must be a boolean` |
| `Crypto` | The cryptography failed: a key that isn't valid, the wrong key or a changed ciphertext, or the decrypted data isn't a DataDescriptor. | `Decryption failed. Key or ciphertext may be incorrect.`, `decrypted data has no DataDescriptor` |

Anything else, such as a crash inside Rust, is thrown as it is: it is a bug,
not a result.

## Limits and where they come from

Every limit is defined once, in `veruszsupportcore/src/limits.rs`, and
`limits()` returns them:

| Field | Value | From |
|---|---|---|
| `maxIndex` | 2147483647 | ZIP 32 hardened indices (the daemon's `ZIP32_HARDENED_KEY_LIMIT` - 1) |
| `seedLengths` | 32, 64 | the daemon's `z_getencryptionaddress` |
| `spendingKeyBytes` | 169 | ZIP 32 extended spending key (the daemon's `ZIP32_XSK_SIZE`) |
| `paymentAddressBytes` | 43 | Zcash protocol spec, Sapling payment address |
| `identityIdBytes` | 20 | a VerusID (`CIdentityID`, a uint160) |
| `ivkBytes`, `epkBytes` | 32 | Zcash protocol spec (uint256 in the daemon) |
| `sskBytes`, `tagBytes` | 32, 16 | ChaCha20-Poly1305, RFC 8439 |
| `maxPayloadBytes` | 1000000 | the daemon's `signdata` cap, `MAX_TX_SIZE_AFTER_SAPLING` / 2 |
| `saltBytes` | 32 | the daemon's salts (`CSaltedData::FreshSalt`, a uint256) |

Indices reach Rust as plain JavaScript numbers and are checked there, so
`2 ** 32` or `1.5` is refused instead of quietly wrapping to another account.

## Security

- Seeds, keys and plaintext are held in Rust as `Secret`s, which are wiped when
  dropped, and the React Native engine wipes its own copies once Rust has
  them. The records that carry keys out of Rust have no `Debug`, so they can't
  be printed by mistake.
- Decrypted bytes are untrusted until they parse: anyone can encrypt to a
  public address.
- Salts and ephemeral keys come from the operating system's random source on
  Android and iOS, and from `crypto.getRandomValues` on the web.
- The Rust runs on the calling thread, on every platform. One decrypt takes
  a fraction of a millisecond and deriving keys a few milliseconds, so a
  single call goes unnoticed. For hundreds of messages at once, or payloads
  near the 1 MB cap, work in chunks and let the app draw in between; on the
  web you can also call the library from a Web Worker.

## Development

Once:

```bash
pnpm install
pnpm setup:web          # the wasm target and wasm-pack
pnpm setup:android      # the Android targets and cargo-ndk; pnpm setup:ios on a Mac
```

Build and test:

```bash
pnpm test               # Rust: the core and the mobile crate (veruszsupporttests)
pnpm test:wasm          # Rust: the web crate, as WebAssembly in Node (veruszsupporttests)
pnpm build:web          # WebAssembly + dist/
pnpm test:web           # the TypeScript suite against dist/
pnpm test:native        # the same suite through engine.native.ts, without a phone
pnpm test:all           # all of the above
pnpm typecheck          # src/, both engines
pnpm format             # Prettier, with the same settings as VerusSky
pnpm build:android      # the native libraries, and the bindings generated from them
pnpm build:ios          # on a Mac
```

Every Rust test lives in `veruszsupporttests`, one file per crate:
`tests/core.rs`, `tests/mobile.rs` and `tests/web.rs`, with the values they
share in `src/lib.rs`. The crates themselves hold no tests.

`pnpm test:native` bundles `src/` the way Metro does and swaps the native
bindings for `test/native/standin.mjs`, which is as strict as uniffi about its
inputs but runs the same Rust as WebAssembly. On a phone, the app is the test.

These are generated, never edited by hand: commit them as the build leaves
them.

- `dist/`, by `pnpm build:web`
- the engine's `src/index.tsx`, `src/NativeReactNativeVeruszsupport.ts`,
  `src/generated/`, `cpp/`, `ios/`, `android/` and podspec, by
  `pnpm build:android` and `pnpm build:ios`

## Using a local build in an app

Test the library in an app exactly the way it will be installed, from tarballs:

```bash
# in the library
pnpm build:web && pnpm pack
pnpm build:android && (cd modules/react-native-veruszsupport && pnpm pack)
```

```jsonc
// in the app's package.json
"veruszsupportlib": "file:../veruszsupportlibrary/veruszsupportlib-1.1.0.tgz",
"@veruszsupportlib/react-native-veruszsupport": "file:../veruszsupportlibrary/modules/react-native-veruszsupport/veruszsupportlib-react-native-veruszsupport-1.1.0.tgz"
```

Avoid `file:` pointing at the library's folder: the app keeps its own copy of
it, and it is easy to end up with the new JavaScript but the old native
library. The app then stops on the splash screen with `ApiChecksumMismatch`. After changing the native
library, also clear the app's native build (`android/app/.cxx`,
`android/app/build`, `android/build`).

## Notes for pnpm 11+ consumers

pnpm 11 blocks git-hosted transitive dependencies by default. Since this
library depends on `verus-typescript-primitives`, which pulls in `blake2b`
from a git fork, you'll hit `ERR_PNPM_EXOTIC_SUBDEP` on install.

Two options to resolve:

**Quick fix — allow exotic subdeps globally:**

Add to your project's `pnpm-workspace.yaml`:

```yaml
blockExoticSubdeps: false
```

**Manual maintenance — keep the security default:**

Add `blake2b` as a direct dependency in your `package.json`, then strip
the transitive one with a `.pnpmfile.cjs` in your project root:

```javascript
function readPackage(pkg) {
  if (pkg.name === 'verus-typescript-primitives' && pkg.dependencies?.blake2b) {
    delete pkg.dependencies.blake2b;
  }
  return pkg;
}

module.exports = { hooks: { readPackage } };
```

Users on npm, yarn, or pnpm 10 and earlier don't need either fix.

## License

MIT
