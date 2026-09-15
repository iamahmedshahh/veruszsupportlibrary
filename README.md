# veruszsupportlib

Sapling encryption and key derivation for Verus DREAM Apps.

WebAssembly powered library exposing three primitives:

- `z_getEncryptionAddress` — derive Sapling channel keys
- `encryptData` — encrypt bytes to a payment address
- `decryptData` — decrypt with viewing key + epk or just symmetric key

## Installation

```bash
pnpm add github:iamahmedshahh/zsupportextension#veruscryptolibrary
```

## Usage

### Derive channel keys

```typescript
import { z_getEncryptionAddress } from 'veruszsupportlib';

const keys = await z_getEncryptionAddress({
  seed:            seedBytes,        // Uint8Array
  fromId:          fromIdBytes,      // Uint8Array, 20 bytes (hash160)
  toId:            toIdBytes,        // Uint8Array, 20 bytes (hash160)
  encryptionIndex: 0,
});

// keys.address     → Uint8Array, 43 bytes
// keys.ivk         → Uint8Array, 32 bytes
// keys.extfvk      → Uint8Array
// keys.spendingKey → Uint8Array | null
```

### Encrypt data

```typescript
import { encryptData } from 'veruszsupportlib';

const encrypted = await encryptData({
  address: keys.address,
  data:    new TextEncoder().encode('hello'),
});

// encrypted.encryptedData       → Uint8Array
// encrypted.ephemeralPublicKey  → Uint8Array, 32 bytes
// encrypted.symmetricKey        → Uint8Array 169 bytes or null
```

### Decrypt data

Accepts any object with the encrypted fields — automatically picks ivk or ssk:

```typescript
import { decryptData } from 'veruszsupportlib';

const plaintext = await decryptData({
  objectdata: encrypted.encryptedData,
  ivk:        keys.ivk,
  epk:        encrypted.ephemeralPublicKey,
});
```

A `DataDescriptor` from `verus-typescript-primitives` also satisfies the input shape:

```typescript
import { DataDescriptor } from 'verus-typescript-primitives';

const descriptor = new DataDescriptor({
  objectdata: encryptedBytes,
  ivk:        ivkBuffer,
  epk:        epkBuffer,
});

const plaintext = await decryptData(descriptor);
```



# New Functions 


## encryptDescriptor

Encrypts a `DataDescriptor` to a Sapling payment address. 


### Parameters

| Field | Type | Description |
|---|---|---|
| `descriptor` | `DataDescriptor` | Your data + optional `mimeType`, `label`, `salt` |
| `address` | `Uint8Array` | 43-byte Sapling payment address |
| `returnSsk` | `boolean` | Optional. If `true`, returns the symmetric session key |

### Returns

```typescript
{
  descriptor: DataDescriptor;  
  ssk:        Uint8Array | null; 
}
```

### Example

```typescript
import { encryptDescriptor, DataDescriptor } from 'veruszsupportlib';
import { Buffer } from 'buffer';

const plain = new DataDescriptor({
  objectdata: Buffer.from('hello from library'),
  mimeType:   'text/plain',
});

const { descriptor: encrypted } = encryptDescriptor({
  descriptor: plain,
  address:    keys.address,
});

console.log(encrypted.toJson());
```

---

## decryptDescriptor

Decrypts an encrypted `DataDescriptor` and returns the original.

### Parameters

| Field | Type | Description |
|---|---|---|
| `descriptor` | `DataDescriptor` | Encrypted descriptor (cipher in `objectdata`, `epk` present) |
| `ivk` | `Uint8Array` | Incoming viewing key (use this OR `ssk`) |
| `ssk` | `Uint8Array` | Symmetric session key (use this OR `ivk`) |

### Returns

The original `DataDescriptor` with `objectdata`, `salt`, and any `mimeType`/`label` that was set during encryption.

### Example

```typescript
import { decryptDescriptor, DataDescriptor } from 'veruszsupportlib';

// If received as JSON over the wire:
const encrypted = DataDescriptor.fromJson(receivedJson);

const decrypted = decryptDescriptor({
  descriptor: encrypted,
  ivk:        keys.ivk,
});

console.log(decrypted.objectdata.toString('utf8'));   // "hello from library"
console.log(decrypted.mimeType);                       // "text/plain"
```

---

## Installation

The library is on the `veruszsupportlib` branch:

```bash
pnpm add github:iamahmedshahh/veruszsupportlib#veruszsupportlib
```

## Building WASM

```bash
cd veruszsupportweb
wasm-pack build --target web --release --out-dir pkg
```

## Building the Library

Once the wasm pack is build navigate to the root of the project:

```
pnpm build
```


## API

### z_getEncryptionAddress(params) → ChannelKeys

| Param           | Type       | Description                          |
|-----------------|------------|--------------------------------------|
| seed            | Uint8Array | Raw seed bytes (optional)            |
| spendingKey     | Uint8Array | 169 byte extended spending key (opt) |
| hdIndex         | number     | HD derivation index (optional)       |
| encryptionIndex | number     | Channel encryption index (optional)  |
| fromId          | Uint8Array | 20 byte hash160 of from VerusID      |
| toId            | Uint8Array | 20 byte hash160 of to VerusID        |
| returnSecret    | boolean    | Return the spending key in result    |

Returns `ChannelKeys` with `address`, `ivk`, `extfvk`, `spendingKey`.

### encryptData(params) → EncryptedPayload

| Param      | Type       | Description                          |
|------------|------------|--------------------------------------|
| address    | Uint8Array | 43 byte Sapling PaymentAddress       |
| data       | Uint8Array | Bytes to encrypt                     |
| returnSsk  | boolean    | Return the symmetric session key if requested    |

Returns `EncryptedPayload` with `encryptedData`, `ephemeralPublicKey`, `symmetricKey`.

### decryptData(descriptor) → Uint8Array

Accepts an object with `objectdata` and either:
- `ivk` (+ optional `epk`) — uses viewing key path
- `ssk` — uses symmetric key path

Returns decrypted bytes.

## Compatibility

| Environment              | Supported |
|--------------------------|-----------|
| Vite / Webpack / Rollup  | Yes       |
| Next.js, Nuxt, SvelteKit | Yes       |
| Node.js 18+              | Yes       |
| Deno, Bun                | Yes       |
| Electron, Tauri          | Yes       |



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