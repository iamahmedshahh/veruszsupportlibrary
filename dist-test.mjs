import { KEYBYTES } from 'blake2b';
import {
  z_getEncryptionAddress,
  encryptDescriptor,
  decryptDescriptor,
  DataDescriptor,
} from './dist/index.es.js';

import { Buffer } from 'buffer';
import { bech32 } from 'bech32';
import bs58check from 'bs58check';

// Decode i-address to extract embedded hash160 (not hash it!)
function iAddressToHash160(iAddress) {
  const decoded = bs58check.decode(iAddress);
  return new Uint8Array(decoded.slice(1)); // skip version byte
}


const seed = new Uint8Array(Buffer.from('aa'.repeat(32), 'hex'));

const keys = z_getEncryptionAddress({
  seed,
  fromId:         iAddressToHash160('i4Wbn1whE3AoxqyTuT2xdQMNE5Uz1BCSuQ'),
  toId:           iAddressToHash160('i3bCS2hfQXktHXHmXEAxKPeby5cb6Px6Le'),
  hdIndex: 0,
  encryptionIndex: 0,
  returnSecret:    true,
});


console.log('═══ Channel keys ═══');
console.log('ivk:', Buffer.from(keys.ivk).toString('hex'));

// Decode address bytes to readable zs1... format
const addressWords = bech32.toWords(Buffer.from(keys.address));
const addressReadable = bech32.encode('zs', addressWords);
console.log('address:', addressReadable);

const message = 'hello from library';

const inputDescriptor = new DataDescriptor({
  objectdata: Buffer.from(message),
  // salt omitted — encryptDescriptor generates one
});

console.log('\n═══ Input descriptor ═══');
console.log(JSON.stringify(inputDescriptor.toJson(), null, 2));


const result = encryptDescriptor({
  descriptor: inputDescriptor,
  address:    keys.address,
  returnSsk:  true,
});

console.log('\n═══ encryptDescriptor() result ═══');
console.log('returned object keys:', Object.keys(result));
console.log('\nresult.descriptor (the encrypted DataDescriptor):');
console.log(JSON.stringify(result.descriptor.toJson(), null, 2));
console.log('\nresult.ssk (symmetric key, hex):');
console.log(`  ${Buffer.from(result.ssk).toString('hex')}`);

console.log('\nraw fields on the returned descriptor:');
console.log('  version:    ', result.descriptor.version.toString());
console.log('  flags:      ', result.descriptor.flags.toString());
console.log('  objectdata: ', result.descriptor.objectdata.toString('hex'), `(${result.descriptor.objectdata.length} bytes)`);
console.log('  epk:        ', result.descriptor.epk.toString('hex'), `(${result.descriptor.epk.length} bytes)`);


const decryptedInner = decryptDescriptor({
  descriptor: result.descriptor,
  ivk:        keys.ivk,
});

console.log('\n═══ decryptDescriptor() result ═══');
console.log('inner descriptor JSON:');
console.log(JSON.stringify(decryptedInner.toJson(), null, 2));
console.log('\ndecrypted message:', decryptedInner.objectdata.toString('utf8'));
console.log('decrypted type (hex):', decryptedInner.mimeType);
console.log('roundtrip ok?     ', decryptedInner.objectdata.toString('utf8') === message);


const daemonPayload = {
  datadescriptor: {
    version:    1,
    flags:      5,
    objectdata: result.descriptor.objectdata.toString('hex'),
    epk:        result.descriptor.epk.toString('hex'),
  },
  ivk: Buffer.from(keys.ivk).toString('hex'),
};

console.log('\n═══ Daemon verification ═══');
console.log(`./verus decryptdata '${JSON.stringify(daemonPayload)}'`);
console.log('\n(Expected output: the message in hex →', Buffer.from(message).toString('hex'), ')');