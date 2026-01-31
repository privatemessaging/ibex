import type { CryptoProvider, KeyPair } from '../types/crypto.js';
import nacl from 'tweetnacl';
import { blake2b } from '@noble/hashes/blake2.js';

/**
 * Pad or truncate a string to exactly `length` bytes
 */
function padString(str: string, length: number): Uint8Array {
  const encoder = new TextEncoder();
  const encoded = encoder.encode(str);
  const result = new Uint8Array(length);
  result.set(encoded.subarray(0, length));
  return result;
}

/**
 * Default crypto provider using tweetnacl and @noble/hashes
 *
 * This implementation is suitable for Node.js and browser environments.
 * For production use, consider implementing CryptoProvider with
 * platform-specific optimized libraries.
 */
export class DefaultCryptoProvider implements CryptoProvider {
  async generateKeyPair(): Promise<KeyPair> {
    const keyPair = nacl.box.keyPair();
    return {
      publicKey: keyPair.publicKey,
      privateKey: keyPair.secretKey,
    };
  }

  async x25519(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
    // tweetnacl's scalarMult performs X25519
    return nacl.scalarMult(privateKey, publicKey);
  }

  async blake2b256(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array> {
    // BLAKE2b personalization and salt are each 16 bytes
    const personalBytes = padString(personal, 16);
    const saltBytes = padString(salt, 16);

    const result = blake2b(data, {
      dkLen: 32,
      key: key ?? undefined,
      personalization: personalBytes,
      salt: saltBytes,
    });
    // Wrap in canonical Uint8Array to ensure compatibility with tweetnacl's
    // strict instanceof checks (noble-hashes may return a subclass)
    return new Uint8Array(result);
  }

  async blake2b512(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array> {
    const personalBytes = padString(personal, 16);
    const saltBytes = padString(salt, 16);

    const result = blake2b(data, {
      dkLen: 64,
      key: key ?? undefined,
      personalization: personalBytes,
      salt: saltBytes,
    });
    return new Uint8Array(result);
  }

  async symmetricEncrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    return nacl.secretbox(data, nonce, key);
  }

  async symmetricDecrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    const result = nacl.secretbox.open(data, nonce, key);
    if (result === null) {
      throw new Error('Decryption failed: authentication tag mismatch');
    }
    return result;
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    return nacl.randomBytes(length);
  }
}

/**
 * Singleton instance of the default crypto provider
 */
export const defaultCryptoProvider = new DefaultCryptoProvider();
