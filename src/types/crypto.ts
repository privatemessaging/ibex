/**
 * Key pair for X25519 key exchange
 */
export interface KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/**
 * Cryptographic provider interface
 *
 * All methods return Promises to support both synchronous and asynchronous
 * implementations (e.g., WebCrypto, hardware security modules, etc.)
 */
export interface CryptoProvider {
  /**
   * Generate an X25519 key pair
   * @returns 32-byte public key and 32-byte private key
   */
  generateKeyPair(): Promise<KeyPair>;

  /**
   * Perform X25519 Diffie-Hellman key exchange
   * @param privateKey - 32-byte private key
   * @param publicKey - 32-byte public key of the other party
   * @returns 32-byte shared secret
   */
  x25519(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array>;

  /**
   * Compute BLAKE2b-256 keyed hash
   * @param key - Key material (or null for unkeyed hash)
   * @param personal - Personalization string (max 16 bytes when encoded)
   * @param salt - Salt string (max 16 bytes when encoded)
   * @param data - Data to hash
   * @returns 32-byte hash
   */
  blake2b256(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Compute BLAKE2b-512 keyed hash
   * @param key - Key material (or null for unkeyed hash)
   * @param personal - Personalization string (max 16 bytes when encoded)
   * @param salt - Salt string (max 16 bytes when encoded)
   * @param data - Data to hash
   * @returns 64-byte hash
   */
  blake2b512(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Encrypt data using XSalsa20-Poly1305 (NaCl secretbox)
   * @param data - Plaintext to encrypt
   * @param key - 32-byte encryption key
   * @param nonce - 24-byte nonce
   * @returns Ciphertext with 16-byte authentication tag prepended
   */
  symmetricEncrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Decrypt data using XSalsa20-Poly1305 (NaCl secretbox)
   * @param data - Ciphertext with authentication tag
   * @param key - 32-byte encryption key
   * @param nonce - 24-byte nonce
   * @returns Decrypted plaintext
   * @throws Error if authentication fails
   */
  symmetricDecrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array>;

  /**
   * Generate cryptographically secure random bytes
   * @param length - Number of bytes to generate
   * @returns Random bytes
   */
  randomBytes(length: number): Promise<Uint8Array>;
}

/**
 * Constants for key and nonce sizes
 */
export const CryptoConstants = {
  /** X25519 public key size in bytes */
  PUBLIC_KEY_BYTES: 32,
  /** X25519 private key size in bytes */
  PRIVATE_KEY_BYTES: 32,
  /** Shared secret size in bytes */
  SHARED_SECRET_BYTES: 32,
  /** XSalsa20-Poly1305 nonce size in bytes */
  NONCE_BYTES: 24,
  /** XSalsa20-Poly1305 key size in bytes */
  SYMMETRIC_KEY_BYTES: 32,
  /** Poly1305 authentication tag size in bytes */
  AUTH_TAG_BYTES: 16,
} as const;
