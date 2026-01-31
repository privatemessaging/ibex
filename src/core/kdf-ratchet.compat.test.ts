import { describe, it, expect } from 'vitest';
import { KDFRatchet } from './kdf-ratchet.js';
import { DefaultCryptoProvider } from '../crypto/default-provider.js';
import { bytesToHex, hexToBytes } from '../utils/bytes.js';

/**
 * Android compatibility tests
 *
 * These test vectors are from Threema Android's KDFRatchetTest.java:
 * threema-android/domain/src/test/java/ch/threema/domain/fs/KDFRatchetTest.java
 *
 * The Android implementation uses:
 * - Counter starting at 0 (we start at 1)
 * - BLAKE2b with personalization "3ma-e2e" and salts "kdf-ck" / "kdf-aek"
 */
describe('Android KDFRatchet Compatibility', () => {
  const crypto = new DefaultCryptoProvider();

  // From KDFRatchetTest.java
  const INITIAL_CHAIN_KEY = '421e73cf324785dee4c4830f2efbb8cd4b258ed8520a608a6ce340aaa7400024';

  // Expected encryption key after 1 turn (counter=1 in Android)
  const EXPECTED_KEY_AFTER_1_TURN = '60d3de2d849fa8b3d9799e8e50b09a7ef1d4e1e855c99fdb711bfe29466cdad3';

  // Expected encryption key after 100 turns (counter=100 in Android)
  const EXPECTED_KEY_AFTER_100_TURNS = 'd2acf6e1c7262eb360ad92b6a74e0f9ad6ee129278742fc2462ae72916eaa334';

  it('should match Android encryption key after 1 turn', async () => {
    const initialChainKey = hexToBytes(INITIAL_CHAIN_KEY);

    // Create ratchet with counter=0 (matching Android)
    const ratchet = new KDFRatchet(0, initialChainKey);

    // Turn once (like Android's turnRatchet() call)
    await ratchet.turn(crypto);
    expect(ratchet.counter).toBe(1); // Same as Android after 1 turn

    // Get the encryption key
    const encryptionKey = await ratchet.getCurrentEncryptionKey(crypto);
    const keyHex = bytesToHex(encryptionKey);

    expect(keyHex).toBe(EXPECTED_KEY_AFTER_1_TURN);
  });

  it('should match Android encryption key after 100 turns', async () => {
    const initialChainKey = hexToBytes(INITIAL_CHAIN_KEY);
    const ratchet = new KDFRatchet(0, initialChainKey);

    // Turn 100 times
    for (let i = 0; i < 100; i++) {
      await ratchet.turn(crypto);
    }
    expect(ratchet.counter).toBe(100); // Same as Android after 100 turns

    const encryptionKey = await ratchet.getCurrentEncryptionKey(crypto);
    const keyHex = bytesToHex(encryptionKey);

    expect(keyHex).toBe(EXPECTED_KEY_AFTER_100_TURNS);
  });

  it('should use turnUntil to reach counter 100', async () => {
    const initialChainKey = hexToBytes(INITIAL_CHAIN_KEY);
    const ratchet = new KDFRatchet(0, initialChainKey);

    // Turn until counter=100 (same as 100 turns from counter=0)
    await ratchet.turnUntil(crypto, 100);

    const encryptionKey = await ratchet.getCurrentEncryptionKey(crypto);
    const keyHex = bytesToHex(encryptionKey);

    expect(keyHex).toBe(EXPECTED_KEY_AFTER_100_TURNS);
  });
});
