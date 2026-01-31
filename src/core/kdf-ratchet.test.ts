import { describe, it, expect, beforeEach } from 'vitest';
import { KDFRatchet, RatchetError } from './kdf-ratchet.js';
import { DefaultCryptoProvider } from '../crypto/default-provider.js';
import { constantTimeEqual } from '../utils/bytes.js';

describe('KDFRatchet', () => {
  let crypto: DefaultCryptoProvider;
  let initialKey: Uint8Array;

  beforeEach(async () => {
    crypto = new DefaultCryptoProvider();
    initialKey = await crypto.randomBytes(32);
  });

  describe('constructor', () => {
    it('should create a ratchet with initial state', () => {
      const ratchet = new KDFRatchet(0, initialKey);

      expect(ratchet.counter).toBe(0);
      expect(ratchet.currentChainKey.length).toBe(32);
    });

    it('should reject invalid key length', () => {
      expect(() => new KDFRatchet(0, new Uint8Array(16))).toThrow(RatchetError);
      expect(() => new KDFRatchet(0, new Uint8Array(64))).toThrow(RatchetError);
    });

    it('should reject negative counter', () => {
      expect(() => new KDFRatchet(-1, initialKey)).toThrow(RatchetError);
    });
  });

  describe('getCurrentEncryptionKey', () => {
    it('should derive a 32-byte encryption key', async () => {
      const ratchet = new KDFRatchet(0, initialKey);
      const encKey = await ratchet.getCurrentEncryptionKey(crypto);

      expect(encKey).toBeInstanceOf(Uint8Array);
      expect(encKey.length).toBe(32);
    });

    it('should derive same encryption key for same chain key', async () => {
      const ratchet1 = new KDFRatchet(0, initialKey);
      const ratchet2 = new KDFRatchet(0, initialKey);

      const key1 = await ratchet1.getCurrentEncryptionKey(crypto);
      const key2 = await ratchet2.getCurrentEncryptionKey(crypto);

      expect(constantTimeEqual(key1, key2)).toBe(true);
    });

    it('should derive different keys with different config', async () => {
      const ratchet1 = new KDFRatchet(0, initialKey);
      const ratchet2 = new KDFRatchet(0, initialKey, { kdfPersonal: 'custom' });

      const key1 = await ratchet1.getCurrentEncryptionKey(crypto);
      const key2 = await ratchet2.getCurrentEncryptionKey(crypto);

      expect(constantTimeEqual(key1, key2)).toBe(false);
    });
  });

  describe('turn', () => {
    it('should increment counter after turn', async () => {
      const ratchet = new KDFRatchet(0, initialKey);

      await ratchet.turn(crypto);

      expect(ratchet.counter).toBe(1);
    });

    it('should derive different chain key after turn', async () => {
      const ratchet = new KDFRatchet(0, initialKey);
      const keyBefore = ratchet.currentChainKey;

      await ratchet.turn(crypto);

      expect(constantTimeEqual(keyBefore, ratchet.currentChainKey)).toBe(false);
    });

    it('should derive different encryption keys after turn', async () => {
      const ratchet = new KDFRatchet(0, initialKey);
      const encKeyBefore = await ratchet.getCurrentEncryptionKey(crypto);

      await ratchet.turn(crypto);

      const encKeyAfter = await ratchet.getCurrentEncryptionKey(crypto);
      expect(constantTimeEqual(encKeyBefore, encKeyAfter)).toBe(false);
    });
  });

  describe('turnUntil', () => {
    it('should turn multiple times to reach target', async () => {
      const ratchet = new KDFRatchet(0, initialKey);

      const numTurns = await ratchet.turnUntil(crypto, 5);

      expect(numTurns).toBe(5);
      expect(ratchet.counter).toBe(5);
    });

    it('should return 0 if already at target', async () => {
      const ratchet = new KDFRatchet(5, initialKey);

      const numTurns = await ratchet.turnUntil(crypto, 5);

      expect(numTurns).toBe(0);
      expect(ratchet.counter).toBe(5);
    });

    it('should reject turning backwards', async () => {
      const ratchet = new KDFRatchet(5, initialKey);

      await expect(ratchet.turnUntil(crypto, 3)).rejects.toThrow(RatchetError);
    });

    it('should reject excessive turns', async () => {
      const ratchet = new KDFRatchet(0, initialKey);

      // Default maxCounterIncrement is 25000
      await expect(ratchet.turnUntil(crypto, 30000)).rejects.toThrow(RatchetError);
    });

    it('should respect custom maxCounterIncrement', async () => {
      const ratchet = new KDFRatchet(0, initialKey, { maxCounterIncrement: 10 });

      await expect(ratchet.turnUntil(crypto, 15)).rejects.toThrow(RatchetError);

      // But 10 should work
      const numTurns = await ratchet.turnUntil(crypto, 10);
      expect(numTurns).toBe(10);
    });
  });

  describe('clone', () => {
    it('should create independent copy', async () => {
      const ratchet = new KDFRatchet(0, initialKey);
      const clone = ratchet.clone();

      await ratchet.turn(crypto);

      expect(ratchet.counter).toBe(1);
      expect(clone.counter).toBe(0);
    });
  });

  describe('serialization', () => {
    it('should serialize and deserialize correctly', async () => {
      const ratchet = new KDFRatchet(5, initialKey);
      await ratchet.turn(crypto);
      await ratchet.turn(crypto);

      const json = ratchet.toJSON();
      const restored = KDFRatchet.fromJSON(json);

      expect(restored.counter).toBe(7);
      expect(constantTimeEqual(restored.currentChainKey, ratchet.currentChainKey)).toBe(true);
    });

    it('should preserve config through serialization', async () => {
      const config = { kdfPersonal: 'custom-app' };
      const ratchet = new KDFRatchet(0, initialKey, config);

      const json = ratchet.toJSON();
      const restored = KDFRatchet.fromJSON(json, config);

      const key1 = await ratchet.getCurrentEncryptionKey(crypto);
      const key2 = await restored.getCurrentEncryptionKey(crypto);

      expect(constantTimeEqual(key1, key2)).toBe(true);
    });
  });
});
