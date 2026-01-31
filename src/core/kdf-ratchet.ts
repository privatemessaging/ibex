import type { CryptoProvider } from '../types/crypto.js';
import type { ResolvedIbexConfig } from '../types/common.js';
import { DEFAULT_CONFIG } from '../types/common.js';

/**
 * Error thrown when a ratchet operation fails
 */
export class RatchetError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RatchetError';
  }
}

/**
 * KDF Ratchet for forward secrecy
 *
 * Each turn derives a new chain key from the previous one, ensuring
 * that past keys cannot be recovered from the current state.
 */
export class KDFRatchet {
  private _counter: number;
  private _currentChainKey: Uint8Array;
  private _config: ResolvedIbexConfig;

  /**
   * Create a new KDF ratchet
   * @param counter - Initial counter value (typically 0)
   * @param initialChainKey - 32-byte initial chain key (K0)
   * @param config - Optional configuration overrides
   */
  constructor(
    counter: number,
    initialChainKey: Uint8Array,
    config?: Partial<ResolvedIbexConfig>
  ) {
    if (initialChainKey.length !== 32) {
      throw new RatchetError('Initial chain key must be 32 bytes');
    }
    if (counter < 0) {
      throw new RatchetError('Counter must be non-negative');
    }

    this._counter = counter;
    this._currentChainKey = new Uint8Array(initialChainKey);
    this._config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Current ratchet counter (0-based, increments after each turn)
   */
  get counter(): number {
    return this._counter;
  }

  /**
   * Current chain key (for persistence)
   */
  get currentChainKey(): Uint8Array {
    return new Uint8Array(this._currentChainKey);
  }

  /**
   * Derive the encryption key from the current chain key
   * @param crypto - Crypto provider to use
   * @returns 32-byte encryption key
   */
  async getCurrentEncryptionKey(crypto: CryptoProvider): Promise<Uint8Array> {
    return crypto.blake2b256(
      this._currentChainKey,
      this._config.kdfPersonal,
      this._config.kdfSaltEncryptionKey,
      new Uint8Array(0)
    );
  }

  /**
   * Turn the ratchet once, deriving a new chain key
   * @param crypto - Crypto provider to use
   */
  async turn(crypto: CryptoProvider): Promise<void> {
    const newChainKey = await crypto.blake2b256(
      this._currentChainKey,
      this._config.kdfPersonal,
      this._config.kdfSaltChainKey,
      new Uint8Array(0)
    );

    // Zero out old key for forward secrecy
    this._currentChainKey.fill(0);
    this._currentChainKey = newChainKey;
    this._counter++;
  }

  /**
   * Turn the ratchet until it reaches the target counter
   * @param crypto - Crypto provider to use
   * @param targetCounter - Target counter value
   * @returns Number of turns performed
   * @throws RatchetError if target is behind current counter or too far ahead
   */
  async turnUntil(crypto: CryptoProvider, targetCounter: number): Promise<number> {
    if (targetCounter < this._counter) {
      throw new RatchetError(
        `Cannot turn ratchet backwards: current=${this._counter}, target=${targetCounter}`
      );
    }

    const numTurns = targetCounter - this._counter;
    if (numTurns > this._config.maxCounterIncrement) {
      throw new RatchetError(
        `Counter increment too large: ${numTurns} > ${this._config.maxCounterIncrement}`
      );
    }

    for (let i = 0; i < numTurns; i++) {
      await this.turn(crypto);
    }

    return numTurns;
  }

  /**
   * Create a copy of this ratchet (for persistence/testing)
   */
  clone(): KDFRatchet {
    return new KDFRatchet(this._counter, this._currentChainKey, this._config);
  }

  /**
   * Serialize the ratchet state for persistence
   */
  toJSON(): { counter: number; chainKey: number[] } {
    return {
      counter: this._counter,
      chainKey: Array.from(this._currentChainKey),
    };
  }

  /**
   * Restore a ratchet from serialized state
   */
  static fromJSON(
    data: { counter: number; chainKey: number[] },
    config?: Partial<ResolvedIbexConfig>
  ): KDFRatchet {
    return new KDFRatchet(
      data.counter,
      new Uint8Array(data.chainKey),
      config
    );
  }
}
