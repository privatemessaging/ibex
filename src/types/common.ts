/**
 * Protocol version encoding: major version in high byte, minor in low byte
 * e.g., 0x0100 = 1.0, 0x0101 = 1.1, 0x0102 = 1.2
 */
export type Version = number;

export const Version = {
  UNSPECIFIED: 0,
  V1_0: 0x0100,
  V1_1: 0x0101,
  V1_2: 0x0102,

  major(v: Version): number {
    return (v >> 8) & 0xff;
  },

  minor(v: Version): number {
    return v & 0xff;
  },

  create(major: number, minor: number): Version {
    return ((major & 0xff) << 8) | (minor & 0xff);
  },

  toString(v: Version): string {
    return `${Version.major(v)}.${Version.minor(v)}`;
  },
} as const;

export interface VersionRange {
  min: Version;
  max: Version;
}

/**
 * DH type indicating 2DH or 4DH encryption mode
 */
export enum DHType {
  TWODH = 1,
  FOURDH = 2,
}

/**
 * Ibex encryption mode for messages
 */
export enum IbexMode {
  NONE = 0,
  TWODH = 1,
  FOURDH = 2,
}

/**
 * Ibex session states
 */
export enum IbexSessionState {
  /** Locally initiated, outgoing 2DH only */
  L20 = 'L20',
  /** Remotely initiated, incoming 2DH only */
  R20 = 'R20',
  /** Remotely initiated, incoming 2DH + outgoing 4DH */
  R24 = 'R24',
  /** Full 4DH in both directions */
  RL44 = 'RL44',
}

/**
 * Configuration for Ibex protocol constants
 * All values have Threema-compatible defaults
 */
export interface IbexConfig {
  /** KDF personalization string (default: "3ma-e2e") */
  kdfPersonal?: string;
  /** Salt for deriving chain keys (default: "kdf-ck") */
  kdfSaltChainKey?: string;
  /** Salt for deriving encryption keys (default: "kdf-aek") */
  kdfSaltEncryptionKey?: string;
  /** Prefix for 2DH key exchange salt (default: "ke-2dh-") */
  keSalt2DHPrefix?: string;
  /** Prefix for 4DH key exchange salt (default: "ke-4dh-") */
  keSalt4DHPrefix?: string;
  /** Maximum ratchet turns allowed in one operation (default: 25000) */
  maxCounterIncrement?: number;
}

/**
 * Resolved configuration with all defaults applied
 */
export interface ResolvedIbexConfig {
  kdfPersonal: string;
  kdfSaltChainKey: string;
  kdfSaltEncryptionKey: string;
  keSalt2DHPrefix: string;
  keSalt4DHPrefix: string;
  maxCounterIncrement: number;
}

/**
 * Default Threema-compatible configuration values
 */
export const DEFAULT_CONFIG: ResolvedIbexConfig = {
  kdfPersonal: '3ma-e2e',
  kdfSaltChainKey: 'kdf-ck',
  kdfSaltEncryptionKey: 'kdf-aek',
  keSalt2DHPrefix: 'ke-2dh-',
  keSalt4DHPrefix: 'ke-4dh-',
  maxCounterIncrement: 25000,
};

/**
 * Resolve partial config to full config with defaults
 */
export function resolveConfig(config?: IbexConfig): ResolvedIbexConfig {
  return {
    ...DEFAULT_CONFIG,
    ...config,
  };
}
