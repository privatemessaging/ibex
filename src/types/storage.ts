import type { IbexSessionId } from '../core/session-id.js';
import { IbexSessionState } from './common.js';
import type { Version } from './common.js';

/**
 * Serialized KDF ratchet state for persistence
 */
export interface SerializedRatchet {
  counter: number;
  chainKey: Uint8Array;
}

/**
 * Serialized Ibex session for persistence
 */
export interface SerializedIbexSession {
  /** Session identifier */
  id: IbexSessionId;
  /** Local identity (my identity) */
  myIdentity: string;
  /** Remote identity (peer identity) */
  peerIdentity: string;
  /** My ephemeral private key (null after Accept received) */
  myEphemeralPrivateKey: Uint8Array | null;
  /** My ephemeral public key */
  myEphemeralPublicKey: Uint8Array;
  /** Current negotiated versions (null before 4DH established) */
  current4DHVersions: { local: Version; remote: Version } | null;
  /** Timestamp of last outgoing message */
  lastOutgoingMessageTimestamp: number;
  /** My 2DH ratchet (outgoing in L20 state) */
  myRatchet2DH: SerializedRatchet | null;
  /** My 4DH ratchet (outgoing in R24/RL44 state) */
  myRatchet4DH: SerializedRatchet | null;
  /** Peer 2DH ratchet (incoming in R20/R24 state) */
  peerRatchet2DH: SerializedRatchet | null;
  /** Peer 4DH ratchet (incoming in R24/RL44 state) */
  peerRatchet4DH: SerializedRatchet | null;
}

/**
 * Storage interface for Ibex sessions
 *
 * Implementations can use any storage backend (in-memory, SQLite, IndexedDB, etc.)
 */
export interface IbexSessionStore {
  /**
   * Store or update an Ibex session
   * @param session - Session to store
   */
  store(session: SerializedIbexSession): Promise<void>;

  /**
   * Get a specific Ibex session by ID
   * @param myIdentity - Local identity
   * @param peerIdentity - Remote identity
   * @param sessionId - Session identifier
   * @returns Session if found, null otherwise
   */
  get(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<SerializedIbexSession | null>;

  /**
   * Get the best (lowest ID) Ibex session with a peer in RL44 state
   * Falls back to any session if none in RL44 state
   * @param myIdentity - Local identity
   * @param peerIdentity - Remote identity
   * @returns Best session if found, null otherwise
   */
  getBest(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession | null>;

  /**
   * Get all Ibex sessions with a peer
   * @param myIdentity - Local identity
   * @param peerIdentity - Remote identity
   * @returns Array of sessions
   */
  getAll(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession[]>;

  /**
   * Delete a specific Ibex session
   * @param myIdentity - Local identity
   * @param peerIdentity - Remote identity
   * @param sessionId - Session identifier
   * @returns true if session was deleted, false if not found
   */
  delete(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<boolean>;

  /**
   * Delete all sessions with a peer except one
   * @param myIdentity - Local identity
   * @param peerIdentity - Remote identity
   * @param exceptSessionId - Session to keep
   * @param keepL20Sessions - If true, also keep L20 (locally initiated) sessions
   * @returns Number of sessions deleted
   */
  deleteAllExcept(
    myIdentity: string,
    peerIdentity: string,
    exceptSessionId: IbexSessionId,
    keepL20Sessions: boolean
  ): Promise<number>;

  /**
   * Delete all sessions with a peer
   * @param myIdentity - Local identity
   * @param peerIdentity - Remote identity
   * @returns Number of sessions deleted
   */
  deleteAll(myIdentity: string, peerIdentity: string): Promise<number>;
}

/**
 * Determine session state from ratchet availability
 */
export function getSessionState(session: SerializedIbexSession): IbexSessionState {
  const { myRatchet2DH, myRatchet4DH, peerRatchet2DH, peerRatchet4DH } = session;

  if (!myRatchet2DH && myRatchet4DH && !peerRatchet2DH && peerRatchet4DH) {
    return IbexSessionState.RL44;
  }
  if (!myRatchet2DH && peerRatchet2DH && myRatchet4DH && peerRatchet4DH) {
    return IbexSessionState.R24;
  }
  if (myRatchet2DH && !myRatchet4DH && !peerRatchet2DH && !peerRatchet4DH) {
    return IbexSessionState.L20;
  }
  if (!myRatchet2DH && !myRatchet4DH && peerRatchet2DH && !peerRatchet4DH) {
    return IbexSessionState.R20;
  }

  throw new Error(
    `Invalid session state: my2DH=${!!myRatchet2DH}, my4DH=${!!myRatchet4DH}, ` +
      `peer2DH=${!!peerRatchet2DH}, peer4DH=${!!peerRatchet4DH}`
  );
}
