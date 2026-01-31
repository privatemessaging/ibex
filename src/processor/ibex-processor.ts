import type { CryptoProvider } from '../types/crypto.js';
import type { IbexSessionStore } from '../types/storage.js';
import type { ResolvedIbexConfig } from '../types/common.js';
import {
  DHType,
  IbexMode,
  resolveConfig,
  Version,
} from '../types/common.js';
import type {
  IbexInit,
  IbexAccept,
  IbexReject,
  IbexTerminate,
  IbexMessage,
} from '../types/messages.js';
import {
  RejectCause,
  TerminateCause,
  createInit,
  createAccept,
  createReject,
  createTerminate,
  createMessage,
} from '../types/messages.js';
import { IbexSession, Contact, IdentityStore } from '../core/ibex-session.js';
import { IbexSessionId } from '../core/session-id.js';
import { CryptoConstants } from '../types/crypto.js';
import { zeroNonce } from '../utils/bytes.js';

/**
 * Result of decrypting an encapsulated message
 */
export interface DecryptionResult {
  /** Decrypted plaintext (type byte + body) */
  plaintext: Uint8Array;
  /** Forward security mode used */
  mode: IbexMode;
  /** Applied version */
  appliedVersion: Version;
  /** Info needed to commit the ratchet after processing */
  ratchetId: RatchetIdentifier;
}

/**
 * Identifies which ratchet was used for decryption
 */
export interface RatchetIdentifier {
  sessionId: IbexSessionId;
  peerIdentity: string;
  dhType: DHType;
}

/**
 * Result of committing a peer ratchet
 */
export type CommitResult =
  | { committed: true }
  | { committed: false; reason: 'session_not_found' | 'ratchet_not_found' };

/**
 * Result of encrypting a message
 */
export interface EncryptionResult {
  /** Encrypted message */
  message: IbexMessage;
  /** Updated session (must be persisted after send confirmed) */
  session: IbexSession;
}

/**
 * Result of running encapsulation steps
 */
export interface EncapsulationResult {
  /** Messages to send in order (may include Init before Message) */
  messages: (IbexInit | IbexMessage)[];
  /** Updated session (must be persisted after all messages sent) */
  session: IbexSession | null;
  /** Forward security mode of the main message */
  mode: IbexMode;
}

/**
 * Events emitted by the processor
 */
export interface IbexProcessorEvents {
  /** New session initiated by local party */
  onSessionInitiated?(session: IbexSession, contact: Contact): void;
  /** Session established as responder */
  onSessionEstablishedAsResponder?(session: IbexSession, contact: Contact): void;
  /** Session established as initiator (after Accept) */
  onSessionEstablishedAsInitiator?(session: IbexSession, contact: Contact): void;
  /** Session terminated */
  onSessionTerminated?(sessionId: IbexSessionId, contact: Contact, cause: TerminateCause): void;
  /** Messages were skipped (ratchet turned multiple times) */
  onMessagesSkipped?(sessionId: IbexSessionId, contact: Contact, count: number): void;
  /** First 4DH message received */
  onFirst4DHMessageReceived?(session: IbexSession, contact: Contact): void;
}

/**
 * Ibex Message Processor
 *
 * Handles encryption, decryption, and protocol message processing
 * for the Ibex forward secrecy protocol.
 */
export class IbexProcessor {
  private readonly store: IbexSessionStore;
  private readonly crypto: CryptoProvider;
  private readonly config: ResolvedIbexConfig;
  private readonly events: IbexProcessorEvents;

  constructor(options: {
    sessionStore: IbexSessionStore;
    cryptoProvider: CryptoProvider;
    config?: Partial<ResolvedIbexConfig>;
    events?: IbexProcessorEvents;
  }) {
    this.store = options.sessionStore;
    this.crypto = options.cryptoProvider;
    this.config = resolveConfig(options.config);
    this.events = options.events ?? {};
  }

  /**
   * Run forward security encapsulation steps for a message
   *
   * Returns messages to send (may include Init) and the updated session
   * to persist after successful send.
   */
  async encapsulate(
    contact: Contact,
    identityStore: IdentityStore,
    plaintext: Uint8Array
  ): Promise<EncapsulationResult> {
    const messages: (IbexInit | IbexMessage)[] = [];

    // Get or create session
    let session = await this.getBestSession(identityStore.identity, contact.identity);

    if (!session) {
      // Create new session
      session = await IbexSession.createAsInitiator(contact, identityStore, this.crypto, this.config);

      // Create Init message
      const init = createInit(
        session.id,
        IbexSession.getSupportedVersionRange(),
        session.myEphemeralPublicKey
      );
      messages.push(init);

      this.events.onSessionInitiated?.(session, contact);
    }

    // Encapsulate the message
    const encrypted = await this.encapsulateInSession(session, plaintext);
    messages.push(encrypted.message);

    // Update timestamp
    session.lastOutgoingMessageTimestamp = Date.now();

    return {
      messages,
      session: encrypted.session,
      mode: encrypted.message.dhType === DHType.FOURDH
        ? IbexMode.FOURDH
        : IbexMode.TWODH,
    };
  }

  /**
   * Encapsulate a message in an existing session
   */
  private async encapsulateInSession(
    session: IbexSession,
    plaintext: Uint8Array
  ): Promise<EncryptionResult> {
    // Determine which ratchet to use
    let ratchet = session.myRatchet4DH;
    let dhType = DHType.FOURDH;

    if (!ratchet) {
      ratchet = session.myRatchet2DH;
      dhType = DHType.TWODH;

      if (!ratchet) {
        throw new Error('No outgoing ratchet available');
      }
    }

    // Get encryption key and turn ratchet
    const encryptionKey = await ratchet.getCurrentEncryptionKey(this.crypto);
    const counter = ratchet.counter;
    await ratchet.turn(this.crypto);

    // Encrypt with zero nonce (safe because key is unique per message)
    const nonce = zeroNonce(CryptoConstants.NONCE_BYTES);
    const ciphertext = await this.crypto.symmetricEncrypt(plaintext, encryptionKey, nonce);

    // Determine versions
    const versions = session.current4DHVersions;
    const offeredVersion = versions?.local ?? Version.V1_0;
    const appliedVersion = versions?.local ?? Version.V1_0;

    const message = createMessage(
      session.id,
      dhType,
      counter,
      offeredVersion,
      appliedVersion,
      ciphertext
    );

    return { message, session };
  }

  /**
   * Process an Init message (received as responder)
   */
  async processInit(
    contact: Contact,
    identityStore: IdentityStore,
    init: IbexInit
  ): Promise<IbexAccept | IbexTerminate> {
    // Check if we already have this session
    const existing = await this.store.get(
      identityStore.identity,
      contact.identity,
      init.sessionId
    );
    if (existing) {
      // Silently ignore duplicate Init
      return createTerminate(init.sessionId, TerminateCause.UNKNOWN_SESSION);
    }

    // Delete any existing 4DH sessions (keep L20 for race conditions)
    await this.store.deleteAllExcept(
      identityStore.identity,
      contact.identity,
      init.sessionId,
      true // Keep L20 sessions
    );

    try {
      // Create session as responder
      const session = await IbexSession.createAsResponder(
        init.sessionId,
        init.versionRange,
        init.ephemeralPublicKey,
        contact,
        identityStore,
        this.crypto,
        this.config
      );

      session.lastOutgoingMessageTimestamp = Date.now();

      // Store session
      await this.store.store(session.serialize());

      this.events.onSessionEstablishedAsResponder?.(session, contact);

      // Return Accept
      return createAccept(
        init.sessionId,
        IbexSession.getSupportedVersionRange(),
        session.myEphemeralPublicKey
      );
    } catch (error) {
      // Version negotiation failed or other error
      return createTerminate(init.sessionId, TerminateCause.DISABLED_BY_LOCAL);
    }
  }

  /**
   * Process an Accept message (received as initiator)
   */
  async processAccept(
    contact: Contact,
    identityStore: IdentityStore,
    accept: IbexAccept
  ): Promise<void> {
    const serialized = await this.store.get(
      identityStore.identity,
      contact.identity,
      accept.sessionId
    );

    if (!serialized) {
      throw new Error(`Session not found: ${accept.sessionId.toHex()}`);
    }

    const session = IbexSession.restore(serialized, this.config);

    await session.processAccept(
      accept.versionRange,
      accept.ephemeralPublicKey,
      contact,
      identityStore,
      this.crypto
    );

    await this.store.store(session.serialize());

    this.events.onSessionEstablishedAsInitiator?.(session, contact);
  }

  /**
   * Process an encapsulated message
   */
  async processMessage(
    contact: Contact,
    identityStore: IdentityStore,
    message: IbexMessage
  ): Promise<DecryptionResult | IbexReject> {
    const serialized = await this.store.get(
      identityStore.identity,
      contact.identity,
      message.sessionId
    );

    if (!serialized) {
      return createReject(
        message.sessionId,
        new Uint8Array(16), // TODO: actual message ID
        RejectCause.UNKNOWN_SESSION,
        message.groupIdentity
      );
    }

    const session = IbexSession.restore(serialized, this.config);

    // Get appropriate ratchet
    const ratchet = message.dhType === DHType.TWODH
      ? session.peerRatchet2DH
      : session.peerRatchet4DH;

    if (!ratchet) {
      return createReject(
        message.sessionId,
        new Uint8Array(16),
        RejectCause.STATE_MISMATCH,
        message.groupIdentity
      );
    }

    // Turn ratchet to match counter
    try {
      const numSkipped = await ratchet.turnUntil(this.crypto, message.counter);
      if (numSkipped > 0) {
        this.events.onMessagesSkipped?.(message.sessionId, contact, numSkipped);
      }
    } catch (error) {
      return createReject(
        message.sessionId,
        new Uint8Array(16),
        RejectCause.STATE_MISMATCH,
        message.groupIdentity
      );
    }

    // Decrypt
    const encryptionKey = await ratchet.getCurrentEncryptionKey(this.crypto);
    const nonce = zeroNonce(CryptoConstants.NONCE_BYTES);

    let plaintext: Uint8Array;
    try {
      plaintext = await this.crypto.symmetricDecrypt(message.encryptedData, encryptionKey, nonce);
    } catch (error) {
      return createReject(
        message.sessionId,
        new Uint8Array(16),
        RejectCause.STATE_MISMATCH,
        message.groupIdentity
      );
    }

    // Handle first 4DH message (counter=0 is the first message with 0-based counters)
    if (message.dhType === DHType.FOURDH && ratchet.counter === 0) {
      this.events.onFirst4DHMessageReceived?.(session, contact);
    }

    // If 4DH message and we still have peer 2DH ratchet, discard it
    if (message.dhType === DHType.FOURDH && session.peerRatchet2DH) {
      session.discardPeerRatchet2DH();
    }

    // Save session (ratchet not yet turned - will be turned by commitPeerRatchet)
    await this.store.store(session.serialize());

    const mode = message.dhType === DHType.FOURDH
      ? IbexMode.FOURDH
      : IbexMode.TWODH;

    return {
      plaintext,
      mode,
      appliedVersion: message.appliedVersion,
      ratchetId: {
        sessionId: message.sessionId,
        peerIdentity: contact.identity,
        dhType: message.dhType,
      },
    };
  }

  /**
   * Commit the peer ratchet after message processing is complete.
   *
   * Returns a result indicating whether the commit succeeded. A failed commit
   * means the ratchet state may be desynchronized - the sender has advanced
   * their counter but this receiver has not.
   */
  async commitPeerRatchet(
    identityStore: IdentityStore,
    ratchetId: RatchetIdentifier
  ): Promise<CommitResult> {
    const serialized = await this.store.get(
      identityStore.identity,
      ratchetId.peerIdentity,
      ratchetId.sessionId
    );

    if (!serialized) {
      return { committed: false, reason: 'session_not_found' };
    }

    const session = IbexSession.restore(serialized, this.config);
    const ratchet = ratchetId.dhType === DHType.TWODH
      ? session.peerRatchet2DH
      : session.peerRatchet4DH;

    if (!ratchet) {
      return { committed: false, reason: 'ratchet_not_found' };
    }

    await ratchet.turn(this.crypto);
    await this.store.store(session.serialize());
    return { committed: true };
  }

  /**
   * Process a Reject message
   */
  async processReject(
    identityStore: IdentityStore,
    contact: Contact,
    reject: IbexReject
  ): Promise<void> {
    // Delete the session
    await this.store.delete(
      identityStore.identity,
      contact.identity,
      reject.sessionId
    );

    this.events.onSessionTerminated?.(reject.sessionId, contact, TerminateCause.RESET);
  }

  /**
   * Process a Terminate message
   */
  async processTerminate(
    identityStore: IdentityStore,
    contact: Contact,
    terminate: IbexTerminate
  ): Promise<void> {
    await this.store.delete(
      identityStore.identity,
      contact.identity,
      terminate.sessionId
    );

    this.events.onSessionTerminated?.(terminate.sessionId, contact, terminate.cause);
  }

  /**
   * Clear and terminate all sessions with a contact
   */
  async clearAndTerminateAllSessions(
    identityStore: IdentityStore,
    contact: Contact,
    cause: TerminateCause
  ): Promise<IbexTerminate[]> {
    const sessions = await this.store.getAll(identityStore.identity, contact.identity);
    const terminates: IbexTerminate[] = [];

    for (const session of sessions) {
      terminates.push(createTerminate(session.id, cause));
      this.events.onSessionTerminated?.(session.id, contact, cause);
    }

    await this.store.deleteAll(identityStore.identity, contact.identity);

    return terminates;
  }

  /**
   * Get the best session for a contact
   */
  private async getBestSession(
    myIdentity: string,
    peerIdentity: string
  ): Promise<IbexSession | null> {
    const serialized = await this.store.getBest(myIdentity, peerIdentity);
    if (!serialized) {
      return null;
    }
    return IbexSession.restore(serialized, this.config);
  }
}
