import type { IbexSessionId } from '../core/session-id.js';
import type { DHType, Version, VersionRange } from './common.js';

/**
 * Ibex control message types
 */
export enum IbexMessageType {
  INIT = 'init',
  ACCEPT = 'accept',
  REJECT = 'reject',
  TERMINATE = 'terminate',
  MESSAGE = 'message',
}

/**
 * Reason for rejecting a message
 */
export enum RejectCause {
  /** Session ID is unknown */
  UNKNOWN_SESSION = 1,
  /** State mismatch (e.g., 4DH message in 2DH-only session) */
  STATE_MISMATCH = 2,
}

/**
 * Reason for terminating a session
 */
export enum TerminateCause {
  /** Session is being reset by user */
  RESET = 1,
  /** Session ID is unknown */
  UNKNOWN_SESSION = 2,
  /** Forward security disabled by local party */
  DISABLED_BY_LOCAL = 3,
  /** Forward security disabled by remote party */
  DISABLED_BY_REMOTE = 4,
}

/**
 * Base interface for all Ibex messages
 */
export interface IbexMessageBase {
  type: IbexMessageType;
  sessionId: IbexSessionId;
}

/**
 * Init message - sent to initiate a new session
 */
export interface IbexInit extends IbexMessageBase {
  type: IbexMessageType.INIT;
  /** Supported version range */
  versionRange: VersionRange;
  /** Ephemeral public key (32 bytes) */
  ephemeralPublicKey: Uint8Array;
}

/**
 * Accept message - response to Init
 */
export interface IbexAccept extends IbexMessageBase {
  type: IbexMessageType.ACCEPT;
  /** Supported version range */
  versionRange: VersionRange;
  /** Ephemeral public key (32 bytes) */
  ephemeralPublicKey: Uint8Array;
}

/**
 * Reject message - reject an encapsulated message
 */
export interface IbexReject extends IbexMessageBase {
  type: IbexMessageType.REJECT;
  /** ID of the rejected message */
  rejectedMessageId: Uint8Array;
  /** Reason for rejection */
  cause: RejectCause;
  /** Optional group identity if rejecting a group message */
  groupIdentity?: GroupIdentity;
}

/**
 * Terminate message - end a session
 */
export interface IbexTerminate extends IbexMessageBase {
  type: IbexMessageType.TERMINATE;
  /** Reason for termination */
  cause: TerminateCause;
}

/**
 * Encapsulated message - contains encrypted inner message
 */
export interface IbexMessage extends IbexMessageBase {
  type: IbexMessageType.MESSAGE;
  /** DH type (2DH or 4DH) */
  dhType: DHType;
  /** Ratchet counter */
  counter: number;
  /** Offered version (max supported) */
  offeredVersion: Version;
  /** Applied version (actually used) */
  appliedVersion: Version;
  /** Optional group identity */
  groupIdentity?: GroupIdentity;
  /** Encrypted message payload */
  encryptedData: Uint8Array;
}

/**
 * Group identity for group messages
 */
export interface GroupIdentity {
  /** Group creator's identity */
  creatorIdentity: string;
  /** Group ID */
  groupId: Uint8Array;
}

/**
 * Union type for all Ibex messages
 */
export type IbexControlMessage = IbexInit | IbexAccept | IbexReject | IbexTerminate | IbexMessage;

/**
 * Create an Init message
 */
export function createInit(
  sessionId: IbexSessionId,
  versionRange: VersionRange,
  ephemeralPublicKey: Uint8Array
): IbexInit {
  return {
    type: IbexMessageType.INIT,
    sessionId,
    versionRange,
    ephemeralPublicKey: new Uint8Array(ephemeralPublicKey),
  };
}

/**
 * Create an Accept message
 */
export function createAccept(
  sessionId: IbexSessionId,
  versionRange: VersionRange,
  ephemeralPublicKey: Uint8Array
): IbexAccept {
  return {
    type: IbexMessageType.ACCEPT,
    sessionId,
    versionRange,
    ephemeralPublicKey: new Uint8Array(ephemeralPublicKey),
  };
}

/**
 * Create a Reject message
 */
export function createReject(
  sessionId: IbexSessionId,
  rejectedMessageId: Uint8Array,
  cause: RejectCause,
  groupIdentity?: GroupIdentity
): IbexReject {
  return {
    type: IbexMessageType.REJECT,
    sessionId,
    rejectedMessageId: new Uint8Array(rejectedMessageId),
    cause,
    groupIdentity,
  };
}

/**
 * Create a Terminate message
 */
export function createTerminate(
  sessionId: IbexSessionId,
  cause: TerminateCause
): IbexTerminate {
  return {
    type: IbexMessageType.TERMINATE,
    sessionId,
    cause,
  };
}

/**
 * Create an encapsulated Message
 */
export function createMessage(
  sessionId: IbexSessionId,
  dhType: DHType,
  counter: number,
  offeredVersion: Version,
  appliedVersion: Version,
  encryptedData: Uint8Array,
  groupIdentity?: GroupIdentity
): IbexMessage {
  return {
    type: IbexMessageType.MESSAGE,
    sessionId,
    dhType,
    counter,
    offeredVersion,
    appliedVersion,
    encryptedData: new Uint8Array(encryptedData),
    groupIdentity,
  };
}
