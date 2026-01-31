# @privatemessaging/ibex

A non-opinionated TypeScript implementation of the Threema Ibex forward secrecy protocol.

## Features

- **Forward Secrecy**: Each message uses a unique encryption key derived via KDF ratcheting
- **Pluggable Crypto**: Implement `CryptoProvider` to use your own crypto backend
- **Pluggable Storage**: Implement `IbexSessionStore` to use any storage backend
- **Configurable**: Override protocol constants (salts, personalization strings)
- **TypeScript**: Full type definitions included
- **ESM**: Modern ES modules, tree-shakeable

## Installation

```bash
npm install @privatemessaging/ibex
```

## Quick Start

```typescript
import {
  IbexProcessor,
  MemoryIbexSessionStore,
  IbexMessageType,
} from '@privatemessaging/ibex';
import { DefaultCryptoProvider } from '@privatemessaging/ibex/crypto';

// Setup
const crypto = new DefaultCryptoProvider();
const aliceStore = new MemoryIbexSessionStore();
const bobStore = new MemoryIbexSessionStore();

// Create identities (normally persisted)
const aliceKeys = await crypto.generateKeyPair();
const bobKeys = await crypto.generateKeyPair();

const alice = {
  identity: 'ALICE123',
  publicKey: aliceKeys.publicKey,
  privateKey: aliceKeys.privateKey,
};

const bob = {
  identity: 'BOB12345',
  publicKey: bobKeys.publicKey,
  privateKey: bobKeys.privateKey,
};

// Create processors
const aliceProcessor = new IbexProcessor({
  sessionStore: aliceStore,
  cryptoProvider: crypto,
});

const bobProcessor = new IbexProcessor({
  sessionStore: bobStore,
  cryptoProvider: crypto,
});

// Alice sends a message to Bob
const plaintext = new TextEncoder().encode('Hello, Bob!');
const result = await aliceProcessor.encapsulate(
  { identity: bob.identity, publicKey: bob.publicKey },
  alice,
  plaintext
);

// result.messages contains [Init, Message] for new sessions
// Store session after successful send
await aliceStore.store(result.session!.serialize());

// Bob processes Init
const init = result.messages[0]; // IbexInit
const accept = await bobProcessor.processInit(
  { identity: alice.identity, publicKey: alice.publicKey },
  bob,
  init
);

// Bob decrypts message
const message = result.messages[1]; // IbexMessage
const decrypted = await bobProcessor.processMessage(
  { identity: alice.identity, publicKey: alice.publicKey },
  bob,
  message
);

if ('plaintext' in decrypted) {
  console.log(new TextDecoder().decode(decrypted.plaintext));
  // "Hello, Bob!"

  // Commit ratchet after processing
  const commitResult = await bobProcessor.commitPeerRatchet(bob, decrypted.ratchetId);
  if (!commitResult.committed) {
    console.error('Failed to commit ratchet:', commitResult.reason);
  }
}

// Alice processes Accept to complete handshake
await aliceProcessor.processAccept(
  { identity: bob.identity, publicKey: bob.publicKey },
  alice,
  accept
);

// Now both parties can exchange 4DH messages
```

## Custom Crypto Provider

The default crypto provider uses `tweetnacl` and `@noble/hashes`, which are optional dependencies. If you implement your own `CryptoProvider`, you don't need these packages:

```typescript
import type { CryptoProvider, KeyPair } from '@privatemessaging/ibex';
// No need to install tweetnacl or @noble/hashes

class MyCryptoProvider implements CryptoProvider {
  async generateKeyPair(): Promise<KeyPair> {
    // Your implementation
  }

  async x25519(privateKey: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
    // X25519 key exchange
  }

  async blake2b256(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array> {
    // BLAKE2b-256 with personalization and salt
  }

  async blake2b512(
    key: Uint8Array | null,
    personal: string,
    salt: string,
    data: Uint8Array
  ): Promise<Uint8Array> {
    // BLAKE2b-512 with personalization and salt
  }

  async symmetricEncrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    // XSalsa20-Poly1305 encryption
  }

  async symmetricDecrypt(
    data: Uint8Array,
    key: Uint8Array,
    nonce: Uint8Array
  ): Promise<Uint8Array> {
    // XSalsa20-Poly1305 decryption
  }

  async randomBytes(length: number): Promise<Uint8Array> {
    // Cryptographically secure random bytes
  }
}
```

## Custom Storage Backend

Implement `IbexSessionStore` for persistent storage:

```typescript
import type { IbexSessionStore, SerializedIbexSession } from '@privatemessaging/ibex';
import type { IbexSessionId } from '@privatemessaging/ibex';

class SQLiteIbexSessionStore implements IbexSessionStore {
  async store(session: SerializedIbexSession): Promise<void> {
    // Save to SQLite
  }

  async get(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<SerializedIbexSession | null> {
    // Load from SQLite
  }

  async getBest(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession | null> {
    // Get best session (prefer RL44, then lowest ID)
  }

  async getAll(
    myIdentity: string,
    peerIdentity: string
  ): Promise<SerializedIbexSession[]> {
    // Get all sessions with peer
  }

  async delete(
    myIdentity: string,
    peerIdentity: string,
    sessionId: IbexSessionId
  ): Promise<boolean> {
    // Delete session
  }

  async deleteAllExcept(
    myIdentity: string,
    peerIdentity: string,
    exceptSessionId: IbexSessionId,
    keepL20Sessions: boolean
  ): Promise<number> {
    // Delete all sessions except one
  }

  async deleteAll(myIdentity: string, peerIdentity: string): Promise<number> {
    // Delete all sessions with peer
  }
}
```

## Custom Protocol Constants

Override Threema defaults for your own application:

```typescript
const processor = new IbexProcessor({
  sessionStore,
  cryptoProvider,
  config: {
    kdfPersonal: 'my-app',           // Default: "3ma-e2e"
    kdfSaltChainKey: 'my-ck',        // Default: "kdf-ck"
    kdfSaltEncryptionKey: 'my-aek',  // Default: "kdf-aek"
    keSalt2DHPrefix: 'my-2dh-',      // Default: "ke-2dh-"
    keSalt4DHPrefix: 'my-4dh-',      // Default: "ke-4dh-"
    maxCounterIncrement: 10000,      // Default: 25000
  },
});
```

## Session States

The protocol has four session states:

| State | Description |
|-------|-------------|
| `L20` | Locally initiated, outgoing 2DH only (awaiting Accept) |
| `R20` | Remotely initiated, incoming 2DH only (just received Init) |
| `R24` | Remotely initiated, incoming 2DH + outgoing 4DH |
| `RL44` | Full 4DH in both directions (normal state) |

## Events

Listen for session lifecycle events:

```typescript
const processor = new IbexProcessor({
  sessionStore,
  cryptoProvider,
  events: {
    onSessionInitiated(session, contact) {
      console.log(`New session with ${contact.identity}`);
    },
    onSessionEstablishedAsResponder(session, contact) {
      console.log(`Responded to ${contact.identity}`);
    },
    onSessionEstablishedAsInitiator(session, contact) {
      console.log(`Session complete with ${contact.identity}`);
    },
    onSessionTerminated(sessionId, contact, cause) {
      console.log(`Session terminated: ${cause}`);
    },
    onMessagesSkipped(sessionId, contact, count) {
      console.log(`Skipped ${count} messages`);
    },
    onFirst4DHMessageReceived(session, contact) {
      console.log(`First 4DH message from ${contact.identity}`);
    },
  },
});
```

## API Reference

### IbexProcessor

Main class for encryption/decryption and protocol handling.

- `encapsulate(contact, identityStore, plaintext)` - Encrypt a message
- `processInit(contact, identityStore, init)` - Handle Init message
- `processAccept(contact, identityStore, accept)` - Handle Accept message
- `processMessage(contact, identityStore, message)` - Decrypt a message
- `commitPeerRatchet(identityStore, ratchetId)` - Commit ratchet after processing (returns `CommitResult`)
- `processReject(identityStore, contact, reject)` - Handle Reject message
- `processTerminate(identityStore, contact, terminate)` - Handle Terminate message
- `clearAndTerminateAllSessions(identityStore, contact, cause)` - Clear all sessions

### IbexSession

Low-level session management.

- `IbexSession.createAsInitiator(contact, identityStore, crypto, config?)` - Create initiator session
- `IbexSession.createAsResponder(sessionId, versionRange, ephemeralPubKey, contact, identityStore, crypto, config?)` - Create responder session
- `session.processAccept(versionRange, ephemeralPubKey, contact, identityStore, crypto)` - Process Accept
- `session.serialize()` - Serialize for storage
- `IbexSession.restore(data, config?)` - Restore from storage

### KDFRatchet

Key derivation ratchet.

- `new KDFRatchet(counter, initialChainKey, config?)` - Create ratchet
- `ratchet.getCurrentEncryptionKey(crypto)` - Get encryption key
- `ratchet.turn(crypto)` - Turn ratchet once
- `ratchet.turnUntil(crypto, targetCounter)` - Turn to target counter

## License

MIT
