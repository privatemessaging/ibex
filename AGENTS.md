# @privatemessaging/ibex - Project Context

## Overview
Non-opinionated TypeScript implementation of the Threema Ibex forward secrecy protocol.

## Key Files
- `src/processor/ibex-processor.ts` - Main processor for encryption/decryption
- `src/core/ibex-session.ts` - Ibex session state machine
- `src/core/kdf-ratchet.ts` - KDF ratcheting for forward secrecy
- `src/crypto/default-provider.ts` - Default crypto using tweetnacl + @noble/hashes
- `src/storage/memory-store.ts` - In-memory session store
- `src/types/` - Type definitions for crypto, storage, messages, config

## Running Tests
```bash
npm test        # Run all tests
npm run typecheck  # Type check
```

## Design Decisions
- All protocol constants (salts, personalization) are configurable via `IbexConfig`
- Crypto and storage are interfaces - users can provide their own implementations
- ESM-only module format
- Async crypto interface to support WebCrypto, HSMs, etc.

## White Paper
- `https://threema.com/press-files/2_documentation/security_analysis_ibex_2023.pdf`

## Reference Implementation
- `https://github.com/threema-ch/threema-android` - Original Android/Java implementation
