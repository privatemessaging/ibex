# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.3] - 2026-01-31

### Fixed

- Wrap blake2b output in canonical `Uint8Array` to prevent tweetnacl type check failures in certain runtime environments

## [0.1.2] - 2026-01-31

### Fixed

- Replace dynamic imports with static imports in `DefaultCryptoProvider` to prevent Uint8Array type mismatch errors when consuming applications also import tweetnacl directly

## [0.1.1] - 2026-01-31

### Changed

- `commitPeerRatchet` now returns `CommitResult` instead of `void`, enabling callers to detect and handle failure cases (session not found, ratchet not found)

## [0.1.0] - 2026-01-31

### Added

- Initial release
- `IbexProcessor` for high-level message encryption/decryption
- `IbexSession` for low-level session management
- `KDFRatchet` for key derivation ratcheting
- `DefaultCryptoProvider` using tweetnacl and @noble/hashes
- `MemoryIbexSessionStore` for in-memory session storage
- Pluggable `CryptoProvider` interface for custom crypto backends
- Pluggable `IbexSessionStore` interface for custom storage backends
- Configurable protocol constants (salts, personalization strings)
- Session lifecycle events
- Full TypeScript type definitions
- ESM module support
