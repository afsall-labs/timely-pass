# Timely Pass — Product Requirements Document (PRD)

**Author:** Muhammad Bashir Sharif (Khalifa Balqaasem)
**Project:** Timely Pass (`timely-pass`) — Time-based password manager SDK + CLI
**Tech stack:** Rust (pure Rust), `ratatui` for CLI UI, `serde` for serialization, `chrono` or `time` for timestamps, `argon2`/`scrypt` for KDF, RustCrypto (AEAD, HKDF, HMAC), `zeroize` for secret cleanup.

---

## Summary / Vision

Timely Pass is a composable, modular, production-ready library and CLI that enable applications and users to define, manage, and enforce *time-based* password policies locally. It enables apps, files/folders, devices and services to rotate, accept, or reject authentication factors according to explicit policies built around time — both absolute (dates) and relative (durations). Security and auditability are first-class citizens: keys are cryptographically protected, secrets zeroed from memory, logs auditable, and the attack surface minimized.

The deliverables:

* `timely-pass-sdk` — a pure-Rust crate exposing a minimal, ergonomic API for applications to evaluate policies, generate and verify time-based passwords/credentials, and manage secrets.
* `timely-pass-cli` — a user-facing terminal application (using `ratatui`) to administer Timely Pass locally: create policies, create/permanently store encrypted secrets, protect/unprotect files, generate ephemeral tokens, visualize timelines, and integrate with local auth hooks (PAM optional).
* Optional integrations: PAM module (separate crate), FUSE/virtual filesystem bridge (optional component), OS keystore adapters (optional, platform-dependent).

---

## Key Concepts & Terminology

* **Period**: the fundamental time constraint type. A `Period` can be:

  * `Time`: a wall-clock instant or interval (e.g., 14:30 UTC),
  * `Date`: a calendar date or date-range (e.g., 2026-02-01 to 2026-02-10),
  * `Duration`: relative durations (e.g., next 4 hours).
* **Hook**: the primitives the system exposes to gate acceptance of a password. Hooks:

  1. `onlyBefore(period)`
  2. `onlyAfter(period)`
  3. `onlyWithin(period)` — accepts only if current time ∈ period
  4. `onlyFor(period)` — accepts for exactly the given *duration* after activation/creation
* **Policy**: a composable set of hooks and other constraints (time zone, clock skew tolerance, usage limits).
* **Authenticator / Credential**: secret material (password, key, token) tied to a policy and one or more mechanisms (password + OTP, HMAC token, ephemeral key).
* **Secret Store**: encrypted on-disk storage for long-term secrets, managed by the SDK, optionally backed by OS keystore.
* **Evaluation Engine**: small deterministic engine in the SDK that, given a `Policy` and an attempted credential usage time, returns accept/reject and audit metadata.
* **CLI**: management tool for both users and automation. Interactive `ratatui` UI and non-interactive flags for scripts.

---

## Design Principles

1. **Security-first**: minimize secret exposure, use modern AEAD primitives, zero memory after use, support hardware-backed keys optionally, and provide clear threat model + mitigations.
2. **Composability**: SDK should be a library with well-defined modules (policy, storage, crypto, evaluation), and minimal surface area for apps to embed.
3. **Determinism & Auditable**: policies and evaluations deterministic; logs are append-only and signed.
4. **Portability**: pure Rust, cross-platform (Linux, macOS, Windows). Platform-specific features (Keychain, DPAPI, Secret Service) are optional Cargo features.
5. **Low-dependency core**: keep the core small and dependency-light so it's easier to audit.
6. **Extensibility**: plugin points for authentication mechanisms, storage backends, UI widgets.

---

## High-level Architecture

```
+-------------------------------------------------------------+
| timely-pass-cli (ratatui)                                   |
|  - interactive UI                                            |
|  - scriptable subcommands                                    |
+-------------------------------------------------------------+
| timely-pass-sdk crate                                        |
|  - policy module                                             |
|  - evaluator engine                                          |
|  - crypto module (AEAD, KDF, HKDF)                           |
|  - storage module (file-backed encrypted store)              |
|  - integration adapters (optional features)                  |
+-------------------------------------------------------------+
| optional components                                          |
|  - PAM plugin (timely-pass-pam)                              |
|  - FUSE/virtual fs bridge                                    |
|  - OS keystore adapters                                      |
+-------------------------------------------------------------+
```

---

## Requirements

### Functional Requirements

1. **Policy Definition API (SDK)**

   * Programmatic ability to create, combine, serialize policies.
   * Policy must support:

     * `onlyBefore(Period)`
     * `onlyAfter(Period)`
     * `onlyWithin(Period)` (start + end)
     * `onlyFor(Period)` (duration after activation)
     * Optional constraints: allowed timezones, clock skew tolerance (e.g. 5s — 5min), max attempts, single-use toggle.
   * Policies must be serializable with versioning metadata (for future backward compatibility).
   * Provide policy DSL builder in Rust and textual representation in TOML/YAML/JSON for human editing.

2. **Credential Management**

   * Create/Update/Delete credentials bound to policies.
   * Credentials may be:

     * Static password (string),
     * Derived token (HMAC-SHA256 of timestamp + secret),
     * Ephemeral key pair generated and encrypted on-disk.
   * Support rotation policies (automatic rotation schedule or manual rotation).

3. **Evaluation / Verification**

   * Given a credential presented at time `t`, SDK returns:

     * Verdict: `Accept | Reject | Expired | NotYetValid | InvalidSignature | PolicyViolation`
     * Audit metadata: evaluation timestamp (UTC), matched hook(s), clock skew used, policy id/version.
   * Evaluator must be deterministic and side-effect-free (except logging when requested).

4. **Secure Storage**

   * Local file-backed encrypted store with the following properties:

     * AEAD encryption (e.g., `XChaCha20Poly1305` via `chacha20poly1305` crate).
     * Master key derived from user passphrase via Argon2id (configurable parameters) and HKDF for subkeys.
     * Optionally, use platform key stores if feature enabled (behind Cargo feature).
     * Secrets stored with metadata (creation_time, policy_id, labels, idempotent identifier).
     * Support for encrypted backups and export/import (with passphrase).
   * Store must support atomic writes, integrity checks, and crash-safe updates (use temp file + `fsync` + rename).

5. **CLI Features**

   * Commands:

     * `timely-pass init` — initialize store (create master key, set password policy).
     * `timely-pass add` — add credential with policy (interactive or flags).
     * `timely-pass get` — generate or retrieve credential (respecting policy).
     * `timely-pass eval` — evaluate an external presented credential against a policy (for integration/test).
     * `timely-pass rotate` — rotate credential or master key.
     * `timely-pass protect <path>` — create an encrypted wrapper for a file/folder or generate short-lived decrypt tokens; optionally integrate with OS-level locking.
     * `timely-pass audit` — show signed audit log.
     * `timely-pass ui` — launch interactive `ratatui` dashboard.
     * `timely-pass export|import` — encrypted export for migration.
     * `timely-pass status` — show store status (locked/unlocked, version).
   * Non-interactive flags for automation: `--yes`, `--format json`, `--output`.

6. **CLI UX**

   * `ratatui` interactive dashboard:

     * Timeline view showing policies, upcoming activations, rotations.
     * Credential list with filter by tag/expiry.
     * Visual calendar to create `onlyWithin` windows.
     * Confirmation modal for destructive actions.
   * Accessibility and keyboard shortcuts (explicit in UI spec).

7. **Integrations**

   * Optional PAM module for Linux to require time-gated password evaluation during login.
   * Optional FUSE-backed mount that only exposes decrypted files when a time-based token is active (documented as experimental).
   * Optional API for applications to call into SDK to evaluate credentials.

### Non-Functional Requirements

1. **Security**

   * Use AEAD primitives (e.g., `XChaCha20Poly1305`) for confidentiality + integrity.
   * Use Argon2id for master passphrase KDF with secure defaults (configurable).
   * All secrets zeroized in memory using `zeroize`.
   * No logs should ever contain plaintext secrets; redact by default.
   * Minimal attack surface (no network services run by default).
   * Signed audit logs using per-store logging key, encrypted & integrity-protected.
   * Optionally sign releases and provide reproducible build instructions.

2. **Reliability**

   * Atomic and crash-safe store operations.
   * Deterministic evaluation engine that can be unit tested.
   * Robust error handling and clear error codes.

3. **Performance**

   * Policy evaluation must be constant-time relative to policy size (practical small microsecond range).
   * KDF and crypto operations measured and tuned; Argon2 settings suggested per-platform in docs.
   * SDK must avoid blocking operations in evaluation paths; expose async API if disk IO required.

4. **Portability**

   * Support Linux, macOS, Windows (stable Rust).
   * Optional platform-specific features behind Cargo features.

5. **Auditability & Observability**

   * Signed, append-only audit logs.
   * Optional telemetry: opt-in only, privacy-preserving, aggregated.

---

## Security & Threat Model

### Assumptions

* Adversary may have access to user filesystem but not their passphrase.
* Adversary may attempt to tamper with store files, replay logs, or use clock changes.
* Host OS may be compromised — mitigations limited; hardware-backed keys recommended in that case.

### Threats & Mitigations

1. **Store theft**: Encrypted with AEAD + Argon2id-derived master key. Mitigation: strong passphrase + configurable Argon2 parameters. Document recommended parameters per-platform (e.g., memory=64MiB, time=3, lanes=4).
2. **Brute-force passphrase**: Use slow KDF, and rate limiting in CLI via sleep; warn users to use strong passphrases and optionally hardware key.
3. **Tampered store**: AEAD integrity checks ensure tampering detected.
4. **Replay / rollback attacks**: store versions and signed append-only logs; when importing, check monotonic counters.
5. **Clock manipulation**: include optional monotonic counters; allow configurable clock skew tolerance; advise using NTP or secure time sources if critical.
6. **Memory disclosure**: zeroize secrets; avoid using swap by recommending `mlock` on platforms supporting it (optional feature).
7. **Supply-chain**: reproducible builds recommended; minimal dependencies.

### Cryptography choices (recommended)

* **AEAD**: `XChaCha20Poly1305` (XChaCha20-Poly1305) via `chacha20poly1305` crate.
* **KDF**: `argon2` crate (Argon2id).
* **HMAC**: `hmac` + `sha2` crates.
* **HKDF**: `hkdf` crate for key separation.
* **Randomness**: use `rand` crate seeded from OS CSPRNG.
* **Zeroization**: `zeroize` crate.
* **Serialization**: `serde` + `serde_json` or `ron`/`bincode` for compact on-disk format (with versioning).

All cryptography primitives must be behind a single `crypto` module; unit tests must cover algorithm correctness and public test vectors where possible.

---

## SDK API — module & type outline

Below is a concise API sketch; this should be stable and ergonomic:

```rust
// crate: timely_pass_sdk

pub mod policy {
    use chrono::{DateTime, Utc};
    use serde::{Serialize, Deserialize};

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Period {
        Instant(DateTime<Utc>),
        Range { start: DateTime<Utc>, end: DateTime<Utc> },
        DurationSecs(u64), // duration in seconds
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub enum Hook {
        OnlyBefore(Period),
        OnlyAfter(Period),
        OnlyWithin(Period),
        OnlyFor(Period), // interpreted as duration anchored to creation/activation
    }

    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct Policy {
        pub id: String,
        pub hooks: Vec<Hook>,
        pub timezone: Option<String>, // e.g., "UTC" or IANA TZ
        pub clock_skew_secs: u64,
        pub max_attempts: Option<u32>,
        pub single_use: bool,
        pub version: u32,
    }

    impl Policy {
        pub fn builder() -> PolicyBuilder { /* ... */ }
        pub fn evaluate(&self, ctx: &EvaluationContext) -> PolicyEvaluation { /* ... */ }
    }
}

pub mod crypto {
    pub struct CryptoConfig { /* argon2 params, aead variant etc. */ }

    pub struct MasterKey(/* secret */);
    impl MasterKey {
        pub fn derive_from_passphrase(pass: &str, cfg: &CryptoConfig) -> Result<Self, Error>;
        pub fn derive_subkey(&self, info: &[u8]) -> [u8; 32];
    }
}

pub mod store {
    use super::policy::Policy;

    pub struct SecretStore { /* path, file lock, version, etc */ }

    impl SecretStore {
        pub fn init(path: impl AsRef<Path>, master: &crypto::MasterKey, cfg: &StoreConfig) -> Result<Self, Error>;
        pub fn open(path: impl AsRef<Path>, master: &crypto::MasterKey) -> Result<Self, Error>;
        pub fn add_credential(&mut self, cred: Credential) -> Result<CredentialId, Error>;
        pub fn get_credential(&self, id: &CredentialId) -> Result<Credential, Error>;
        pub fn rotate_credential(&mut self, id: &CredentialId, policy: Policy) -> Result<(), Error>;
        pub fn export_encrypted(&self, out: impl AsRef<Path>, passphrase: &str) -> Result<(), Error>;
    }
}

pub mod eval {
    use super::policy::Policy;
    pub struct EvaluationContext {
        pub now_utc: DateTime<Utc>,
        pub attempted_value: Option<String>,
    }
    pub enum Verdict { Accept, Reject, Expired, NotYetValid, InvalidSignature, PolicyViolation }
    pub struct PolicyEvaluation { pub verdict: Verdict, pub matched_hooks: Vec<String>, pub details: HashMap<String,String> }
}
```

* All secret-containing structs implement `Drop` + `zeroize`.
* Errors are typed with `thiserror` and explicit error codes for consumers.

---

## CLI: Commands & UX

### CLI Top-level commands & examples

* `timely-pass init --store ~/.timely-pass/store.db --passphrase`
  Initializes a new encrypted store.

* `timely-pass add --id work-vpn --type password --secret-from-prompt --policy-file vpn_policy.toml`
  Adds password bound to policy.

* `timely-pass get --id work-vpn --format json`
  Retrieves or generates credential if allowed; otherwise returns `403`-like verdict.

* `timely-pass protect --path ~/secrets.zip --policy-file temp_access.toml --out ~/secrets.enc`
  Create an encrypted wrapper requiring the specified policy to decrypt.

* `timely-pass eval --policy-file test_policy.toml --presented "hunter2" --time "2026-01-22T10:00:00Z"`
  Evaluate an external presented credential.

* `timely-pass rotate --id work-vpn --rotate-policy rotate.toml`
  Rotate credential with rotation metadata.

* `timely-pass ui`
  Launches `ratatui` interactive dashboard.

### Ratatui UI Screens (spec)

1. **Home Dashboard**

   * Left pane: credential list (searchable).
   * Right pane: calendar/timeline view with highlighted `onlyWithin` windows and upcoming rotations.
   * Bottom: status bar (store locked/unlocked, sync status).

2. **Credential Detail**

   * Metadata, policy summary, audit log for that credential.
   * Actions: `Show Secret` (requires confirmation + passphrase), `Rotate`, `Export`, `Delete`.

3. **Policy Builder**

   * Interactive forms to create hooks (datepicker, duration slider), preview textual policy and save to store.

4. **Audit Viewer**

   * Filter by time range, credential id, verdict.
   * Each row shows signed hash of audit entry; option to export logs.

Keyboard navigation and accessibility:

* `j/k` to move, `Enter` to open, `q` to quit, `/` to search.

---

## Data Formats & Storage Layout

* On-disk store file: root header with version, store UUID, KDF params, HKDF salt, and the encrypted payload blob.
* Per-credential entries inside encrypted payload include:

  * `id` (UUID)
  * `label`, `tags`
  * `created_at`, `updated_at`
  * `policy_id`
  * `secret_type` (password, hmac_key, keypair)
  * `secret_blob` (AEAD ciphertext)
  * `usage_counter`
* Exports: encrypted `.timely` files include metadata and integrity signature.

All serialized using `serde` + `bincode` or `cibor` for compactness. Include a human-readable `policy.toml` format for policy editing.

---

## Versioning, Backwards Compatibility & Migration

* Use semantic versioning for crate APIs.
* On-disk store version included in header. Upgrades must include migration code.
* Policy and credential objects include `version` numbers to allow rolling upgrades.
* Provide `timely-pass migrate` that reads older stores and migrates with a safe, logged process (creating backups automatically).

---

## Testing Strategy

* Unit tests for:

  * `Period` parsing and boundary conditions (midnight, leap seconds, DST transitions).
  * Policy evaluation edge cases (exact boundary, clock skew).
  * Serialization round trip for policies & credentials.
  * Crypto primitive wrappers against known test vectors.
* Integration tests:

  * Full store init/open/rotate flow in a temp FS.
  * CLI end-to-end with `assert_cmd`.
* Fuzz & property-based tests:

  * Use `proptest` for varied `Period`/`Hook` combinations.
  * Fuzz serialization inputs.
* Security testing:

  * Static analysis with `cargo-audit`.
  * Memory checks and sanitizer builds.
  * Optional third-party cryptography audit.
* CI:

  * GitHub Actions matrix for Linux (glibc + musl), macOS, Windows.
  * Run unit, integration, lint (`clippy`), formatting (`rustfmt`), `cargo-audit`.
  * Build artifacts: static binaries for Linux (musl), signed packages.

---

## Release & Packaging

* Use GitHub Releases. Sign releases with project GPG key; include reproducible build recipes.
* Provide pre-built binaries for:

  * Linux x86_64 (musl / glibc)
  * macOS universal
  * Windows x86_64
* Provide crate `timely-pass-sdk` published to crates.io; `timely-pass-cli` as separate crate.
* Package as:

  * `.deb`, `.rpm`, Homebrew formula, and Scoop/chocolatey manifests (community-maintained).
* Provide Docker image for CI use (no network services, just CLI).

---

## Developer Experience & Documentation

* API docs with `cargo doc`.
* Examples:

  * Minimal Rust app showing how to evaluate a policy.
  * Example `policy.toml` DSL with 10+ real-world examples (work VPN schedule, weekend-only admin password, one-time maintenance window).
* Cookbook:

  * Integrating Timely Pass into a service: call SDK to evaluate a presented credential before allowing operation.
  * Protecting a file: encrypt with `timely-pass protect` and present `timely-pass get` token to decrypt.
* Security guide:

  * Recommended Argon2 parameters per platform.
  * How to use hardware-backed keys.
  * Threat modeling guide and recommended mitigations.
* Migration guide and policy language reference.

---

## Policy Language (Human-editable)

Design a compact TOML-based policy format:

```toml
id = "vpn-weekday-9-5"
version = 1
timezone = "UTC"
clock_skew_secs = 60
max_attempts = 5
single_use = false

[[hooks]]
type = "onlyWithin"
start = "2026-01-01T09:00:00Z"
end = "2026-01-01T17:00:00Z"

# or relative
[[hooks]]
type = "onlyFor"
duration_secs = 7200  # after activation
```

SDK provides a parser and validator for the format.

---

## Extensibility & Plugins

* Storage backends trait (`SecretStoreBackend`) allowing in-process database, remote vault, or OS keyring adapters.
* Auth mechanisms trait (`Authenticator`) allowing RSA keys, YubiKey/CTAP, password, or OTP.
* CLI supports plugin executables: `timely-pass plugin run <plugin> --args` hooking into the UI.

---

## Operational Concerns

* **Backup & Recovery**: users must export an encrypted backup; provide `timely-pass backup --out` that creates signed backups and verifies on import.
* **Key Rotation**: support re-wrapping of secrets when master key changes.
* **Logging**: by default, only high-level events logged. Audit logs include cryptographic signature tied to store's log signing key.
* **Telemetry**: strictly opt-in; only non-identifying metadata, and documented.

---

## Performance & Benchmarks

* Provide benchmark targets and scripts (Criterion):

  * `policy_evaluation` times for 1, 10, 100 hooks (microseconds).
  * `aead_encrypt/decrypt` throughput for large blobs.
  * `argon2` KDF time given defaults; sample table for different Argon2 settings and hardware.
* Document realistic expectations and adjust KDF parameters based on machine class.

---

## Threat-Specific Notes & Operational Advice

* **Clock attacks**: If the host clock is manipulated by attacker, `onlyWithin` policies can be bypassed. Mitigations:

  * Allow server-sourced secure time for critical operations (optional remote attestation).
  * Use monotonic timers where applicable (for `onlyFor` anchored to local activation).
* **Replay of generated ephemeral tokens**: tokens include nonce + counter; tokens are single-use optionally enforced in store via incremented counters and audit entries.
* **Privilege escalation via CLI**: CLI must adhere to least privilege — file operations require explicit `--path` and confirmation for recursive ops.

---

## Migration / Adoption Path for Developers

1. Integrate `timely-pass-sdk` and evaluate existing credentials with `Policy::evaluate`.
2. For files, use `timely-pass-cli protect`; for services, call SDK APIs during authentication flows.
3. Optionally deploy PAM plugin for Linux desktops/servers.
4. Start with `monitor-only` mode: `timely-pass eval` logs violations instead of enforcing, to validate policies.

---

## Roadmap (MVP → v1.0 → future)

* **MVP**:

  * Core SDK (policy, evaluation, crypto, file-backed store).
  * CLI non-interactive features (`init`, `add`, `get`, `eval`, `export`).
  * Basic `ratatui` UI skeleton.
  * Tests + CI.

* **v1.0**:

  * Fully featured CLI UI.
  * Audit logs, backups, rotation, OS keystore optional adapters.
  * Documentation + example integrations, PAM plugin alpha.

* **Future**:

  * FUSE-backed decrypt-on-demand mount (experimental).
  * Hardware security module (HSM) integration & enterprise features.
  * Server-side policy synchronization (opt-in).
  * SDK language bindings (Go/Python) via FFI if needed.

---

## Implementation Checklist (Developer-ready)

* [ ] Create repository with crates: `timely-pass-sdk`, `timely-pass-cli`, `timely-pass-pam` (optional).
* [ ] Implement `policy` module + DSL parser, TOML policy examples.
* [ ] Implement `crypto` module (Argon2id KDF, HKDF, XChaCha20Poly1305 AEAD, HMAC).
* [ ] Implement `store` with atomic writes & unit tests.
* [ ] Implement `eval` deterministic engine + property tests.
* [ ] CLI base commands using `structopt`/`clap`.
* [ ] Integrate `ratatui` for UI screens (home/dashboard, policy builder, audit viewer).
* [ ] Add `zeroize` on secret containers.
* [ ] Add `cargo-audit` and CI pipeline with cross-matrix builds.
* [ ] Prepare documentation, developer guide, and security guide.
* [ ] Release process & signing keys.

---

## Appendix: Example Use Cases

1. **DevOps maintenance window**: Generate a credential valid `onlyWithin` Feb 1 02:00–04:00 UTC for a maintenance shell; credential automatically expires outside the window.

2. **Temporary file sharing**: Encrypt a file and grant `onlyFor` a 2-hour window after activation; the recipient must use timely-pass CLI to request the decryption token within that window.

3. **Workday VPN**: Password is accepted `onlyWithin` Mon-Fri 09:00–17:00 in local timezone; failed attempts >5 require admin review (audited).

4. **Emergency single-use admin**: Create `single_use = true` credential valid `onlyFor` 30 mins that, once used, is invalidated.

---

## Final Notes (Security & Production-readiness)

This PRD assumes strict adherence to modern cryptographic practices, secure defaults, and conservative optional features for hardware-backed keys and OS integrations. The SDK API must remain stable and minimal: consumers should be able to evaluate policies without depending on the CLI; CLI should be built on top of SDK. Every shipping artifact must be accompanied by documentation for secure parameter choices (Argon2, AEAD) and a clear migration/backup story. Automated tests (unit, property, integration), static auditing (`cargo-audit`), and reproducible builds are required before a v1.0 production release.

---

# Timely Pass — Ratatui UI Layout & Interaction Design

**UI framework:** Ratatui
**Target:** terminal-first power users, DevOps, security engineers
**Constraints:** keyboard-only, deterministic rendering, no mouse reliance

---

## 1. UI Architecture Overview

### 1.1 High-level UI model

The UI follows a **state-driven, screen-based architecture**:

```
App
 ├── GlobalState
 │    ├── store_status (locked/unlocked)
 │    ├── selected_credential
 │    ├── notification_queue
 │    └── clock (UTC + local)
 ├── Screen
 │    ├── Dashboard
 │    ├── CredentialList
 │    ├── CredentialDetail
 │    ├── PolicyBuilder
 │    ├── TimelineView
 │    ├── AuditLog
 │    └── Help
 └── Modal
      ├── Confirm
      ├── PassphrasePrompt
      ├── Error
      └── Info
```

**Design choice (important):**

* Screens are **full ownership views**.
* Modals are **stacked overlays**, never nested screens.
* No implicit navigation: every screen transition is explicit and logged.

This prevents UI state corruption—a common Ratatui failure mode.

---

## 2. Global Layout Skeleton

Every screen shares a common **root layout**.

```
┌──────────────────────────────────────────────────────────┐
│ Timely Pass │ Store: 🔓 Unlocked │ UTC 14:32 │ v0.1.0   │  ← Header
├──────────────────────────────────────────────────────────┤
│                                                          │
│                                                          │
│                    MAIN CONTENT                          │
│                                                          │
│                                                          │
├──────────────────────────────────────────────────────────┤
│ [H] Help  [/] Search  [Q] Quit  [↑↓←→] Navigate          │  ← Footer
└──────────────────────────────────────────────────────────┘
```

### 2.1 Header (fixed)

**Height:** 1 row
**Contents:**

* App name
* Store lock status (🔒 / 🔓)
* Current UTC time (authoritative)
* Version

**Reasoning:**
Time is core to Timely Pass. Showing UTC **always** avoids ambiguity.

---

### 2.2 Footer (fixed)

**Height:** 1 row
**Purpose:** contextual shortcuts

Footer contents change **per screen**, but must always show:

* Quit
* Help
* Navigation hint

---

## 3. Dashboard Screen (Default)

### Purpose

* High-level situational awareness
* Entry point for everything else

### Layout

```
┌───────────────┬─────────────────────────────────────────┐
│ Credentials   │ Timeline / Upcoming Windows             │
│ (List)        │                                         │
│               │   ── Now ──────────────────────▶        │
│ ▸ vpn-admin   │   [09:00 ─ 17:00] work-vpn               │
│   prod-db     │   [22:00 ─ 23:00] maintenance            │
│   temp-share  │                                         │
│               │                                         │
├───────────────┴─────────────────────────────────────────┤
│ Status: 3 active │ 1 expiring soon │ 2 locked            │
└─────────────────────────────────────────────────────────┘
```

### Widgets Used

* Left: `List`
* Right: custom `Canvas` or `Paragraph` (ASCII timeline)
* Bottom: `Paragraph` (status summary)

### Interaction

* `↑↓`: select credential
* `Enter`: open Credential Detail
* `T`: open full Timeline View
* `/`: filter credentials
* `A`: add credential

**Critical design note:**
Do **not** attempt pixel-perfect timelines. ASCII timelines with labels are more reliable and readable in terminals.

---

## 4. Credential List Screen (Focused Mode)

Used when users want to browse/search/manage credentials at scale.

```
┌──────────────────────────────────────────────────────────┐
│ Credentials (filter: "vpn")                              │
├──────────────────────────────────────────────────────────┤
│ ID            │ Type     │ Policy        │ Status        │
│───────────────┼──────────┼───────────────┼──────────────│
│ vpn-admin     │ Password │ weekday-9-5   │ ✔ Active     │
│ vpn-backup    │ HMAC     │ emergency     │ ⏳ Pending   │
│ temp-share-1  │ FileKey  │ 2h-only       │ ❌ Expired   │
│               │          │               │              │
└──────────────────────────────────────────────────────────┘
```

### Widgets

* `Table` with fixed column widths
* Row highlighting

### Keyboard Model

* `↑↓`: move row
* `Enter`: open Credential Detail
* `D`: delete (opens Confirm modal)
* `R`: rotate credential
* `E`: export credential
* `Esc`: back to Dashboard

**Performance note:**
Tables over ~500 rows should paginate. Do not attempt virtual scrolling initially.

---

## 5. Credential Detail Screen

This is where **security-sensitive actions** happen.

```
┌──────────────────────────────────────────────────────────┐
│ Credential: vpn-admin                                    │
├──────────────────────────────────────────────────────────┤
│ Metadata                                                 │
│ ─────────                                                │
│ ID: vpn-admin                                            │
│ Type: Password                                           │
│ Created: 2025-12-01T10:12Z                                │
│ Policy: weekday-9-5                                      │
│                                                         │
│ Policy Summary                                           │
│ ─────────────                                           │
│ ✔ onlyWithin 09:00 → 17:00 UTC                           │
│ ✖ single-use                                            │
│ ✔ max_attempts: 5                                       │
│                                                         │
├──────────────────────────────────────────────────────────┤
│ [S] Show Secret  [R] Rotate  [A] Audit Log  [Esc] Back   │
└──────────────────────────────────────────────────────────┘
```

### Security UX rules

* `Show Secret` **always** triggers:

  1. Passphrase modal
  2. Warning modal
  3. Timed reveal (e.g., auto-hide after 10s)

### Widgets

* Multiple `Paragraph`s
* Clear visual separators
* Icons (✔ ✖ ⏳ ❌) using Unicode (fallback ASCII if unsupported)

---

## 6. Policy Builder Screen (High-Complexity)

This is the hardest screen. It must be **structured**, not free-form.

### Layout

```
┌────────────────────┬───────────────────────────────────┐
│ Hooks               │ Policy Preview                    │
│                    │                                   │
│ [+] onlyWithin     │ id = "weekday-9-5"                │
│ [+] onlyBefore     │ timezone = "UTC"                  │
│ [+] onlyAfter      │                                   │
│ [+] onlyFor        │ [[hooks]]                          │
│                    │ type = "onlyWithin"               │
│                    │ start = "09:00"                   │
│                    │ end = "17:00"                     │
│                    │                                   │
├────────────────────┴───────────────────────────────────┤
│ [Tab] Switch  [Enter] Edit  [S] Save  [Esc] Cancel     │
└──────────────────────────────────────────────────────────┘
```

### Interaction Model

* Left pane: hook list
* Right pane: **read-only live preview** of TOML
* Editing a hook opens a modal:

```
┌──────── Edit onlyWithin ─────────┐
│ Start Time: [09:00      ]        │
│ End Time:   [17:00      ]        │
│ Timezone:   [UTC        ]        │
│                                  │
│ [Enter] Save   [Esc] Cancel      │
└──────────────────────────────────┘
```

**Design decision:**
Do NOT allow free-form text editing of policies in UI. That belongs in `$EDITOR`, not Ratatui.

---

## 7. Timeline View (Full-Screen)

Dedicated time visualization.

```
┌──────────────────────────────────────────────────────────┐
│ Timeline (UTC)                                           │
├──────────────────────────────────────────────────────────┤
│ 08:00 ──┬───────────────┬───────────────┬────────────── │
│         │ [vpn-admin]   │               │               │
│ 12:00 ──┼───────────────┼───────────────┼────────────── │
│         │               │ [maintenance] │               │
│ 16:00 ──┼───────────────┼───────────────┼────────────── │
│                                                         │
│ Selected: vpn-admin │ Active now: ✔                    │
└──────────────────────────────────────────────────────────┘
```

### Implementation

* Use `Canvas` with block coordinates
* Time grid fixed (hour resolution)
* Cursor highlights selected credential window

---

## 8. Audit Log Screen

Immutable, append-only view.

```
┌──────────────────────────────────────────────────────────┐
│ Audit Log (signed)                                       │
├──────────────────────────────────────────────────────────┤
│ Time (UTC)        │ Credential │ Result  │ Reason       │
│───────────────────┼────────────┼─────────┼──────────────│
│ 14:02:01          │ vpn-admin  │ ACCEPT  │ within-window│
│ 18:01:12          │ vpn-admin  │ REJECT  │ expired      │
│                   │            │         │              │
└──────────────────────────────────────────────────────────┘
```

* `Enter` on row opens detailed view (hash, signature, policy snapshot)
* No delete. Ever.

---

## 9. Modal System (Critical)

### Modal Types

1. Confirm (destructive actions)
2. Passphrase prompt
3. Error (fatal/non-fatal)
4. Info

### Modal Rules

* Always centered
* Blocks background input
* Explicit close keys only (`Enter`, `Esc`)
* Stack depth max = 1 (no nested modals)

---

## 10. Input & Navigation Summary

| Key     | Action             |
| ------- | ------------------ |
| `↑↓←→`  | Navigate           |
| `Enter` | Select / Open      |
| `Esc`   | Back / Close modal |
| `/`     | Search/filter      |
| `A`     | Add                |
| `R`     | Rotate             |
| `D`     | Delete (confirm)   |
| `T`     | Timeline           |
| `H`     | Help               |
| `Q`     | Quit               |

---

## 11. Implementation Guidance (Realistic)

### What Ratatui is good at

* Lists, tables, structured panels
* Deterministic redraws
* Keyboard-driven workflows

### What to avoid

* Free-form text editors
* Overly dynamic layouts
* Sub-second animation

### State Management

Use:

* `enum Screen`
* `enum Modal`
* Single `AppState` struct
* Reducer-style `handle_event(event, state)`

This prevents UI logic from bleeding into rendering.

---

## 12. Final Assessment (Blunt)

This UI:

* Is **implementable today** in Ratatui
* Avoids terminal UX traps
* Matches Timely Pass’s security posture
* Scales from personal use → professional ops
