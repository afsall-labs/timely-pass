# Timely Pass

**Timely Pass** is a production-grade, composable, and modular Rust SDK and CLI tool for managing local, time-based password policies. It allows users and applications to define sophisticated rules for when credentials are valid, enforcing security constraints based on absolute time (dates) and relative time (durations).

Built with a "Security First" mindset, Timely Pass ensures strict cryptographic protection, secure memory handling, and auditability.

---

## 🚀 Features

- **Time-Based Policies**: Define complex validity rules using composable hooks:
  - `OnlyBefore`: Valid only before a specific date.
  - `OnlyAfter`: Valid only after a specific date.
  - `OnlyWithin`: Valid within a specific time range.
  - `OnlyFor`: Valid for a specific duration from creation or last use.
- **Secure Storage**:
  - Authenticated Encryption with Associated Data (AEAD) using **XChaCha20Poly1305**.
  - Master keys derived using **Argon2id** (memory-hard KDF).
  - Credentials stored in an encrypted, tamper-evident local file.
- **Memory Safety**:
  - Sensitive data (passwords, keys) are wrapped in `Secret` types.
  - Automatic memory zeroing (wiping) on drop using the `zeroize` crate.
- **Modular Design**:
  - **SDK**: A pure Rust library (`timely-pass-sdk`) for embedding in applications.
  - **CLI**: A feature-rich command-line tool (`timely-pass-cli`) for human interaction.
- **Auditability**: Deterministic policy evaluation with detailed verdicts.

---

## 📦 Installation

Ensure you have Rust and Cargo installed.

```bash
# Install from source
git clone https://github.com/yourusername/timely-pass.git
cd timely-pass
cargo install --path timely-pass-cli
```

Verify the installation:
```bash
timely-pass --help
```

---

## ⚡ Quick Start

### CLI Commands

#### 1. Initialize a Secret Store
Create a new encrypted store. You will be prompted to set a strong passphrase.
```bash
timely-pass init
# Default store is created at ./store.timely
```

### 2. Add a Credential
Add a password or API key. If you don't provide a secret, one will be securely generated for you.
```bash
# Add a generated key
timely-pass add --id api-key-prod --type key

# Add a specific password
timely-pass add --id email-password --type password --secret
```

### 3. Retrieve a Credential
Retrieve and decrypt a credential. This updates its usage counter and "last used" timestamp.
```bash
timely-pass get --id api-key-prod
```

### 4. Apply a Time-Based Policy
Create a policy file (e.g., `policy.toml`) to restrict access to business hours or a specific timeframe. You can also manage policies directly in the store using `timely-pass policy add`.

**policy.toml**:
```toml
id = "business-hours"
version = 1
clock_skew_secs = 60
single_use = false

[[hooks]]
type = "OnlyWithin"
[hooks.period]
type = "Range"
start = "2024-01-01T09:00:00Z"
end = "2025-01-01T17:00:00Z"
```

Add a credential with this policy:
```bash
timely-pass add --id restricted-token --type token --policy policy.toml
```

### 5. Evaluate Access
Check if a policy would allow access at a specific time (dry-run).
```bash
timely-pass eval --policy policy.toml --time "2024-06-01T12:00:00Z"
```

---

## 📚 Documentation

Detailed documentation is available in the [docs/](./docs/) directory:

- [**CLI Reference**](./docs/cli.md): Comprehensive guide to all CLI commands.
- [**Architecture**](./docs/architecture.md): High-level design, modules, and data flow.
- [**Security Model**](./docs/security.md): Cryptography, memory protection, and threat model.
- [**SDK Guide**](./docs/sdk.md): How to use the `timely-pass-sdk` in your Rust projects.

---

## 🛡️ Security

Timely Pass uses industry-standard cryptographic primitives:
- **XChaCha20Poly1305** for encryption (via `chacha20poly1305` crate).
- **Argon2id** for key derivation (via `argon2` crate).
- **Zeroize** for clearing secrets from memory.

See [Security Model](./docs/security.md) for details.

---

## 📄 License

TimelyPass is dual-licensed under [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).
