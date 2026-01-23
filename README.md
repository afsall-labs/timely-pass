# Timely Pass

Timely Pass is a comprehensive, composable, modular, and production-ready library and Command-Line Interface (CLI) tool for time-based password policies.

## Features

- **Time-based Policies**: Define policies using `onlyBefore`, `onlyAfter`, `onlyWithin`, and `onlyFor` hooks.
- **Secure Storage**: Credentials are stored in an encrypted file (XChaCha20Poly1305) with Argon2id derived keys.
- **Memory Safety**: Secrets are zeroed out in memory using `zeroize`.
- **Auditability**: Policies and evaluations are deterministic.
- **CLI**: Feature-complete CLI for managing credentials and policies.

## Installation

```bash
cargo install --path timely-pass-cli
```

## Usage

### Initialize Store

```bash
timely-pass init --store ~/.timely/store.db
```

### Add Credential

```bash
# Add a simple password
timely-pass add --id work-vpn --type password --secret

# Add with policy
timely-pass add --id limited-access --policy policy.toml --secret
```

### Policy Example (policy.toml)

```toml
id = "work-hours"
version = 1
clock_skew_secs = 60
single_use = false

[[hooks]]
type = "OnlyWithin"
[hooks.period]
type = "Range"
start = "2024-01-01T09:00:00Z"
end = "2024-01-01T17:00:00Z"
```

### Get Credential

```bash
timely-pass get --id work-vpn
```

### Evaluate Policy (Dry Run)

```bash
timely-pass eval --policy policy.toml --time "2024-01-01T10:00:00Z"
```

### Rotate Credential

```bash
timely-pass rotate --id work-vpn
```

## Security

- **Encryption**: XChaCha20Poly1305
- **KDF**: Argon2id
- **Key Derivation**: HKDF
- **Zeroization**: All secrets are zeroized on drop.

## License

MIT
