# Timely Pass CLI

The `timely-pass-cli` is the official command-line interface for the Timely Pass system. It provides a robust suite of tools to manage your secure, time-based credential store directly from your terminal.

## 🚀 Features

- **Full CRUD Operations**: Create, Read, Update, Delete credentials securely.
- **Policy Management**: Associate complex time-based policies with credentials.
- **Secure Defaults**: Automatic secure secret generation and encrypted storage.
- **Cross-Platform**: Runs on Windows, macOS, and Linux.

## 📦 Installation

```bash
cargo install --path .
```

## 🖥️ Usage

```bash
# Initialize a new store
timely-pass init

# Add a new credential
timely-pass add --id my-secret --type password --secret

# Get a credential (subject to policy)
timely-pass get --id my-secret

# List all credentials
timely-pass list

# Rotate a credential's secret
timely-pass rotate --id my-secret --new-secret "new-super-secure-password"

# Remove a credential
timely-pass remove --id my-secret

# Manage Policies
# Add a policy to the store
timely-pass policy add --id business-hours --path ./policy.toml

# List stored policies
timely-pass policy list

# Evaluate a policy against a time
timely-pass eval --policy ./policy.toml --time "2024-01-01T12:00:00Z"

# Upgrade the CLI
# Upgrade to the latest version
timely-pass upgrade

# Upgrade to a specific version
timely-pass upgrade --version 0.2.0
```

## 🛡️ Security

- **Visual Privacy**: Secrets are masked by default (`****************`) and only revealed explicitly.
- **Memory Safety**: The CLI leverages the SDK's secure memory handling to ensure secrets don't linger in RAM.

## 📄 License

TimelyPass is dual-licensed under [Apache-2.0](LICENSE-APACHE) and [MIT](LICENSE-MIT).
