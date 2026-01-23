# CLI Reference

The `timely-pass` CLI is the primary interface for managing your secure, time-based credentials.

## Global Options

- `--store <PATH>`: Path to the secret store file. Defaults to `store.timely` in the current directory.
- `-h, --help`: Print help information.
- `-V, --version`: Print version information.

---

## Commands

### `init`

Initializes a new encrypted secret store. You will be prompted to enter and confirm a strong passphrase.

**Usage:**
```bash
timely-pass init [--store <PATH>]
```

**Example:**
```bash
timely-pass init
# Output:
# Initializing new store at "store.timely"
# Enter passphrase: ...
```

---

### `add`

Adds a new credential to the store.

**Usage:**
```bash
timely-pass add [OPTIONS] --id <ID>
```

**Options:**
- `--id <ID>`: Unique identifier for the credential (e.g., "gmail-password", "aws-key").
- `--type <TYPE>`: Type of secret. Allowed values: `password`, `key`, `token`. Default: `password`.
- `--secret`: If specified, you will be prompted to enter the secret manually. If omitted, a secure 32-byte secret is generated automatically.
- `--policy <PATH>`: Path to a TOML policy file to associate with this credential.

**Examples:**
```bash
# Add a randomly generated API key
timely-pass add --id stripe-api-key --type key

# Add a password manually
timely-pass add --id facebook --type password --secret

# Add a token with a time-based policy
timely-pass add --id limited-access-token --type token --policy policies/weekend-only.toml
```

---

### `get`

Retrieves a credential's secret. This operation:
1. Decrypts the store.
2. Checks if the credential exists.
3. **Evaluates the associated policy** (if any). If the policy denies access (e.g., wrong time), the secret is NOT revealed.
4. Updates the credential's `usage_counter` and `updated_at` timestamp.
5. Prints the secret to stdout.

**Usage:**
```bash
timely-pass get --id <ID>
```

**Example:**
```bash
timely-pass get --id stripe-api-key
```

---

### `list`

Lists all stored credentials with their metadata (ID, Type, Creation Date). Does **not** reveal secrets.

**Usage:**
```bash
timely-pass list
```

**Example:**
```bash
timely-pass list
# Output:
# ID                   Type                 Created At
# -------------------- -------------------- ------------------------------
# stripe-api-key       Key                  2024-01-23 10:00:00 UTC
# facebook             Password             2024-01-23 10:05:00 UTC
```

---

### `remove`

Permanently deletes a credential from the store.

**Usage:**
```bash
timely-pass remove --id <ID>
```

**Example:**
```bash
timely-pass remove --id facebook
```

---

### `rotate`

Rotates a credential's secret. Generates a new random secret or prompts for one, replacing the old secret while preserving metadata and policy.

**Usage:**
```bash
timely-pass rotate --id <ID>
```

**Example:**
```bash
timely-pass rotate --id stripe-api-key
```

---

### `eval`

Evaluates a policy file against a specific time without accessing the store. Useful for testing and debugging policies.

**Usage:**
```bash
timely-pass eval --policy <PATH> [--time <ISO-8601>]
```

**Options:**
- `--policy <PATH>`: Path to the TOML policy file.
- `--time <ISO-8601>`: The timestamp to test against. Defaults to the current time (`now`).

**Example:**
```bash
timely-pass eval --policy policies/working-hours.toml --time "2024-01-23T20:00:00Z"
```

---

### `tui`

Launches the interactive Terminal User Interface. This provides a visual way to manage your store with keyboard shortcuts.

**Usage:**
```bash
timely-pass tui
```

**Key Bindings:**

| Key | Action |
| :--- | :--- |
| `a` | **Add** a new credential |
| `d` / `Delete` | **Delete** selected credential |
| `r` | **Rotate** secret for selected credential |
| `/` | **Search** / Filter list |
| `c` | **Copy** secret to clipboard |
| `Enter` | **Reveal/Hide** secret details |
| `Esc` | Cancel action / Clear search / Quit |
| `q` | Quit application |

