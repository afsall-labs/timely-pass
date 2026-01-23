# CLI Reference

The `timely-pass` CLI is the primary interface for managing your secure, time-based credentials and policies.

## Global Options

- `--store <PATH>`: Path to the secret store file. Defaults to `store.timely` in the current directory.
- `-h, --help`: Print help information.
- `-V, --version`: Print version information.

---

## Credential Commands

### `init`

Initializes a new encrypted secret store. You will be prompted to enter and confirm a strong passphrase.

**Usage:**
```bash
timely-pass init [--store <PATH>]
```

**Example: Creating a New Store**
```bash
timely-pass init
# Output:
# Initializing new store at "store.timely"
# Enter passphrase: ...
```

**Example: Creating a Store at a Custom Path**
```bash
timely-pass init --store ./secure/my-secrets.timely
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
- `--policy <PATH>`: Path to a policy file (JSON or TOML) to associate with this credential.

**Example: Adding a Randomly Generated API Key**
```bash
timely-pass add --id stripe-api-key --type key
# A secure secret will be generated and stored automatically.
```

**Example: Adding a Password Manually**
```bash
timely-pass add --id facebook --type password --secret
# You will be prompted to enter the password hiddenly.
```

**Example: Adding a Token with a Time-Based Policy**
```bash
timely-pass add --id limited-access-token --type token --policy policies/weekend-only.json
# Associates the credential with the specified policy rules.
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

**Example: Retrieving an API Key**
```bash
timely-pass get --id stripe-api-key
# Output:
# <decrypted_secret_value>
```

**Example: Retrieving a Credential from a Custom Store**
```bash
timely-pass get --id aws-root-key --store ./prod-store.timely
```

---

### `list`

Lists all stored credentials with their metadata (ID, Type, Creation Date). Does **not** reveal secrets.

**Usage:**
```bash
timely-pass list
```

**Example: Listing All Credentials**
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

**Example: Removing a Social Media Password**
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

**Example: Rotating an API Key**
```bash
timely-pass rotate --id stripe-api-key
# The old secret is overwritten with a new secure random value.
```

---

## Policy Commands

### `policy add`

Adds a new policy or updates an existing one from a file definition.

**Usage:**
```bash
timely-pass policy add --file <PATH> [--id <ID>]
```

**Options:**
- `--file <PATH>`: Path to the policy definition file (JSON or TOML).
- `--id <ID>`: (Optional) Override the policy ID defined in the file.

**Example Policy File (policy.json):**
```json
{
  "id": "work-hours",
  "hooks": [
    {
      "type": "onlyWithin",
      "period": {
        "type": "range",
        "start": "2024-01-01T09:00:00Z",
        "end": "2024-12-31T17:00:00Z"
      }
    }
  ],
  "clockSkewSecs": 60,
  "enabled": true,
  "version": 1
}
```

**Example: Adding a Work Hours Policy**
```bash
timely-pass policy add --file policy.json
```

**Example: Adding a Policy with a Custom ID**
```bash
timely-pass policy add --file generic-policy.json --id specialized-policy-v2
```

---

### `policy list`

Lists all stored policies.

**Usage:**
```bash
timely-pass policy list
```

**Example: Listing All Policies**
```bash
timely-pass policy list
# Output:
# ID                   Version    Hooks
# -------------------- ---------- ----------
# work-hours           1          1
# weekend-access       2          1
```

---

### `policy get`

Retrieves and displays the full details of a specific policy in JSON format.

**Usage:**
```bash
timely-pass policy get --id <ID>
```

**Example: Inspecting the 'work-hours' Policy**
```bash
timely-pass policy get --id work-hours
```

---

### `policy remove`

Permanently deletes a policy from the store.

**Usage:**
```bash
timely-pass policy remove --id <ID>
```

**Example: Deleting the 'work-hours' Policy**
```bash
timely-pass policy remove --id work-hours
```

---

### `policy update`

Updates specific attributes of an existing policy without needing to re-upload the full definition file.

**Usage:**
```bash
timely-pass policy update --id <ID> [FLAGS]
```

**Options:**
- `--enable` / `--disable`: Enable or disable the policy.
- `--skew <SECONDS>`: Set the clock skew tolerance in seconds.
- `--timezone <TZ>`: Set the timezone (e.g., "UTC", "America/New_York").
- `--max-attempts <NUM>`: Set the maximum allowed access attempts.
- `--single-use` / `--multi-use`: Toggle single-use mode.

**Example: Disabling a Policy Temporarily**
```bash
timely-pass policy update --id work-hours --disable
```

**Example: Updating Clock Skew and Timezone**
```bash
timely-pass policy update --id work-hours --skew 120 --timezone "America/New_York"
```

**Example: Enforcing Single-Use on a Token Policy**
```bash
timely-pass policy update --id one-time-token --single-use
```

---

## Utility Commands

### `eval`

Evaluates a policy file against a specific time without accessing the store. Useful for testing and debugging policies.

**Usage:**
```bash
timely-pass eval --policy <PATH> [--time <ISO-8601>]
```

**Options:**
- `--policy <PATH>`: Path to the TOML/JSON policy file.
- `--time <ISO-8601>`: The timestamp to test against. Defaults to the current time (`now`).

**Example: Testing a Policy Against a Future Date**
```bash
timely-pass eval --policy policies/working-hours.toml --time "2024-06-01T12:00:00Z"
# Output will indicate if access would be GRANTED or DENIED.
```
