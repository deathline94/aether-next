# Contract: Windows DPAPI Identity Encryption & Elevated Binary Trust

**Feature**: `013-security-reliability-remediation`
**Target Components**: `apps/desktop/src-tauri/src/lib.rs`, `aether/src/config.rs`

---

## 1. Elevated Binary Trust Contract

```rust
// In lib.rs

pub struct TrustedBinaryPolicy {
    pub allow_unsigned_in_debug: bool,
    pub expected_publisher_cn: &'static str,
    pub embedded_hashes: &'static [(&'static str, &'static str)], // (filename, sha256_hex)
}

pub fn verify_elevated_binary(
    path: &Path,
    label: &str,
    policy: &TrustedBinaryPolicy,
) -> Result<(), BinaryTrustError>;
```

### Validation Sequence:
1. `validate_trusted_binary`: Path must reside in `C:\Program Files\Aether Next` (or canonical install directory), regular file, not empty, no reparse points, valid PE `MZ` header.
2. `WinVerifyTrust`: Valid Authenticode signature chaining to a trusted root authority.
3. `CertGetNameString`: Subject matches `CN="deathline94"` or configured publisher.
4. Embedded SHA-256 match against release table.

---

## 2. DPAPI Key Derivation & Environment Injection

```rust
// In lib.rs setup:

pub fn get_or_create_dpapi_config_key(app_data_dir: &Path) -> Result<String, String>;
```

### Invariants:
1. Master 32-byte key is protected with `CryptProtectData` (`CRYPTPROTECT_UI_FORBIDDEN`) and saved to `%APPDATA%\Aether\config_key.dpapi`.
2. Master key is passed to child `aether.exe` process via `AETHER_CONFIG_KEY` as base64-encoded string.
3. Memory buffers holding the raw 32-byte key are wiped using `zeroize::Zeroize` after injection.
