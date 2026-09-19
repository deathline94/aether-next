# Elevation Trust Policy Contract

## Binary Trust Verification Specification

### API Signature
```rust
pub fn verify_elevated_binary(
    path: &Path,
    filename: &str,
    policy: &TrustedBinaryPolicy,
) -> Result<(), BinaryTrustError>
```

### Policy Contracts

#### 1. Engine (`aether.exe`)
```rust
TrustedBinaryPolicy {
    allow_unsigned_in_debug: cfg!(debug_assertions),
    expected_publisher_cn: "deathline94",
    embedded_hashes: EMBEDDED_RELEASE_HASHES,
    enforce_hash_match: !cfg!(debug_assertions),
}
```

#### 2. WinTUN Driver (`wintun.dll`)
```rust
TrustedBinaryPolicy {
    allow_unsigned_in_debug: false, // WireGuard DLL must always be signed
    expected_publisher_cn: "WireGuard LLC",
    embedded_hashes: EMBEDDED_RELEASE_HASHES,
    enforce_hash_match: !cfg!(debug_assertions),
}
```

### Verification Flow & Invariants

```text
1. Check path exists and is regular file.
2. Read file header: must start with MZ/PE (0x5A4D).
3. If enforce_hash_match is true:
   - Calculate SHA-256 hex digest of file.
   - Look up filename in embedded_hashes.
   - If filename not found in embedded_hashes -> Return BinaryTrustError::MissingHash.
   - If calculated hash != expected hash -> Return BinaryTrustError::HashMismatch.
4. If !allow_unsigned_in_debug:
   - Invoke WinVerifyTrust(WTD_CHOICE_FILE).
   - If WinVerifyTrust != ERROR_SUCCESS -> Return BinaryTrustError::Authenticode.
   - Extract signer certificate context.
   - Extract Subject CN from certificate.
   - If CN != expected_publisher_cn -> Return BinaryTrustError::PublisherMismatch.
5. Return Ok(()).
```
