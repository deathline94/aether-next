# Trust verification fixtures

These fixtures exist so that a **positive-looking** trust check can be proven to
actually reject something. Every trust gate in this repo has previously failed in
the same direction: it verified an artifact that was not the one shipped, or
compared a value derived from the file under test.

## Required fixtures

| Fixture | Produced by | Must cause |
|---|---|---|
| `engine-signed-by-pinned-cert.exe` | CI, using the pinned release certificate | verification **accept** |
| `engine-signed-by-other-cn.exe` | local, a throwaway self-signed cert whose subject is also `CN=deathline94` | verification **reject** |
| `engine-unsigned.exe` | local, `cargo build` with no signing step | verification **reject** |
| `engine-tampered.exe` | `engine-signed-by-pinned-cert.exe` + one flipped byte | digest **reject** before any signature check |
| `wintun-unsigned.dll` | a copy of `wintun.dll` with its signature stripped | load **refused**, `DllMain` never executed |

The second row is the important one. A check that only ever sees its own
artifact cannot distinguish "correctly trusted" from "trust check disabled",
which is exactly how the shipped `WinVerifyTrust` + build-time-hash pair passed
while being unable to fail.

## Generating the reject fixtures locally

```powershell
# throwaway certificate, same CN as the pinned one — proves CN is not the check
$pwd2 = ConvertTo-SecureString -String 'temp' -Force -AsPlainText
New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=deathline94' `
  -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(2)
```

Sign a scratch copy of the engine with it, export nothing, delete the
certificate afterwards. These files are test inputs, not release artifacts.

## Do not

- commit any private key, PFX or password here;
- use these fixtures as a substitute for the runtime check — they exist to
  exercise `aether/tests/trust_anchor_independent.rs` and
  `apps/desktop/src-tauri/tests/elevation_trust_test.rs`.
