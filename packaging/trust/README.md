# Windows engine trust

Aether's Windows installer, desktop executable, and engine are **not Authenticode-signed**. Windows may display **Unknown publisher**. The bundled `wintun.dll` retains its WireGuard LLC signature and a pinned SHA-256 digest.

The desktop embeds `engine-trust.json` when it is built. Before it starts `aether.exe`, it compares the engine's bytes with the digest in that committed file. A missing or placeholder digest blocks a release build. The engine digest proves that the desktop launched the exact engine recorded in the reviewed source tree; it is not proof of a Windows publisher identity.

## Prepare a release

1. Run **Prepare engine witness** on the intended source commit (`confirm=PUBLISH`, `ref=main` or a full commit SHA).
2. The workflow builds the unsigned engine, records its SHA-256 and the workflow artifact pointer in `engine-trust.json`, uploads those bytes as `engine-witness`, and opens a pull request.
3. Review and merge that pull request. The release workflow will download the witnessed engine from the recorded run and compare its bytes with the committed digest. It never rebuilds the release engine.
4. Tag the merged commit with a new version. The tag build packages Windows and Android assets, runs the package checks, creates SHA-256 files and build attestations, and publishes the release.

If the witnessed artifact expires or the engine source changes, run the witness workflow again and merge its new pull request before tagging.

## Verify a download

Compare a downloaded package with its `.sha256` sidecar or `SHA256SUMS.txt`. GitHub CLI can verify a build attestation:

```sh
gh attestation verify AetherNext-windows-x64-setup.exe --repo deathline94/aether-next
```

Checksums detect accidental or malicious changes relative to the published manifest. The attestation ties the downloaded bytes to this repository's GitHub Actions build. Neither mechanism makes an unsigned Windows application appear as a verified publisher to Windows.
