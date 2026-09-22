use std::fs;
use std::path::{Path, PathBuf};

/// Committed, reviewed witness. It is the *only* source for the digests the
/// shell compares against at runtime, and it is never generated here.
const ANCHOR_REL: &str = "../../../packaging/trust/engine-trust.json";
const MIN_ANCHOR_BYTES: usize = 256;
const PLACEHOLDER_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const ARTIFACTS: [&str; 2] = ["aether.exe", "wintun.dll"];

fn die(what: &str, detail: &str) -> ! {
    panic!(
        "\n\n  build.rs: refusing to build without a usable trust anchor\n  \
         {what}\n  {detail}\n\n  \
         This is a hard error on purpose. An absent, truncated or malformed anchor makes the\n  \
         runtime digest comparison vacuous — a check that cannot fail is worse than no check, and\n  \
         that is exactly the defect this replaced (see packaging/trust/README.md). Fix the anchor;\n  \
         do not weaken this guard.\n"
    )
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let mut s = String::with_capacity(64);
    for b in hasher.finalize() {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn is_hex64(v: &str) -> bool {
    v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Reads the anchor and returns `(name, digest)` pairs, or stops the build.
fn read_anchor() -> (PathBuf, Vec<u8>, Vec<(String, String)>) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(ANCHOR_REL)
        .canonicalize()
        .unwrap_or_else(|e| {
            die(
                &format!("{ANCHOR_REL} is missing or unresolvable: {e}"),
                "it must be committed; the release job republishes it, the build never invents it",
            )
        });
    let bytes = fs::read(&path)
        .unwrap_or_else(|e| die(&format!("cannot read {}: {e}", path.display()), ""));
    if bytes.len() < MIN_ANCHOR_BYTES {
        die(
            &format!("{} is {} bytes", path.display(), bytes.len()),
            "a stub is indistinguishable from an empty table at the use site",
        );
    }
    let doc: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => die(
            &format!("{} is not valid JSON", path.display()),
            &e.to_string(),
        ),
    };
    let files = doc
        .get("files")
        .and_then(|f| f.as_array())
        .unwrap_or_else(|| die(&format!("{} has no `files` array", path.display()), ""));

    let mut entries: Vec<(String, String)> = Vec::with_capacity(files.len());
    for entry in files {
        let name = entry
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or_else(|| {
                die(
                    &format!(
                        "{} has a `files[]` entry with no string `name`",
                        path.display()
                    ),
                    "",
                )
            });
        let digest = entry
            .get("file_sha256")
            .and_then(|d| d.as_str())
            .unwrap_or_else(|| {
                die(
                    &format!(
                        "{}: entry `{name}` has no string `file_sha256`",
                        path.display()
                    ),
                    "",
                )
            });
        if !is_hex64(digest) {
            die(
                &format!(
                    "{}: entry `{name}` has file_sha256 `{digest}`",
                    path.display()
                ),
                "want exactly 64 hexadecimal characters",
            );
        }
        entries.push((name.to_ascii_lowercase(), digest.to_ascii_lowercase()));
    }

    for want in ARTIFACTS {
        if !entries.iter().any(|(n, _)| n == want) {
            die(
                &format!("{} has no entry for `{want}`", path.display()),
                "an absent entry must not be allowed to mean \"nothing to check\": the runtime \
                 needs an answer for every binary it verifies",
            );
        }
    }

    (path, bytes, entries)
}

fn main() {
    // A build script's entire interface *is* the process environment (cargo
    // documents OUT_DIR/TARGET/CARGO_*); the engine's single-reader rule for
    // `AETHER_*` keys does not apply here.
    #![allow(clippy::disallowed_methods)]

    let (anchor_path, anchor_bytes, entries) = read_anchor();
    let anchor_sha = sha256_hex(&anchor_bytes);

    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into());
    println!("cargo:rerun-if-changed={}", anchor_path.display());
    #[cfg(windows)]
    println!("cargo:rustc-link-search=native={out_dir}");

    let has_placeholder = entries.iter().any(|(_, d)| d == PLACEHOLDER_SHA256);
    if has_placeholder {
        println!(
            "cargo:warning=engine-trust.json still carries a placeholder digest, so release \
             builds will refuse that binary until the publish-anchor step records its real one"
        );
        // A release build that ends up refusing its own engine at runtime is not a
        // warning — it is a shipped product that cannot connect, and the documented
        // `cargo build --release` path produced exactly that. Fail here, where the
        // reason is legible, unless this is a deliberately unwitnessed dev build.
        let profile = std::env::var("PROFILE").unwrap_or_else(|_| "unknown".into());
        let allow_unwitnessed =
            matches!(std::env::var("AETHER_ALLOW_UNWITNESSED").as_deref(), Ok(v) if !v.trim().is_empty());
        if profile == "release" && !allow_unwitnessed {
            die(
                "engine-trust.json still carries a placeholder digest, so this release shell \
                 would refuse to spawn the engine it ships with",
                "cut the real witness with the prepare-anchor workflow and commit it, or set \
                 AETHER_ALLOW_UNWITNESSED=1 to build a deliberately unwitnessed dev binary \
                 (it can never be released: it has no trusted engine to start)",
            );
        }
        if profile == "release" {
            println!(
                "cargo:warning=AETHER_ALLOW_UNWITNESSED is set on a release build: this \
                 artifact has no committed witness and must not be published"
            );
        }
    }

    let mut code = String::new();
    code.push_str(&format!(
        "// @generated by build.rs from {ANCHOR_REL} — do not edit, and do not regenerate \
         from the artifacts.\n"
    ));
    code.push_str(
        "/// Digested from the committed trust anchor. The values are deliberately *not*\n\
         /// computed from `resources/*`: hashing the file we then ship made the runtime\n\
         /// comparison unable to fail.\n",
    );
    code.push_str("pub static EMBEDDED_RELEASE_HASHES: &[(&str, &str)] = &[\n");
    for (name, digest) in &entries {
        code.push_str(&format!("    ({name:?}, {digest:?}),\n"));
    }
    code.push_str("];\n");
    code.push_str(&format!(
        "/// Verbatim bytes of the anchor this binary was built against, so the running shell can \
         say which witness it is holding.\n\
         pub static ENGINE_TRUST_ANCHOR_BYTES: &[u8] = include_bytes!({anchor_path:?});\n"
    ));
    code.push_str(&format!(
        "pub static ENGINE_TRUST_ANCHOR_SHA256: &str = {anchor_sha:?};\n"
    ));
    code.push_str(&format!(
        "pub static ENGINE_TRUST_ANCHOR_HAS_PLACEHOLDER: bool = {has_placeholder};\n"
    ));

    let dest_path: PathBuf = Path::new(&out_dir).join("release_hashes.rs");
    fs::write(&dest_path, code)
        .unwrap_or_else(|e| die(&format!("cannot write {}: {e}", dest_path.display()), ""));

    tauri_build::build();
}
