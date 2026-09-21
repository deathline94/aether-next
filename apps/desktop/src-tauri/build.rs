use std::fs;
use std::path::Path;

fn compute_sha256(path: &Path) -> Option<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = fs::File::open(path).ok()?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let res = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in res {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    Some(s)
}

fn main() {
    tauri_build::build();

    // A build script's entire interface *is* the process environment (cargo
    // documents OUT_DIR/TARGET/CARGO_*); the engine's single-reader rule for
    // `AETHER_*` keys does not apply here.
    #[allow(clippy::disallowed_methods)]
    let out_dir = std::env::var("OUT_DIR").unwrap_or_else(|_| ".".into());
    #[cfg(windows)]
    {
        println!("cargo:rustc-link-search=native={out_dir}");
    }

    // Look for staged wintun.dll and aether.exe
    let wintun_path = Path::new("resources/wintun.dll");
    let packaging_wintun = Path::new("../../../packaging/wintun.dll");
    let wintun_hash = compute_sha256(wintun_path)
        .or_else(|| compute_sha256(packaging_wintun))
        .unwrap_or_else(|| "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce".to_string());

    let aether_path = Path::new("resources/aether.exe");
    let engine_release = Path::new("../../../aether/target/release/aether.exe");
    let aether_hash = compute_sha256(aether_path)
        .or_else(|| compute_sha256(engine_release))
        .unwrap_or_default();

    let mut hashes_code = String::from("pub static EMBEDDED_RELEASE_HASHES: &[(&str, &str)] = &[\n");
    hashes_code.push_str(&format!("    (\"wintun.dll\", \"{wintun_hash}\"),\n"));
    if !aether_hash.is_empty() {
        hashes_code.push_str(&format!("    (\"aether.exe\", \"{aether_hash}\"),\n"));
    }
    hashes_code.push_str("];\n");

    let dest_path = Path::new(&out_dir).join("release_hashes.rs");
    let _ = fs::write(dest_path, hashes_code);
}
