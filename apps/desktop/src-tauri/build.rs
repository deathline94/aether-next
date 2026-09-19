fn main() {
    tauri_build::build();
    #[cfg(windows)]
    {
        if let Ok(out_dir) = std::env::var("OUT_DIR") {
            println!("cargo:rustc-link-search=native={out_dir}");
        }
    }
}
