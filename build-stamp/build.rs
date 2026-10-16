// Notice when this crate's build was copied from another checkout.
//
// Sessions seed a checkout's target dir with a copy of another's (`cp -c -R`,
// which keeps the mtimes). Cargo hashes this workspace's crates by their path
// relative to the workspace root, so the copied builds of this crate and of the
// build scripts that use it are reused, and they name the other checkout: cargo
// decides whether to re-run a build script from the rerun-if-changed list in the
// copy of its last run, and a list printed in another checkout watches that
// checkout's .git and sources. On 2026-10-16 a binary compiled from one checkout
// carried another's stamp, and its commits never re-ran the script. When the
// copy is newer than this checkout's files, no mtime gives it away.
//
// So this script prints one path, absolute and inside this package. Cargo
// stores such a path relative to the package, and the copy's list brings back
// the other checkout's absolute path, which is not inside this package. The
// lists differ, so cargo runs this script again; that recompiles this crate from
// this checkout's sources, which recompiles and re-runs every build script using
// it (rfed's and the two bridges'), and their stamps then watch this checkout.
// In the checkout that built the target the lists match and nothing re-runs.
// Checked with cargo 1.98.1.
fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let anchor = std::path::Path::new(&manifest).join("build.rs");
    println!("cargo:rerun-if-changed={}", anchor.display());
}
