//! Bake the identity of this build into the binary.
//!
//! # Why
//!
//! `rfed` depends on `reticulum_rust`, `lxmf_rust` and `app_links` as **path
//! dependencies cloned at build time**, and CI builds it as
//! `ghcr.io/.../rfed:latest`. Both halves of that arrangement lose information:
//!
//!   - `build-rfed.yml` triggers on pushes to `rfed/**` only. A fix in
//!     Reticulum-rust or LXMF-rust does not rebuild rfed, so it silently never
//!     ships. The workflow's own history is the evidence — commit after commit
//!     reading "ci: pick up reticulum_rust <sha>", "ci: trigger rebuild for
//!     reticulum_rust log fix", each one a rebuild someone had to remember.
//!   - Conversely, a rebuild triggered for an unrelated rfed change clones the
//!     siblings at *whatever is on their main branch that minute*, so changes
//!     nobody was deploying get swept in.
//!
//! Either way the deployed binary is a function of when CI last ran, and
//! nothing recorded which sibling commits went into it. "Is the fix live?" was
//! not an answerable question.
//!
//! So the shas of all four repositories are compiled in, logged at startup, and
//! returned in the CAPABILITIES response, which makes the running node
//! self-describing over the network. `scripts/check-sibling-drift.sh` compares
//! that against local HEADs and says how far behind a node is.
//!
//! CI may override any component through the environment (`RFED_BUILD_SHA`,
//! `RETICULUM_RUST_SHA`, `LXMF_RUST_SHA`, `APP_LINKS_SHA`); otherwise each is
//! read from the corresponding git checkout. Unknown becomes `unknown`, never a
//! guess and never a silent empty string.

use std::path::Path;
use std::process::Command;

fn git_describe(dir: &Path) -> Option<String> {
    let sha = Command::new("git")
        .args(["-C", dir.to_str()?, "rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())?;

    // A dirty checkout is not the commit it claims to be. Say so — this is
    // exactly the case that produced a deployed tree matching no commit at all.
    let dirty = Command::new("git")
        .args(["-C", dir.to_str()?, "status", "--porcelain"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    Some(if dirty { format!("{sha}+dirty") } else { sha })
}

fn component(env_var: &str, dir: &Path) -> String {
    println!("cargo:rerun-if-env-changed={env_var}");
    if let Ok(value) = std::env::var(env_var) {
        if !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    // Rebuild the stamp when the checkout moves.
    for probe in ["HEAD", "index"] {
        let path = dir.join(".git").join(probe);
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }
    git_describe(dir).unwrap_or_else(|| "unknown".to_string())
}

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let rfed_repo = Path::new(&manifest)
        .parent()
        .expect("rfed/ has a parent")
        .to_path_buf();
    let deps_root = rfed_repo.parent().expect("RFed-rust has a parent").to_path_buf();

    let stamp = format!(
        "rfed={} reticulum={} lxmf={} app_links={}",
        component("RFED_BUILD_SHA", &rfed_repo),
        component("RETICULUM_RUST_SHA", &deps_root.join("Reticulum-rust")),
        component("LXMF_RUST_SHA", &deps_root.join("LXMF-rust")),
        component("APP_LINKS_SHA", &deps_root.join("app-links")),
    );

    println!("cargo:rustc-env=RFED_BUILD_STAMP={stamp}");
}
