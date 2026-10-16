// Bake the identity of this build into the binary. (Shared: see `stamp()` at the end.)
//
// # Why
//
// `rfed` depends on `reticulum_rust`, `lxmf_rust` and `app_links` as **path
// dependencies cloned at build time**, and CI builds it as
// `ghcr.io/.../rfed:latest`. Both halves of that arrangement lose information:
//
//   - `build-rfed.yml` triggers on pushes to `rfed/**` only. A fix in
//     Reticulum-rust or LXMF-rust does not rebuild rfed, so it silently never
//     ships. The workflow's own history is the evidence — commit after commit
//     reading "ci: pick up reticulum_rust <sha>", "ci: trigger rebuild for
//     reticulum_rust log fix", each one a rebuild someone had to remember.
//   - Conversely, a rebuild triggered for an unrelated rfed change clones the
//     siblings at *whatever is on their main branch that minute*, so changes
//     nobody was deploying get swept in.
//
// Either way the deployed binary is a function of when CI last ran, and
// nothing recorded which sibling commits went into it. "Is the fix live?" was
// not an answerable question.
//
// So the shas of all four repositories are compiled in, logged at startup, and
// returned in the CAPABILITIES response, which makes the running node
// self-describing over the network. `scripts/check-sibling-drift.sh` compares
// that against local HEADs and says how far behind a node is.
//
// CI may override any component through the environment (`RFED_BUILD_SHA`,
// `RETICULUM_RUST_SHA`, `LXMF_RUST_SHA`, `APP_LINKS_SHA`); otherwise each is
// read from the corresponding git checkout. Unknown becomes `unknown`, never a
// guess and never a silent empty string.

use std::path::{Path, PathBuf};
use std::process::Command;

/// `git -C dir <args>`: its output, if it succeeded.
///
/// `--no-optional-locks` stops `git status` writing back the index it
/// refreshes. That index is watched (`watch_git`), so the write would make
/// this script schedule its own re-run, and it would hold index.lock against
/// whatever git command is run while cargo builds.
fn git(dir: &Path, args: &[&str]) -> Option<String> {
    Command::new("git")
        .arg("--no-optional-locks")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

fn git_describe(dir: &Path) -> Option<String> {
    let sha = git(dir, &["rev-parse", "--short=12", "HEAD"]).filter(|s| !s.is_empty())?;

    // A dirty checkout is not the commit it claims to be. Say so — this is
    // exactly the case that produced a deployed tree matching no commit at all.
    let dirty = git(dir, &["status", "--porcelain"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);

    Some(if dirty { format!("{sha}+dirty") } else { sha })
}

/// Re-run when the checkout moves: HEAD, the branch it names, packed-refs and
/// the index.
///
/// Their paths come from git, not from `dir/.git`. In a worktree `.git` is a
/// file naming the real git dir, so `dir/.git/HEAD` does not exist and nothing
/// was watched: on 2026-10-15 a worktree rebased to d7adf97 built a binary
/// stamped with the pre-rebase `14238fd8ded0+dirty`. A worktree keeps its HEAD
/// and index in its own git dir and shares the refs with the main checkout
/// (the common dir); in the main checkout both are `.git`.
fn watch_git(dir: &Path) {
    let Some(dirs) = git(dir, &["rev-parse", "--git-dir", "--git-common-dir"]) else {
        return;
    };
    // Relative paths are relative to `dir`, where git ran.
    let mut dirs = dirs.lines().map(|line| dir.join(line));
    let (Some(git_dir), Some(common_dir)) = (dirs.next(), dirs.next()) else {
        return;
    };
    let mut paths = vec![
        git_dir.join("HEAD"),
        git_dir.join("index"),
        common_dir.join("packed-refs"),
    ];
    // A commit on a branch rewrites the branch's ref file and leaves HEAD
    // alone, in the main checkout too; only a detached HEAD holds the commit
    // itself. A branch that lives only in packed-refs has no ref file until its
    // next commit creates one, so watch the nearest directory it will appear in.
    if let Some(branch) = git(dir, &["symbolic-ref", "-q", "HEAD"]) {
        let ref_file = common_dir.join(branch);
        paths.extend(
            ref_file
                .ancestors()
                .take_while(|p| *p != common_dir.as_path())
                .find(|p| p.exists())
                .map(Path::to_path_buf),
        );
    }
    rerun_if_changed(paths);
}

/// Re-run when the sources change, so the dirty flag tracks the working tree.
///
/// Watching only the git metadata is not enough, and the failure is the
/// dangerous direction. Editing a tracked source file leaves HEAD and the
/// index untouched — the index records staged content, not the working tree —
/// so cargo would not re-run this script and the binary would keep a stamp
/// claiming a clean checkout while being built from modified sources. That is
/// precisely the "deployed tree matching no commit" case the stamp exists to
/// expose, reproduced inside the detector. Verified 2026-08-17: with only the
/// .git probes, cleaning an untracked file left the stamp reading "+dirty"
/// indefinitely.
///
/// Watched: src/, Cargo.toml and build.rs of the crate at `dir` (each sibling
/// repo) and of every crate one level down (this repo's workspace members),
/// plus `dir/Cargo.lock`. Cargo walks a watched directory, so a file added to
/// src/ counts too. Until 2026-10-15 the only source directory watched was
/// `dir/src`, which this repo does not have, so no edit to rfed's own sources
/// re-ran the script. Never `dir` itself: it holds target/, which every build
/// rewrites, so the script would re-run on every build.
fn watch_sources(dir: &Path) {
    let members = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.join("Cargo.toml").is_file());
    let mut paths = vec![dir.join("Cargo.lock")];
    for krate in std::iter::once(dir.to_path_buf()).chain(members) {
        paths.extend(["src", "Cargo.toml", "build.rs"].map(|probe| krate.join(probe)));
    }
    rerun_if_changed(paths);
}

/// Only paths that exist: cargo treats a missing one as changed, which would
/// re-run this script on every build.
fn rerun_if_changed(paths: Vec<PathBuf>) {
    for path in paths.iter().filter(|p| p.exists()) {
        println!("cargo:rerun-if-changed={}", path.display());
    }
}

fn component(env_var: &str, dir: &Path) -> String {
    println!("cargo:rerun-if-env-changed={env_var}");
    if let Ok(value) = std::env::var(env_var) {
        if !value.trim().is_empty() {
            return value.trim().to_string();
        }
    }
    // Rebuild the stamp when the checkout moves *or* the working tree changes.
    // Cargo re-runs this script only when a path printed here changes, so an
    // input missed here is a binary carrying an earlier build's stamp.
    watch_git(dir);
    watch_sources(dir);
    git_describe(dir).unwrap_or_else(|| "unknown".to_string())
}

/// Shared by every crate in this workspace: rfed, apns-bridge, fcm-bridge.
/// Each crate's `build.rs` is `include!("../build-stamp.rs"); fn main() {
/// stamp("<name>") }`. The stamp is exposed as `BUILD_STAMP` and names this
/// repo's commit under the crate's own name, so a running bridge is as
/// self-describing as a running rfed — until 2026-09-22 the two bridges had
/// no stamp at all, and "which Reticulum-rust is the push relay running?"
/// could only be answered from CI history.
fn stamp(crate_name: &str) {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let this_repo = Path::new(&manifest)
        .parent()
        .expect("crate dir has a parent")
        .to_path_buf();
    let deps_root = this_repo.parent().expect("RFed-rust has a parent").to_path_buf();

    let stamp = format!(
        "{crate_name}={} reticulum={} lxmf={} app_links={}",
        component("RFED_BUILD_SHA", &this_repo),
        component("RETICULUM_RUST_SHA", &deps_root.join("Reticulum-rust")),
        component("LXMF_RUST_SHA", &deps_root.join("LXMF-rust")),
        component("APP_LINKS_SHA", &deps_root.join("app-links")),
    );

    println!("cargo:rustc-env=BUILD_STAMP={stamp}");
}
