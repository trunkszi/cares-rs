//! Source-cache integration scenarios use local Git repositories without network access.

#![allow(clippy::expect_used)]

use cares_sys as _;
use libc as _;

#[path = "../build/source_cache.rs"]
mod source_cache;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    root: PathBuf,
    repository: PathBuf,
    target: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "cares-cache-test-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        let repository = root.join("upstream");
        let target = root.join("target");
        fs::create_dir_all(&repository).expect("create repository");
        fs::create_dir_all(&target).expect("create target");
        for relative in [
            "CMakeLists.txt",
            "include/ares.h",
            "include/ares_dns_record.h",
            "src/lib/CMakeLists.txt",
            "src/lib/ares_init.c",
        ] {
            let destination = repository.join(relative);
            fs::create_dir_all(destination.parent().expect("fixture parent"))
                .expect("create source directory");
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/source-cache")
                    .join(relative),
                destination,
            )
            .expect("copy source fixture");
        }
        git(&repository, &["init", "--initial-branch=main"]);
        git(&repository, &["add", "."]);
        git(
            &repository,
            &[
                "-c",
                "user.name=Cache Test",
                "-c",
                "user.email=cache@example.invalid",
                "commit",
                "-m",
                "source fixture",
            ],
        );
        git(&repository, &["tag", "v1.34.9"]);
        Self {
            root,
            repository,
            target,
        }
    }

    fn resolve(&self, git_ref: &str, stable: bool) -> PathBuf {
        source_cache::clone_into_target(
            &self.target,
            self.repository.to_str().expect("repository path"),
            git_ref,
            stable,
        )
        .expect("resolve source cache")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).expect("remove source-cache fixture");
    }
}

fn git(directory: &Path, arguments: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(arguments)
        .output()
        .expect("run Git");
    assert!(
        output.status.success(),
        "Git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn integration_scenario_nonempty_incomplete_cache_is_replaced() {
    let fixture = Fixture::new();
    let cache = fixture.target.join("c-ares-main");
    fs::create_dir(&cache).expect("create incomplete cache");
    fs::write(cache.join("leftover"), "partial cached checkout").expect("leave cached file");
    assert_eq!(fixture.resolve("main", false), cache);
    assert!(cache.join(".git").is_dir());
    assert!(cache.join("src/lib/ares_init.c").is_file());
    assert!(!cache.join("leftover").exists());
}

#[test]
fn integration_scenario_cache_without_git_metadata_is_replaced() {
    let fixture = Fixture::new();
    let cache = fixture.resolve("main", false);
    fs::remove_dir_all(cache.join(".git")).expect("remove cached Git metadata");
    assert_eq!(fixture.resolve("main", false), cache);
    assert!(cache.join(".git/HEAD").is_file());
}

#[test]
fn integration_scenario_cache_missing_tracked_source_is_replaced() {
    let fixture = Fixture::new();
    let cache = fixture.resolve("main", false);
    fs::remove_file(cache.join("src/lib/ares_init.c")).expect("remove tracked source");
    assert_eq!(fixture.resolve("main", false), cache);
    assert!(cache.join("src/lib/ares_init.c").is_file());
}

#[test]
fn integration_scenario_invalid_git_ref_is_replaced() {
    let fixture = Fixture::new();
    let cache = fixture.resolve("main", false);
    fs::write(cache.join(".git/HEAD"), "invalid cached HEAD\n").expect("damage cached ref");
    assert_eq!(fixture.resolve("main", false), cache);
    git(&cache, &["rev-parse", "--verify", "HEAD"]);
}

#[test]
fn integration_scenario_stable_tag_cache_is_validated() {
    let fixture = Fixture::new();
    let cache = fixture.resolve("v1.34.9", true);
    fs::remove_dir_all(cache.join(".git")).expect("remove stable cache metadata");
    assert_eq!(fixture.resolve("v1.34.9", true), cache);
    git(&cache, &["describe", "--tags", "--exact-match", "HEAD"]);
}

#[test]
fn integration_scenario_valid_cache_is_reused_without_repository_access() {
    let fixture = Fixture::new();
    let cache = fixture.resolve("main", false);
    fs::write(cache.join("preserved"), "valid concurrent cache").expect("mark valid cache");
    fs::remove_dir_all(&fixture.repository).expect("make upstream unavailable");
    assert_eq!(fixture.resolve("main", false), cache);
    assert!(cache.join("preserved").is_file());
}

#[test]
fn integration_lifecycle_concurrent_builds_preserve_one_valid_cache() {
    let fixture = Fixture::new();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| fixture.resolve("main", false));
        let second = scope.spawn(|| fixture.resolve("main", false));
        assert_eq!(
            first.join().expect("first build"),
            second.join().expect("second build")
        );
    });
    let cache = fixture.target.join("c-ares-main");
    git(&cache, &["diff", "--exit-code", "HEAD", "--"]);
    assert!(cache.join("src/lib/ares_init.c").is_file());
    assert!(
        fs::read_dir(&fixture.target)
            .expect("read target")
            .all(|entry| !entry
                .expect("target entry")
                .file_name()
                .to_string_lossy()
                .contains(".fetch-"))
    );
}
