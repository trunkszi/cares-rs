//! Public ownership contracts compiled by rustc against the built SDK metadata.

use std::{
    env,
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn compile(
    deps: &[PathBuf],
    archive: &Path,
    fixture: &str,
    output: &Path,
) -> std::io::Result<Output> {
    let mut command = Command::new(env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()));
    for directory in deps {
        command
            .arg("-L")
            .arg(format!("dependency={}", directory.display()));
    }
    command
        .args([
            "--edition=2024",
            "--crate-type=lib",
            "--emit=metadata",
            "--crate-name=ownership_fixture",
        ])
        .arg(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/compile")
                .join(fixture),
        )
        .arg("--extern")
        .arg(format!("cares={}", archive.display()))
        .arg("-o")
        .arg(output)
        .output()
}

#[test]
fn integration_compile_public_thread_and_borrow_contracts() -> Result<(), Box<dyn Error>> {
    let executable = env::current_exe()?;
    let parent = executable.parent().ok_or("test executable has no parent")?;
    let profile = if parent.file_name().is_some_and(|name| name == "deps") {
        parent.parent().ok_or("missing profile directory")?
    } else {
        executable
            .ancestors()
            .find(|path| path.file_name().is_some_and(|name| name == "build"))
            .and_then(Path::parent)
            .ok_or("missing Cargo build directory")?
    };
    let mut deps = vec![parent.to_path_buf()];
    let conventional = profile.join("deps");
    if conventional.is_dir() {
        deps.push(conventional);
    }
    // Cargo's separated build layout keeps artifacts in build/<crate>/<hash>/out.
    let build = profile.join("build");
    if build.is_dir() {
        for package in fs::read_dir(build)? {
            let package = package?.path();
            if !package.is_dir() {
                continue;
            }
            for variant in fs::read_dir(package)? {
                let out = variant?.path().join("out");
                if out.is_dir() {
                    deps.push(out);
                }
            }
        }
    }
    let mut archives = Vec::new();
    for directory in &deps {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("libcares-"))
                && path
                    .extension()
                    .is_some_and(|extension| extension == "rmeta")
            {
                archives.push(path);
            }
        }
    }
    archives
        .sort_by_key(|path| std::cmp::Reverse(fs::metadata(path).and_then(|m| m.modified()).ok()));
    let output = env::temp_dir().join(format!("cares-ownership-{}.rmeta", std::process::id()));
    let result = (|| -> Result<(), Box<dyn Error>> {
        let archive = archives.first().ok_or("built cares metadata is missing")?;
        let pass = compile(&deps, archive, "pass.rs", &output)?;
        assert!(
            pass.status.success(),
            "compile-pass failed: {}",
            String::from_utf8_lossy(&pass.stderr)
        );
        for (fixture, expected) in [
            ("not_send.rs", "E0277"),
            ("not_sync.rs", "E0277"),
            ("record_escape.rs", "lifetime may not live long enough"),
        ] {
            let failure = compile(&deps, archive, fixture, &output)?;
            let diagnostics = String::from_utf8_lossy(&failure.stderr);
            assert!(!failure.status.success(), "{fixture} unexpectedly compiled");
            assert!(
                diagnostics.contains(expected),
                "{fixture}: expected {expected}: {diagnostics}"
            );
        }
        Ok(())
    })();
    match fs::remove_file(output) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    result
}
