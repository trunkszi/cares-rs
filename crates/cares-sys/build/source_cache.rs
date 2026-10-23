//! Validates and installs cached upstream source checkouts.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

type BuildResult<T> = Result<T, Box<dyn std::error::Error>>;

pub(crate) fn is_source_tree(path: &Path) -> bool {
    [
        "CMakeLists.txt",
        "include/ares.h",
        "include/ares_dns_record.h",
        "src/lib/CMakeLists.txt",
    ]
    .iter()
    .all(|relative| path.join(relative).is_file())
}

fn verify_cached_ref(source: &Path, git_ref: &str, stable: bool) -> BuildResult<bool> {
    if !is_source_tree(source) || !source.join(".git").is_dir() {
        return Ok(false);
    }
    let arguments: &[&str] = if stable {
        &["describe", "--tags", "--exact-match", "HEAD"]
    } else {
        &["rev-parse", "--abbrev-ref", "HEAD"]
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(source)
        .args(["--git-dir=.git", "--work-tree=."])
        .args(arguments)
        .output()?;
    if !output.status.success() || output.stdout != format!("{git_ref}\n").as_bytes() {
        return Ok(false);
    }
    // Cache restorers can omit tracked sources outside the required header surface.
    let status = Command::new("git")
        .arg("-C")
        .arg(source)
        .args(["--git-dir=.git", "--work-tree=."])
        .args(["diff", "--quiet", "HEAD", "--"])
        .status()?;
    Ok(status.success())
}

fn remove_incomplete_cache(path: &Path) -> BuildResult<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => fs::remove_file(path)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(crate) fn clone_into_target(
    target: &Path,
    repository: &str,
    git_ref: &str,
    stable: bool,
) -> BuildResult<PathBuf> {
    let cache = target.join(format!("c-ares-{git_ref}"));
    // Only build-script processes wait here; resolver execution never uses this lock.
    // Keep the lock file in place so every writer locks the same inode.
    let lock = fs::File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(target.join(format!("c-ares-{git_ref}.lock")))?;
    lock.lock()?;
    if verify_cached_ref(&cache, git_ref, stable)? {
        return Ok(cache);
    }
    remove_incomplete_cache(&cache)?;
    let staging = target.join(format!("c-ares-{git_ref}.fetch-{}", std::process::id()));
    // An interrupted fetch from this process may leave a staging directory.
    remove_incomplete_cache(&staging)?;
    let status = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", git_ref, repository])
        .arg(&staging)
        .status()?;
    if !status.success() {
        remove_incomplete_cache(&staging)?;
        return Err(
            format!("failed to clone c-ares {git_ref}; set CARES_DIR for offline builds").into(),
        );
    }
    if !verify_cached_ref(&staging, git_ref, stable)? {
        remove_incomplete_cache(&staging)?;
        return Err("invalid cloned c-ares source tree or Git ref".into());
    }
    for _ in 0..3 {
        match fs::rename(&staging, &cache) {
            Ok(()) => return Ok(cache),
            Err(error) => {
                // A writer from an older build script may not hold the cache lock.
                if verify_cached_ref(&cache, git_ref, stable)? {
                    fs::remove_dir_all(&staging)?;
                    return Ok(cache);
                }
                if !cache.try_exists()? {
                    fs::remove_dir_all(&staging)?;
                    return Err(error.into());
                }
                remove_incomplete_cache(&cache)?;
            }
        }
    }
    fs::remove_dir_all(&staging)?;
    Err(format!(
        "cannot install c-ares cache at {} after competing writes",
        cache.display()
    )
    .into())
}
