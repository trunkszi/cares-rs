//! Builds upstream c-ares as a static library without thread support.
//!
//! `CARES_DIR` accepts a local CMake source tree for offline builds. Otherwise,
//! the default feature uses the cached upstream main branch; `stable` selects
//! the fixed v1.34.9 tag, including when both features are enabled.

use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const REPOSITORY: &str = "https://github.com/c-ares/c-ares.git";
const STABLE_TAG: &str = "v1.34.9";
const DEFAULT_BRANCH: &str = "main";

fn is_source_tree(path: &Path) -> bool {
    [
        "CMakeLists.txt",
        "include/ares.h",
        "include/ares_dns_record.h",
        "src/lib/CMakeLists.txt",
    ]
    .iter()
    .all(|relative| path.join(relative).is_file())
}

fn target_root(manifest: &Path, out_dir: &Path) -> PathBuf {
    env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|path| {
            if path.is_absolute() {
                path
            } else {
                manifest.join("../..").join(path)
            }
        })
        .or_else(|| {
            out_dir
                .ancestors()
                .find(|path| path.file_name().is_some_and(|name| name == "build"))
                .and_then(Path::parent)
                .and_then(Path::parent)
                .map(|path| {
                    let triple = env::var_os("TARGET").expect("TARGET");
                    if path.file_name() == Some(triple.as_os_str()) {
                        path.parent().expect("target triple parent")
                    } else {
                        path
                    }
                })
                .map(Path::to_path_buf)
        })
        .unwrap_or_else(|| manifest.join("../../target"))
}

fn verify_cached_ref(source: &Path, git_ref: &str, stable: bool) {
    assert!(
        source.join(".git").exists(),
        "cached c-ares source has no Git metadata at {}; use CARES_DIR for a source archive",
        source.display()
    );
    let arguments: &[&str] = if stable {
        &["describe", "--tags", "--exact-match", "HEAD"]
    } else {
        &["rev-parse", "--abbrev-ref", "HEAD"]
    };
    let output = Command::new("git")
        .arg("-C")
        .arg(source)
        .args(arguments)
        .output()
        .expect("verify cached c-ares source ref");
    assert!(output.status.success(), "cannot verify cached c-ares ref");
    let actual = String::from_utf8(output.stdout).expect("UTF-8 c-ares ref");
    assert_eq!(
        actual.trim(),
        git_ref,
        "unexpected c-ares ref at {}",
        source.display()
    );
}

fn clone_into_target(target: &Path, git_ref: &str, stable: bool) -> PathBuf {
    let cache = target.join(format!("c-ares-{git_ref}"));
    if is_source_tree(&cache) {
        verify_cached_ref(&cache, git_ref, stable);
        return cache;
    }
    let staging = target.join(format!("c-ares-{git_ref}.fetch-{}", std::process::id()));
    // An interrupted fetch from this process may leave a staging directory.
    if staging.exists() {
        fs::remove_dir_all(&staging).expect("remove interrupted c-ares fetch");
    }
    let status = Command::new("git")
        .args(["clone", "--depth", "1", "--branch", git_ref, REPOSITORY])
        .arg(&staging)
        .status()
        .expect("run git clone for c-ares");
    assert!(
        status.success(),
        "failed to clone c-ares {git_ref}; set CARES_DIR to a local CMake source tree for offline \
         builds"
    );
    assert!(
        is_source_tree(&staging),
        "invalid cloned c-ares source tree"
    );
    verify_cached_ref(&staging, git_ref, stable);
    if let Err(error) = fs::rename(&staging, &cache) {
        // Independent Cargo target builds may populate the shared source cache.
        assert!(
            is_source_tree(&cache),
            "cannot install c-ares cache at {}: {error}",
            cache.display()
        );
        fs::remove_dir_all(&staging).expect("remove redundant c-ares fetch");
    }
    verify_cached_ref(&cache, git_ref, stable);
    cache
}

fn resolve_source(manifest: &Path, out_dir: &Path) -> PathBuf {
    if let Some(configured) = env::var_os("CARES_DIR") {
        let source = PathBuf::from(configured);
        assert!(
            is_source_tree(&source),
            "CARES_DIR={} does not point to a valid c-ares CMake source tree",
            source.display()
        );
        return fs::canonicalize(source).expect("resolve CARES_DIR");
    }
    let target = target_root(manifest, out_dir);
    fs::create_dir_all(&target).expect("create c-ares cache directory");
    let stable = cfg!(feature = "stable");
    let git_ref = if stable { STABLE_TAG } else { DEFAULT_BRANCH };
    clone_into_target(&target, git_ref, stable)
}

fn build_static_library(source: &Path) -> PathBuf {
    cmake::Config::new(source)
        .define("CARES_STATIC", "ON")
        .define("CARES_SHARED", "OFF")
        .define("CARES_THREADS", "OFF")
        .define("CARES_BUILD_TOOLS", "OFF")
        .define("CARES_BUILD_TESTS", "OFF")
        .define("CARES_STATIC_PIC", "ON")
        .define("CARES_INSTALL", "ON")
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .profile("Release")
        .build()
}

fn verify_threadless_configuration(install: &Path) {
    let config = install.join("build/ares_config.h");
    let contents = fs::read_to_string(&config)
        .unwrap_or_else(|error| panic!("read {}: {error}", config.display()));
    assert!(
        !contents.lines().any(|line| {
            line.trim()
                .strip_prefix("#define")
                .is_some_and(|rest| rest.split_whitespace().next() == Some("CARES_THREADS"))
        }),
        "c-ares enabled thread support despite CARES_THREADS=OFF"
    );
}

fn verify_modern_headers(install: &Path, out_dir: &Path) {
    let probe = out_dir.join("cares_header_contract.c");
    fs::write(
        &probe,
        "#include <ares.h>\n#include <ares_dns_record.h>\n_Static_assert(ARES_FALSE == 0, \
         \"ARES_FALSE value\");\n_Static_assert(sizeof(ares_socket_t) == sizeof(int), \"socket \
         ABI\");\nvoid cares_header_contract(void) \
         {\n(void)&ares_set_socket_functions_ex;\n(void)&ares_process_fds;\n(void)&\
         ares_query_dnsrec;\n(void)&ares_dns_record_create;\n}\n",
    )
    .expect("write modern c-ares header contract");
    let objects = cc::Build::new()
        .file(&probe)
        .include(install.join("include"))
        .flag_if_supported("-std=c11")
        .warnings_into_errors(true)
        .compile_intermediates();
    assert!(
        !objects.is_empty(),
        "c-ares header contract produced no object"
    );
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARES_DIR");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tests/abi_probe.c");
    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("target OS");
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").expect("target architecture");
    assert!(
        target_os == "linux" && target_arch == "x86_64",
        "cares-sys supports Linux x86_64 targets"
    );
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("OUT_DIR"));
    let source = resolve_source(&manifest, &out_dir);
    for relative in ["CMakeLists.txt", "cmake", "include", "src/lib"] {
        println!("cargo:rerun-if-changed={}", source.join(relative).display());
    }
    let install = build_static_library(&source);
    verify_threadless_configuration(&install);
    verify_modern_headers(&install, &out_dir);
    cc::Build::new()
        .file(manifest.join("tests/abi_probe.c"))
        .include(install.join("include"))
        .flag_if_supported("-std=c11")
        .warnings_into_errors(true)
        .compile("cares_sys_abi_probe");
    let lib_dir = install.join("lib");
    assert!(
        lib_dir.join("libcares.a").is_file(),
        "CMake did not install static libcares.a"
    );
    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=cares");
    println!("cargo:root={}", install.display());
    println!("cargo:include={}", install.join("include").display());
    println!(
        "cargo:rustc-env=CARES_INCLUDE_DIR={}",
        install.join("include").display()
    );
}
