//! Builds upstream c-ares as a static library without thread support.
//!
//! `CARES_DIR` accepts a local CMake source tree for offline builds. Otherwise,
//! the default feature uses the cached upstream main branch; `stable` selects
//! the fixed v1.34.9 tag, including when both features are enabled.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

#[path = "build/source_cache.rs"]
mod source_cache;

use source_cache::{clone_into_target, is_source_tree};

type BuildResult<T> = Result<T, Box<dyn std::error::Error>>;

const REPOSITORY: &str = "https://github.com/c-ares/c-ares.git";
const STABLE_TAG: &str = "v1.34.9";
const DEFAULT_BRANCH: &str = "main";

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
                    let triple = env::var_os("TARGET");
                    if path.file_name() == triple.as_deref() {
                        path.parent().unwrap_or(path)
                    } else {
                        path
                    }
                })
                .map(Path::to_path_buf)
        })
        .unwrap_or_else(|| manifest.join("../../target"))
}

fn resolve_source(manifest: &Path, out_dir: &Path) -> BuildResult<PathBuf> {
    if let Some(configured) = env::var_os("CARES_DIR") {
        let source = PathBuf::from(configured);
        assert!(
            is_source_tree(&source),
            "CARES_DIR={} does not point to a valid c-ares CMake source tree",
            source.display()
        );
        return Ok(fs::canonicalize(source)?);
    }
    let target = target_root(manifest, out_dir);
    fs::create_dir_all(&target)?;
    let stable = cfg!(feature = "stable");
    let git_ref = if stable { STABLE_TAG } else { DEFAULT_BRANCH };
    clone_into_target(&target, REPOSITORY, git_ref, stable)
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

fn verify_threadless_configuration(install: &Path) -> BuildResult<()> {
    let config = install.join("build/ares_config.h");
    let contents = fs::read_to_string(&config)?;
    assert!(
        !contents.lines().any(|line| {
            line.trim()
                .strip_prefix("#define")
                .is_some_and(|rest| rest.split_whitespace().next() == Some("CARES_THREADS"))
        }),
        "c-ares enabled thread support despite CARES_THREADS=OFF"
    );
    Ok(())
}

fn verify_modern_headers(install: &Path, out_dir: &Path) -> BuildResult<()> {
    let probe = out_dir.join("cares_header_contract.c");
    fs::write(
        &probe,
        "#include <ares.h>\n#include <ares_dns_record.h>\n_Static_assert(ARES_FALSE == 0, \
         \"ARES_FALSE value\");\n_Static_assert(sizeof(ares_socket_t) == sizeof(int), \"socket \
         ABI\");\nvoid cares_header_contract(void) \
         {\n(void)&ares_set_socket_functions_ex;\n(void)&ares_process_fds;\n(void)&\
         ares_query_dnsrec;\n(void)&ares_dns_record_create;\n}\n",
    )?;
    let objects = cc::Build::new()
        .file(&probe)
        .include(install.join("include"))
        .flag_if_supported("-std=c11")
        .warnings_into_errors(true)
        .try_compile_intermediates()?;
    assert!(
        !objects.is_empty(),
        "c-ares header contract produced no object"
    );
    Ok(())
}

fn main() -> BuildResult<()> {
    println!("cargo:rerun-if-env-changed=CARES_DIR");
    println!("cargo:rerun-if-env-changed=CARGO_TARGET_DIR");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=tests/abi_probe.c");
    let target_os = env::var("CARGO_CFG_TARGET_OS")?;
    let target_arch = env::var("CARGO_CFG_TARGET_ARCH")?;
    assert!(
        target_os == "linux" && target_arch == "x86_64",
        "cares-sys supports Linux x86_64 targets"
    );
    let manifest =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").ok_or("CARGO_MANIFEST_DIR is missing")?);
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").ok_or("OUT_DIR is missing")?);
    let source = resolve_source(&manifest, &out_dir)?;
    for relative in ["CMakeLists.txt", "cmake", "include", "src/lib"] {
        println!("cargo:rerun-if-changed={}", source.join(relative).display());
    }
    let install = build_static_library(&source);
    verify_threadless_configuration(&install)?;
    verify_modern_headers(&install, &out_dir)?;
    cc::Build::new()
        .file(manifest.join("tests/abi_probe.c"))
        .include(install.join("include"))
        .flag_if_supported("-std=c11")
        .warnings_into_errors(true)
        .try_compile("cares_sys_abi_probe")?;
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
    Ok(())
}
