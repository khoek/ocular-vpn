#![allow(unused_imports)]

mod download_prebuilt;
mod lib_prob;

use lib_prob::*;
use std::env;
use std::fs;
use std::path::PathBuf;

use crate::download_prebuilt::download_prebuilt_from_sourceforge;

// TODO: optimize path search
fn main() {
    // if building docs, skip build
    if env::var("DOCS_RS").is_ok() {
        return;
    }

    let use_prebuilt =
        env::var("OPENCONNECT_USE_PREBUILT").unwrap_or("false".to_string()) == "true";

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let target_os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap();

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    let openconnect_src_dir = out_path.join("openconnect");

    // statically link openconnect
    let openconnect_lib = openconnect_src_dir.join(".libs");
    let static_lib = openconnect_lib.join("libopenconnect.a");

    if !static_lib.exists() {
        if use_prebuilt {
            download_prebuilt_from_sourceforge(out_path.clone());
        } else {
            let script = manifest_dir.join("scripts/nix.sh");
            let output = std::process::Command::new("sh")
                .args([
                    script.to_str().unwrap(),
                    openconnect_src_dir.to_str().unwrap(),
                ])
                .output()
                .expect("failed to execute process");
            if !output.status.success() {
                panic!(
                    "failed to build bundled openconnect: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    println!(
        "cargo:rustc-link-search={}",
        openconnect_lib.to_str().unwrap()
    );
    println!("cargo:rustc-link-lib=static=openconnect");

    // windows linking
    #[cfg(target_os = "windows")]
    {
        resolve_mingw64_lib_path();

        let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
        let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
        let target_path = out_path.ancestors().nth(3).unwrap();
        print_build_warning!("target_path: {}", target_path.to_string_lossy());
        println!("cargo:rustc-link-search={}", target_path.to_string_lossy());

        let wintun_dll_source = format!("{}/wintun.dll", manifest_dir);
        let wintun_dll_target = format!("{}/wintun.dll", target_path.to_string_lossy());
        std::fs::copy(wintun_dll_source, wintun_dll_target).unwrap();

        try_pkg_config(vec!["openssl", "libxml-2.0", "zlib", "liblz4", "iconv"]);
        println!("cargo:rustc-link-lib=static=intl");
        println!("cargo:rustc-link-lib=dylib=wintun")
    }

    // link c++ stdlib
    #[cfg(target_os = "linux")]
    {
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-search=/usr/lib");
        println!("cargo:rustc-link-search=/usr/lib/x86_64-linux-gnu");
        println!("cargo:rustc-link-search=/lib/x86_64-linux-gnu");
        // Use dynamic dependencies from the host system; static archives
        // are frequently absent on distro installs (for example liblz4.a).
        println!("cargo:rustc-link-lib=dylib=crypto");
        println!("cargo:rustc-link-lib=dylib=ssl");
        println!("cargo:rustc-link-lib=dylib=xml2");
        println!("cargo:rustc-link-lib=dylib=z");
        println!("cargo:rustc-link-lib=dylib=lzma");
        link_linux_system_lib("lz4");
        link_linux_system_lib("icui18n");
        link_linux_system_lib("icudata");
        link_linux_system_lib("icuuc");
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }

    #[cfg(target_os = "macos")]
    {
        // the order is important!!!
        println!("cargo:rustc-link-search=/usr/lib");
        println!("cargo:rustc-link-search=/usr/local/lib");

        try_pkg_config(vec!["openssl", "libxml-2.0", "zlib", "liblz4"]);

        // link for c++ stdlib
        #[cfg(target_arch = "x86_64")]
        {
            println!("cargo:rustc-link-lib=static=intl"); // fix for x86
        }
        println!("cargo:rustc-link-lib=dylib=c++");
        println!("cargo:rustc-link-lib=dylib=c++abi");

        // if you want to link c++ stdlib statically, use llvm c++ stdlib
        // println!("cargo:rustc-link-search=/opt/homebrew/opt/llvm/lib/c++");
        // println!("cargo:rustc-link-lib=static=c++");
        // println!("cargo:rustc-link-lib=static=c++abi");
    }

    println!("cargo:rerun-if-changed=wrapper.h");
    println!("cargo:rerun-if-changed=c-src/helper.h");
    println!("cargo:rerun-if-changed=c-src/helper.c");

    // ===== compile helper.c start =====
    let mut build = cc::Build::new();
    let build = build.file("c-src/helper.c").include("c-src");
    // .include(openconnect_src_dir.to_str().unwrap()); // maybe not needed
    build.compile("helper");
    // ===== compile helper.c end =====

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let mut bindings_builder = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("wrapper.h")
        .header("c-src/helper.h")
        .clang_arg(format!("-I{}", openconnect_src_dir.to_str().unwrap()))
        .enable_function_attribute_detection()
        .trust_clang_mangling(true)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));

    #[cfg(target_os = "linux")]
    {
        if let Ok(output) = std::process::Command::new("gcc")
            .arg("-print-file-name=include")
            .output()
        {
            if output.status.success() {
                if let Ok(path) = String::from_utf8(output.stdout) {
                    let path = path.trim();
                    if !path.is_empty() {
                        bindings_builder = bindings_builder.clang_arg(format!("-I{path}"));
                    }
                }
            }
        }
        for include in ["/usr/include", "/usr/include/x86_64-linux-gnu"] {
            bindings_builder = bindings_builder.clang_arg(format!("-I{include}"));
        }
    }

    // Finish the builder and generate the bindings.
    let bindings = bindings_builder
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    bindings
        .write_to_file(manifest_dir.join(format!(
            "src/bindings_{}_{}{}.rs",
            target_arch,
            target_os,
            if target_env.is_empty() {
                "".to_string()
            } else {
                format!("_{}", target_env)
            }
        )))
        .expect("Couldn't write bindings!");
}

#[cfg(target_os = "linux")]
fn link_linux_system_lib(name: &str) {
    let search_dirs = ["/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu"];
    for dir in search_dirs {
        let plain = PathBuf::from(dir).join(format!("lib{name}.so"));
        if plain.exists() {
            println!("cargo:rustc-link-lib=dylib={name}");
            return;
        }
    }

    for dir in search_dirs {
        if let Ok(entries) = fs::read_dir(dir) {
            let prefix = format!("lib{name}.so.");
            let mut candidates: Vec<String> = entries
                .filter_map(Result::ok)
                .filter_map(|entry| entry.file_name().into_string().ok())
                .filter(|file| file.starts_with(&prefix))
                .collect();
            candidates.sort();
            if let Some(best) = candidates.last() {
                println!("cargo:rustc-link-search={dir}");
                println!("cargo:rustc-link-lib=dylib:+verbatim={best}");
                return;
            }
        }
    }

    println!("cargo:warning=Could not locate shared library for {name}");
    println!("cargo:rustc-link-lib=dylib={name}");
}
