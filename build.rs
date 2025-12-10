//! Build script for UFM
//!
//! This script reads the BUILD file, increments it for each build,
//! and sets environment variables for the build number to be compiled into the binary.

use std::fs;
use std::path::Path;

fn main() {
    // Read the build number from BUILD file
    let build_file = Path::new("BUILD");
    let current_build = if build_file.exists() {
        fs::read_to_string(build_file)
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .parse::<u32>()
            .unwrap_or(0)
    } else {
        0
    };

    // Increment build number
    let new_build = current_build + 1;

    // Write the incremented build number back to BUILD file
    if let Err(e) = fs::write(build_file, new_build.to_string()) {
        eprintln!("Warning: Failed to update BUILD file: {}", e);
    }

    // Set the build number as an environment variable for compilation
    println!("cargo:rustc-env=UFM_BUILD_NUMBER={}", new_build);

    // Rerun if BUILD file changes
    println!("cargo:rerun-if-changed=BUILD");

    // Also rerun if any source file changes to ensure build increments on code changes
    println!("cargo:rerun-if-changed=src");
}
