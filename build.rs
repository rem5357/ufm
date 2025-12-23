//! Build script for UFM
//!
//! This script reads the BUILD file and embeds it into the binary.
//! The BUILD file is the single source of truth and must be manually incremented.

use std::fs;
use std::path::Path;

fn main() {
    // Read the build number from BUILD file (single source of truth)
    let build_file = Path::new("BUILD");
    let build_number = if build_file.exists() {
        fs::read_to_string(build_file)
            .unwrap_or_else(|_| "0".to_string())
            .trim()
            .to_string()
    } else {
        "0".to_string()
    };

    // Set the build number as an environment variable for compilation
    println!("cargo:rustc-env=UFM_BUILD_NUMBER={}", build_number);

    // Rerun if BUILD file changes
    println!("cargo:rerun-if-changed=BUILD");
}
