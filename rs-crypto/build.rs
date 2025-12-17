use cbindgen::{Builder, Language};
use std::env;

fn main() {
    let crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    Builder::new()
        .with_crate(crate_dir)
        .with_language(Language::C)
        .with_header("#pragma once")
        .with_after_include(
            "#define CURVE25519_PRIVATE_KEY_LENGTH 32\n\
             #define CURVE25519_PUBLIC_KEY_LENGTH 32\n\
             #define XEDDSA_SIGNATURE_LENGTH 64\n",
        )
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("include/crypto.h");
}
