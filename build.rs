use std::env;

///
/// Resources
/// * cbindgen : https://github.com/eqrion/cbindgen/blob/master/docs.md
/// * cbindgen.toml tempalte: https://github.com/eqrion/cbindgen/blob/master/template.toml
/// or at the end of the docs.md
///
fn main() {
    // the build will be triggered every time the file has changed.
    // https://doc.rust-lang.org/cargo/reference/build-scripts.html#rerun-if-changed
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cbindgen.toml");
    println!("cargo:rerun-if-changed=src/lib.rs");

    // Note only a limited set of envars are available for the build script
    let crate_dir = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR not provided");
    //let out_dir = env::var("OUT_DIR").expect("OUT_DIR not provided (see --out-dir)");

    cbindgen::generate(crate_dir)
        .expect("Unable to generate bindings")
        .write_to_file(format!("esspam.h"));
}
