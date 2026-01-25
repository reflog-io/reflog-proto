fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf files
    tonic_build::configure()
        .build_server(true)
        // Needed for older protoc versions in CI when using `optional` in proto3.
        .protoc_arg("--experimental_allow_proto3_optional")
        .compile(
        &[
            "proto/ingest.proto",
            "proto/options.proto",
            "proto/custom.proto",
        ],
        &["proto"],
    )?;

    println!("cargo:rerun-if-changed=proto/ingest.proto");
    println!("cargo:rerun-if-changed=proto/options.proto");
    println!("cargo:rerun-if-changed=proto/custom.proto");

    Ok(())
}
