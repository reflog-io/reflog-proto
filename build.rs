fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Compile protobuf files
    tonic_build::configure()
        .build_server(true)
        .compile(
            &["proto/ingest.proto", "proto/options.proto", "proto/custom.proto"],
            &["proto"],
        )?;

    println!("cargo:rerun-if-changed=proto/ingest.proto");
    println!("cargo:rerun-if-changed=proto/options.proto");
    println!("cargo:rerun-if-changed=proto/custom.proto");

    Ok(())
}
