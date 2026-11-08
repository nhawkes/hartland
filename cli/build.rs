// Compiles the vendored REAPI protos with protox (pure Rust; no host protoc).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(
        [
            "build/bazel/remote/execution/v2/remote_execution.proto",
            "google/bytestream/bytestream.proto",
        ],
        ["proto"],
    )?;
    // `bytes` fields as `Bytes` (zero-copy slicing); `prost::Name` for `Any`.
    let mut config = tonic_prost_build::Config::new();
    config.enable_type_names();
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .bytes(".")
        .compile_fds_with_config(fds, config)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
