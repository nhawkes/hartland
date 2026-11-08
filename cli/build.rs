// Compiles the vendored REAPI protos with protox (pure Rust; no host protoc).
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(
        ["build/bazel/remote/execution/v2/remote_execution.proto", "google/bytestream/bytestream.proto"],
        ["proto"],
    )?;
    tonic_prost_build::configure().build_client(true).build_server(true).compile_fds(fds)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}
