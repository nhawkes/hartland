//! Generated Remote Execution API (v2.12.0) and ByteStream types.
//! Module nesting mirrors the proto packages so generated paths resolve.
#![allow(clippy::all, missing_docs)]

pub mod google {
    pub mod api {
        tonic::include_proto!("google.api");
    }
    pub mod rpc {
        tonic::include_proto!("google.rpc");
    }
    pub mod longrunning {
        tonic::include_proto!("google.longrunning");
    }
    pub mod bytestream {
        tonic::include_proto!("google.bytestream");
    }
}

pub mod build {
    pub mod bazel {
        pub mod semver {
            tonic::include_proto!("build.bazel.semver");
        }
        pub mod remote {
            pub mod execution {
                pub mod v2 {
                    tonic::include_proto!("build.bazel.remote.execution.v2");
                }
            }
        }
    }
}

pub use build::bazel::remote::execution::v2 as re;
pub use google::bytestream as bs;
