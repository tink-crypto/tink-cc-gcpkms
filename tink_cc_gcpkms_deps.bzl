"""Tink C++ Cloud KMS Integration Dependencies."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive", "http_file")

def _grpc_deps():
    """Imports gRPC and its dependencies.

    Dependencies taken from: https://github.com/grpc/grpc/blob/v1.59.3/bazel/grpc_deps.bzl.
    """
    if "com_google_protobuf" not in native.existing_rules():
        http_archive(
            name = "com_google_protobuf",
            sha256 = "387478260190c540388839a3449c635a69708d92fc38ea6e2364b1196db90ea5",
            strip_prefix = "protobuf-2434ef2adf0c74149b9d547ac5fb545a1ff8b6b5",
            urls = [
                # https://github.com/protocolbuffers/protobuf/commits/v26.1
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/protocolbuffers/protobuf/archive/2434ef2adf0c74149b9d547ac5fb545a1ff8b6b5.tar.gz",
                "https://github.com/protocolbuffers/protobuf/archive/2434ef2adf0c74149b9d547ac5fb545a1ff8b6b5.tar.gz",
            ],
            patches = [
                "@com_github_grpc_grpc//third_party:protobuf.patch",
                "@com_github_grpc_grpc//third_party:protobuf.10007.patch",
            ],
            patch_args = ["-p1"],
        )

    if "upb" not in native.existing_rules():
        http_archive(
            name = "upb",
            sha256 = "5147e0ab6a28421d1e49004f4a205d84f06b924585e15eaa884cfe13289165b7",
            strip_prefix = "upb-42cd08932e364a4cde35033b73f15c30250d7c2e",
            urls = [
                # https://github.com/protocolbuffers/upb/commits/24.x
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/protocolbuffers/upb/archive/42cd08932e364a4cde35033b73f15c30250d7c2e.tar.gz",
                "https://github.com/protocolbuffers/upb/archive/42cd08932e364a4cde35033b73f15c30250d7c2e.tar.gz",
            ],
        )

    if "envoy_api" not in native.existing_rules():
        http_archive(
            name = "envoy_api",
            sha256 = "ddd3beedda1178a79e0d988f76f362002aced09749452515853f106e22bd2249",
            strip_prefix = "data-plane-api-78f198cf96ecdc7120ef640406770aa01af775c4",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/envoyproxy/data-plane-api/archive/78f198cf96ecdc7120ef640406770aa01af775c4.tar.gz",
                "https://github.com/envoyproxy/data-plane-api/archive/78f198cf96ecdc7120ef640406770aa01af775c4.tar.gz",
            ],
        )

    if "io_bazel_rules_go" not in native.existing_rules():
        http_archive(
            name = "io_bazel_rules_go",
            sha256 = "69de5c704a05ff37862f7e0f5534d4f479418afc21806c887db544a316f3cb6b",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
                "https://github.com/bazelbuild/rules_go/releases/download/v0.27.0/rules_go-v0.27.0.tar.gz",
            ],
        )

    if "build_bazel_rules_apple" not in native.existing_rules():
        http_archive(
            name = "build_bazel_rules_apple",
            sha256 = "f94e6dddf74739ef5cb30f000e13a2a613f6ebfa5e63588305a71fce8a8a9911",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/bazelbuild/rules_apple/releases/download/1.1.3/rules_apple.1.1.3.tar.gz",
                "https://github.com/bazelbuild/rules_apple/releases/download/1.1.3/rules_apple.1.1.3.tar.gz",
            ],
        )

    if "build_bazel_apple_support" not in native.existing_rules():
        http_archive(
            name = "build_bazel_apple_support",
            sha256 = "f4fdf5c9b42b92ea12f229b265d74bb8cedb8208ca7a445b383c9f866cf53392",
            urls = [
                "https://storage.googleapis.com/grpc-bazel-mirror/github.com/bazelbuild/apple_support/releases/download/1.3.1/apple_support.1.3.1.tar.gz",
                "https://github.com/bazelbuild/apple_support/releases/download/1.3.1/apple_support.1.3.1.tar.gz",
            ],
        )

    if "bazel_gazelle" not in native.existing_rules():
        http_archive(
            name = "bazel_gazelle",
            sha256 = "de69a09dc70417580aabf20a28619bb3ef60d038470c7cf8442fafcf627c21cb",
            urls = [
                "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
                "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.24.0/bazel-gazelle-v0.24.0.tar.gz",
            ],
        )

    if "com_envoyproxy_protoc_gen_validate" not in native.existing_rules():
        http_archive(
            name = "com_envoyproxy_protoc_gen_validate",
            strip_prefix = "protoc-gen-validate-4694024279bdac52b77e22dc87808bd0fd732b69",
            sha256 = "1e490b98005664d149b379a9529a6aa05932b8a11b76b4cd86f3d22d76346f47",
            urls = [
                "https://github.com/envoyproxy/protoc-gen-validate/archive/4694024279bdac52b77e22dc87808bd0fd732b69.tar.gz",
            ],
            patches = ["@com_github_grpc_grpc//third_party:protoc-gen-validate.patch"],
            patch_args = ["-p1"],
        )

    if not native.existing_rule("com_github_grpc_grpc"):
        # Release from 2023-08-16.
        http_archive(
            name = "com_github_grpc_grpc",
            sha256 = "14f301f9a6c295f2d3fdae4704182721097a996fb2211d05213096321fc572ac",
            strip_prefix = "grpc-1.65.5",
            urls = ["https://github.com/grpc/grpc/archive/refs/tags/v1.65.5.zip"],
        )

def tink_cc_gcpkms_deps():
    """Loads dependencies for Tink C++ Cloud KMS."""

    # Google PKI certs for connecting to GCP KMS.
    #
    # Note: sha256 is intentionally omitted as this is not a static resource.
    # Whenever updated, clients should fetch the latest revision provided at
    # this URL.
    if not native.existing_rule("google_root_pem"):
        http_file(
            name = "google_root_pem",
            executable = 0,
            urls = ["https://pki.goog/roots.pem"],
        )

    _grpc_deps()

    if "com_google_googleapis" not in native.existing_rules():
        http_archive(
            name = "com_google_googleapis",
            sha256 = "c9bc8f2485009bc7e0f3cf89116ba158c54b215452f5777af6eb3d508aeefe55",
            strip_prefix = "googleapis-0c860e055a00ff0b6553b7f1eb4e77829f00e12a",
            build_file = Label("@com_github_grpc_grpc//bazel:googleapis.BUILD"),
            urls = [
                "https://github.com/googleapis/googleapis/archive/0c860e055a00ff0b6553b7f1eb4e77829f00e12a.tar.gz",
            ],
        )

    if "google_cloud_cpp" not in native.existing_rules():
        http_archive(
            name = "google_cloud_cpp",
            sha256 = "0f42208ca782249555aac06455b1669c17dfb31d6d8fa4baad29a90f295666bb",
            strip_prefix = "google-cloud-cpp-2.20.0",
            url = "https://github.com/googleapis/google-cloud-cpp/archive/v2.20.0.tar.gz",
        )

    if not native.existing_rule("com_google_absl"):
        # Release from 2024-08-01.
        http_archive(
            name = "com_google_absl",
            sha256 = "f50e5ac311a81382da7fa75b97310e4b9006474f9560ac46f54a9967f07d4ae3",
            strip_prefix = "abseil-cpp-20240722.0",
            urls = [
                "https://github.com/abseil/abseil-cpp/releases/download/20240722.0/abseil-cpp-20240722.0.tar.gz",
            ],
        )

    if not native.existing_rule("rules_python"):
        # This is needed to avoid failures like
        # https://github.com/bazelbuild/rules_python/issues/1560.
        # Release from 2023-10-06.
        http_archive(
            name = "rules_python",
            sha256 = "9d04041ac92a0985e344235f5d946f71ac543f1b1565f2cdbc9a2aaee8adf55b",
            strip_prefix = "rules_python-0.26.0",
            url = "https://github.com/bazelbuild/rules_python/releases/download/0.26.0/rules_python-0.26.0.tar.gz",
        )

    if not native.existing_rule("tink_cc"):
        # Release from 2025-05-06.
        http_archive(
            name = "tink_cc",
            sha256 = "06c4d49b0b1357f0b8c3abc77a7d920130dc868e4597d432a9ce1cda4f65e382",
            strip_prefix = "tink-cc-2.4.0",
            urls = ["https://github.com/tink-crypto/tink-cc/releases/download/v2.4.0/tink-cc-2.4.0.zip"],
        )

    if not native.existing_rule("com_googlesource_code_re2"):
        http_archive(
            name = "com_googlesource_code_re2",
            sha256 = "cd191a311b84fcf37310e5cd876845b4bf5aee76fdd755008eef3b6478ce07bb",
            strip_prefix = "re2-2024-02-01",
            url = "https://github.com/google/re2/releases/download/2024-02-01/re2-2024-02-01.tar.gz",
        )

def tink_cc_gcpkms_testonly_deps():
    """Test only dependencies."""

    if not native.existing_rule("com_google_googletest"):
        # Release from 2023-08-02.
        http_archive(
            name = "com_google_googletest",
            sha256 = "1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4",
            strip_prefix = "googletest-1.14.0",
            url = "https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip",
        )
