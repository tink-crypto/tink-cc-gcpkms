workspace(name = "tink_cc_gcpkms")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "tink_cc",
    urls = ["https://github.com/tink-crypto/tink-cc/archive/main.zip"],
    strip_prefix = "tink-cc-main",
)

load("@tink_cc//:tink_cc_deps.bzl", "tink_cc_deps")

tink_cc_deps()

load("@tink_cc//:tink_cc_deps_init.bzl", "tink_cc_deps_init")

tink_cc_deps_init()

load("@tink_cc_gcpkms//:tink_cc_gcpkms_deps.bzl", "tink_cc_gcpkms_deps")

tink_cc_gcpkms_deps()

load("@tink_cc_gcpkms//:tink_cc_gcpkms_deps_init.bzl", "tink_cc_gcpkms_deps_init")

tink_cc_gcpkms_deps_init(register_go = True)
