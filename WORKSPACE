workspace(name = "tink_cc_gcpkms")

local_repository(
    name = "tink_cc",
    path = "../tink_cc",
)

load("@tink_cc//:tink_cc_deps.bzl", "tink_cc_deps")

tink_cc_deps()

load("@tink_cc//:tink_cc_deps_init.bzl", "tink_cc_deps_init")

tink_cc_deps_init()

load("@tink_cc_gcpkms//:tink_cc_gcpkms_deps.bzl", "tink_cc_gcpkms_deps")

tink_cc_gcpkms_deps()

load("@tink_cc_gcpkms//:tink_cc_gcpkms_deps_init.bzl", "tink_cc_gcpkms_deps_init")

tink_cc_gcpkms_deps_init(register_go = True)
