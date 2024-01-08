workspace(name = "tink_cc_gcpkms")

load("@tink_cc_gcpkms//:tink_cc_gcpkms_deps.bzl", "tink_cc_gcpkms_deps", "tink_cc_gcpkms_testonly_deps")

tink_cc_gcpkms_deps()

tink_cc_gcpkms_testonly_deps()

load("@tink_cc_gcpkms//:tink_cc_gcpkms_deps_init.bzl", "tink_cc_gcpkms_deps_init")

tink_cc_gcpkms_deps_init(register_go = True)
