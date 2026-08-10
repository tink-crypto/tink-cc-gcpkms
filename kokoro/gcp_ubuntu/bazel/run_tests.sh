#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

# Builds and tests tink-cc-gcpkms using Bazel.
#
# The behavior of this script can be modified using the following optional env
# variables:
#
# - CONTAINER_IMAGE (unset by default): By default when run locally this script
#   executes tests directly on the host. The CONTAINER_IMAGE variable can be set
#   to execute tests in a custom container image for local testing. E.g.:
#
#   CONTAINER_IMAGE="us-docker.pkg.dev/tink-test-infrastructure/tink-ci-images/linux-tink-cc-base:latest" \
#     sh ./kokoro/gcp_ubuntu/bazel/run_tests.sh

# Generated with openssl rand -hex 10
echo "==========================================================================="
echo "Tink Script ID: 9b5726cdb8704c1e05d3 (to quickly find the script from logs)"
echo "==========================================================================="

set -eEuo pipefail

IS_KOKORO="false"
if [[ -n "${KOKORO_ARTIFACTS_DIR:-}" ]]; then
  IS_KOKORO="true"
fi
readonly IS_KOKORO

RUN_COMMAND_ARGS=()
if [[ "${IS_KOKORO}" == "true" ]]; then
  readonly TINK_BASE_DIR="$(echo "${KOKORO_ARTIFACTS_DIR}"/git*)"
  cd "${TINK_BASE_DIR}/tink_cc_gcpkms"
  source ./kokoro/testutils/cc_test_container_images.sh
  CONTAINER_IMAGE="${TINK_CC_BASE_IMAGE}"
  RUN_COMMAND_ARGS+=( -k "${TINK_GCR_SERVICE_KEY}" )
fi
readonly CONTAINER_IMAGE

if [[ -n "${CONTAINER_IMAGE:-}" ]]; then
  RUN_COMMAND_ARGS+=( -c "${CONTAINER_IMAGE}" )
fi

./kokoro/testutils/copy_credentials.sh "testdata" "gcp"
./kokoro/testutils/copy_credentials.sh "examples/testdata" "gcp"

CACHE_FLAGS=()
if [[ -n "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET:-}" ]]; then
  if [[ -z "${TINK_CC_BASE_IMAGE_HASH:-}" ]] && [[ -f ./kokoro/testutils/cc_test_container_images.sh ]]; then
    source ./kokoro/testutils/cc_test_container_images.sh
  fi
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./cache_key
  cp "${TINK_REMOTE_BAZEL_CACHE_SERVICE_KEY}" ./examples/cache_key
  CACHE_FLAGS+=( -c "${TINK_REMOTE_BAZEL_CACHE_GCS_BUCKET}/bazel/${TINK_CC_BASE_IMAGE_HASH:-default}" )
fi
readonly CACHE_FLAGS

MANUAL_TARGETS=()
if [[ "${IS_KOKORO}" == "true" ]]; then
  MANUAL_TARGETS+=("//tink/integration/gcpkms:gcp_kms_aead_integration_test")
  MANUAL_TARGETS+=("//tink/integration/gcpkms:gcp_kms_mac_integration_test")
  MANUAL_TARGETS+=(
    "//tink/integration/gcpkms:gcp_kms_public_key_sign_verify_integration_test")
fi
readonly MANUAL_TARGETS

# 1. Define build and test options as COMMA-separated strings (No internal quotes)
BAZEL_BUILD_OPTS="--cxxopt=-std=c++17,--host_cxxopt=-std=c++17"
BAZEL_TEST_OPTS="--cxxopt=-std=c++17,--host_cxxopt=-std=c++17"

# Test examples.
EXAMPLES_MANUAL_TARGETS=()
if [[ "${IS_KOKORO}" == "true" ]]; then
  EXAMPLES_MANUAL_TARGETS+=( "//envelopeaead:envelopeaead_cli_test" )
  EXAMPLES_MANUAL_TARGETS+=( "//signature:signature_cli_test" )
  EXAMPLES_MANUAL_TARGETS+=( "//mac:mac_cli_test" )
fi
readonly EXAMPLES_MANUAL_TARGETS

cat <<EOF > _do_run_test.sh
#!/bin/bash
set -eEuo pipefail

./kokoro/testutils/run_bazel_tests.sh ${CACHE_FLAGS[@]:-} \\
  -b "${BAZEL_BUILD_OPTS}" \\
  -t "${BAZEL_TEST_OPTS}" \\
  . ${MANUAL_TARGETS[@]:+"${MANUAL_TARGETS[@]}"}

./kokoro/testutils/run_bazel_tests.sh ${CACHE_FLAGS[@]:-} \\
  -b "${BAZEL_BUILD_OPTS}" \\
  -t "${BAZEL_TEST_OPTS}" \\
  examples ${EXAMPLES_MANUAL_TARGETS[@]:+"${EXAMPLES_MANUAL_TARGETS[@]}"}
EOF

chmod +x _do_run_test.sh

cleanup() {
  rm -f _do_run_test.sh
}

trap cleanup EXIT

./kokoro/testutils/docker_execute.sh "${RUN_COMMAND_ARGS[@]}" ./_do_run_test.sh
