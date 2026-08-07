#!/bin/bash
# Copyright 2026 Google LLC
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

set -euo pipefail

##### Tests for the Google Cloud KMS digital signature example.

readonly CLI="$1"
readonly KEY_NAME="$2"
readonly CRED_FILE="$3"
readonly PUB_KEY_FILE="$4"
readonly ALGORITHM="EC_SIGN_P256_SHA256"
readonly DATA_FILE="${TEST_TMPDIR}/example_data.txt"
readonly SIGNATURE_FILE="${TEST_TMPDIR}/example_data.sig"

cat <<EOF > "${DATA_FILE}"
This is some message
to sign.
EOF

#############################################################################

# A helper function for getting the return code of a command that may fail
# Temporarily disables error safety and stores return value in ${TEST_STATUS}
# Usage:
# % test_command somecommand some args
# % echo ${TEST_STATUS}
test_command() {
  set +e
  "$@"
  TEST_STATUS=$?
  set -e
}

#############################################################################
#### Test signing
TEST_NAME="sign"
echo "+++ Starting test ${TEST_NAME}..."

##### Run signing
test_command "${CLI}" --mode=sign --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --signature_filename="${SIGNATURE_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: message was signed."
else
  echo "--- Failure: could not sign message."
  exit 1
fi

#############################################################################
#### Test that verification of a valid signature succeeds
TEST_NAME="verify"
echo "+++ Starting test ${TEST_NAME}..."

##### Run verification
test_command "${CLI}" --mode=verify --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --signature_filename="${SIGNATURE_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: signature verified."
else
  echo "--- Failure: could not verify signature."
  exit 1
fi

#############################################################################
#### Test that verification fails with a modified message
TEST_NAME="test_verify_fails_with_modified_message"
echo "+++ Starting test ${TEST_NAME}..."

readonly MODIFIED_DATA_FILE="${TEST_TMPDIR}/modified_example_data.txt"
cat <<EOF > "${MODIFIED_DATA_FILE}"
This is some tampered message
to sign.
EOF

##### Run verification against the modified message
test_command "${CLI}" --mode=verify --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${MODIFIED_DATA_FILE}" \
  --signature_filename="${SIGNATURE_FILE}"

if (( TEST_STATUS > 0 )); then
  echo "+++ Verification failed as expected."
else
  echo "--- Verification succeeded but expected to fail."
  exit 1
fi

#############################################################################
#### Test that offline verification of a valid signature succeeds
TEST_NAME="verify-offline"
echo "+++ Starting test ${TEST_NAME}..."

##### Run offline verification
test_command "${CLI}" --mode=verify-offline --public_key_filename="${PUB_KEY_FILE}" \
  --algorithm="${ALGORITHM}" --input_filename="${DATA_FILE}" \
  --signature_filename="${SIGNATURE_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: signature verified offline."
else
  echo "--- Failure: could not verify signature offline."
  exit 1
fi

#############################################################################
#### Test that offline verification fails with a modified message
TEST_NAME="test_verify_offline_fails_with_modified_message"
echo "+++ Starting test ${TEST_NAME}..."

##### Run offline verification against the modified message
test_command "${CLI}" --mode=verify-offline --public_key_filename="${PUB_KEY_FILE}" \
  --algorithm="${ALGORITHM}" --input_filename="${MODIFIED_DATA_FILE}" \
  --signature_filename="${SIGNATURE_FILE}"

if (( TEST_STATUS > 0 )); then
  echo "+++ Offline verification failed as expected."
else
  echo "--- Offline verification succeeded but expected to fail."
  exit 1
fi
