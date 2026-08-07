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

##### Tests for the Google Cloud KMS MAC example.

readonly CLI="$1"
readonly KEY_NAME="$2"
readonly CRED_FILE="$3"
readonly DATA_FILE="${TEST_TMPDIR}/example_data.txt"
readonly MAC_FILE="${TEST_TMPDIR}/example_mac.bin"

cat <<EOF > "${DATA_FILE}"
This is some message
to authenticate.
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
#### Test computing a MAC
TEST_NAME="compute"
echo "+++ Starting test ${TEST_NAME}..."

##### Run MAC computation
test_command "${CLI}" --mode=compute --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --mac_filename="${MAC_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: MAC was computed."
else
  echo "--- Failure: could not compute MAC."
  exit 1
fi

#############################################################################
#### Test that verification of a valid MAC succeeds
TEST_NAME="verify"
echo "+++ Starting test ${TEST_NAME}..."

##### Run MAC verification
test_command "${CLI}" --mode=verify --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --mac_filename="${MAC_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: MAC verified."
else
  echo "--- Failure: could not verify MAC."
  exit 1
fi

#############################################################################
#### Test that verification fails with a modified message
TEST_NAME="test_verify_fails_with_modified_message"
echo "+++ Starting test ${TEST_NAME}..."

readonly MODIFIED_DATA_FILE="${TEST_TMPDIR}/modified_example_data.txt"
cat <<EOF > "${MODIFIED_DATA_FILE}"
This is some tampered message
to authenticate.
EOF

##### Run verification against the modified message
test_command "${CLI}" --mode=verify --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${MODIFIED_DATA_FILE}" \
  --mac_filename="${MAC_FILE}"

if (( TEST_STATUS > 0 )); then
  echo "+++ Verification failed as expected."
else
  echo "--- Verification succeeded but expected to fail."
  exit 1
fi
