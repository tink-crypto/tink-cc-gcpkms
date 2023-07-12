#!/bin/bash
# Copyright 2023 Google LLC
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

##### Tests for the Google Cloud KMS envelope encryption AEAD example.

readonly CLI="$1"
readonly KEY_URI="$2"
readonly CRED_FILE="$3"
readonly DATA_FILE="${TEST_TMPDIR}/example_data.txt"

cat <<EOF > "${DATA_FILE}"
This is some plaintext
to encrypt.
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
#### Test initialization and encryption
TEST_NAME="encrypt"
echo "+++ Starting test ${TEST_NAME}..."

# ##### Run encryption
test_command ${CLI} --mode=encrypt --kek_uri="${KEY_URI}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${DATA_FILE}.encrypted"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: file was encrypted."
else
  echo "--- Failure: could not encrypt file."
  exit 1
fi

#############################################################################
#### Test if decryption succeeds and returns original file
TEST_NAME="decrypt"
echo "+++ Starting test ${TEST_NAME}..."

##### Run decryption
test_command ${CLI} --mode=decrypt --kek_uri="${KEY_URI}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}.encrypted" \
  --output_filename="${DATA_FILE}.decrypted"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: file was successfully decrypted."
else
  echo "--- Failure: could not decrypt file."
  exit 1
fi

if cmp -s "${DATA_FILE}" "${DATA_FILE}.decrypted"; then
  echo "+++ Success: file content is the same after decryption."
else
  echo "--- Failure: file content is not the same after decryption."
  exit 1
fi

#############################################################################
#### Test correct encryption and decryption with associated data
TEST_NAME="test_encrypt_decrypt_succeeds_with_associated_data"
echo "+++ Starting test ${TEST_NAME}..."

##### Run encryption
ASSOCIATED_DATA="header information"
test_command ${CLI} --mode=encrypt --kek_uri="${KEY_URI}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${DATA_FILE}.encrypted" \
  --associated_data="${ASSOCIATED_DATA}"
if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

##### Run decryption
test_command ${CLI} --mode=decrypt --kek_uri="${KEY_URI}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}.encrypted" \
  --output_filename="${DATA_FILE}.decrypted" \
  --associated_data="${ASSOCIATED_DATA}"
if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption successful."
else
  echo "--- Decryption failed."
  exit 1
fi

cmp --s "${DATA_FILE}" ${DATA_FILE}.decrypted

#############################################################################
#### Test decryption fails with modified associated data
TEST_NAME="test_encrypt_decrypt_fails_with_modified_associated_data"
echo "+++ Starting test ${TEST_NAME}..."

##### Run encryption
ASSOCIATED_DATA="header information"
test_command ${CLI} --mode=encrypt --kek_uri="${KEY_URI}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${DATA_FILE}.encrypted" \
  --associated_data="${ASSOCIATED_DATA}"
if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption successful."
else
  echo "--- Encryption failed."
  exit 1
fi

##### Run decryption
MODIFIED_ASSOCIATED_DATA="modified header information"
test_command ${CLI} --mode=decrypt --kek_uri="${KEY_URI}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}.encrypted" \
  --output_filename="${DATA_FILE}.decrypted" \
  --associated_data="${MODIFIED_ASSOCIATED_DATA}"

if (( TEST_STATUS > 0 )); then
  echo "+++ Decryption failed as expected."
else
  echo "--- Decryption succeeded but expected to fail."
  exit 1
fi

