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

##### Tests for the Google Cloud KMS HPKE example.

readonly CLI="$1"
readonly KEY_NAME="$2"
readonly CRED_FILE="$3"
readonly PUB_KEY_FILE="$4"
readonly DATA_FILE="${TEST_TMPDIR}/example_data.txt"
readonly CIPHERTEXT_FILE="${TEST_TMPDIR}/example_ciphertext.bin"
readonly DECRYPTED_FILE="${TEST_TMPDIR}/example_decrypted.txt"

cat <<EOF > "${DATA_FILE}"
This is some plaintext
to encrypt using HPKE.
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
#### Test HPKE encryption
TEST_NAME="encrypt"
echo "+++ Starting test ${TEST_NAME}..."

##### Run encryption
test_command "${CLI}" --mode=encrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: file was encrypted."
else
  echo "--- Failure: could not encrypt file."
  exit 1
fi

#############################################################################
#### Test that decryption succeeds and returns the original plaintext
TEST_NAME="decrypt"
echo "+++ Starting test ${TEST_NAME}..."

##### Run decryption
test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Success: file was successfully decrypted."
else
  echo "--- Failure: could not decrypt file."
  exit 1
fi

if cmp -s "${DATA_FILE}" "${DECRYPTED_FILE}"; then
  echo "+++ Success: file content is the same after decryption."
else
  echo "--- Failure: file content is not the same after decryption."
  exit 1
fi

#############################################################################
#### Test encryption and decryption with context info
TEST_NAME="test_encrypt_decrypt_succeeds_with_context_info"
echo "+++ Starting test ${TEST_NAME}..."

readonly CONTEXT_INFO="example context info"
test_command "${CLI}" --mode=encrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}" \
  --context_info="${CONTEXT_INFO}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption with context info successful."
else
  echo "--- Encryption with context info failed."
  exit 1
fi

test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --context_info="${CONTEXT_INFO}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption with context info successful."
else
  echo "--- Decryption with context info failed."
  exit 1
fi

if cmp -s "${DATA_FILE}" "${DECRYPTED_FILE}"; then
  echo "+++ Success: file content is the same after decryption with context info."
else
  echo "--- Failure: file content is not the same after decryption with context info."
  exit 1
fi

#############################################################################
#### Test that decryption fails with modified context info
TEST_NAME="test_decrypt_fails_with_modified_context_info"
echo "+++ Starting test ${TEST_NAME}..."

readonly MODIFIED_CONTEXT_INFO="modified context info"
test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --context_info="${MODIFIED_CONTEXT_INFO}"

if (( TEST_STATUS > 0 )); then
  echo "+++ Decryption failed as expected."
else
  echo "--- Decryption succeeded but expected to fail."
  exit 1
fi

#############################################################################
#### Test that decryption fails with modified ciphertext
TEST_NAME="test_decrypt_fails_with_modified_ciphertext"
echo "+++ Starting test ${TEST_NAME}..."

readonly MODIFIED_CIPHERTEXT_FILE="${TEST_TMPDIR}/modified_ciphertext.bin"
cp "${CIPHERTEXT_FILE}" "${MODIFIED_CIPHERTEXT_FILE}"
printf '\xff' >> "${MODIFIED_CIPHERTEXT_FILE}"

test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${MODIFIED_CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --context_info="${CONTEXT_INFO}"

if (( TEST_STATUS > 0 )); then
  echo "+++ Decryption of modified ciphertext failed as expected."
else
  echo "--- Decryption of modified ciphertext succeeded but expected to fail."
  exit 1
fi

#############################################################################
#### Test encryption and decryption with explicit KEM, KDF, and AES-128-GCM AEAD
TEST_NAME="test_encrypt_decrypt_succeeds_with_aes_128_gcm"
echo "+++ Starting test ${TEST_NAME}..."

test_command "${CLI}" --mode=encrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}" \
  --kem=X_WING --kdf=HKDF_SHA256 --aead=AES_128_GCM

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption with AES-128-GCM successful."
else
  echo "--- Encryption with AES-128-GCM failed."
  exit 1
fi

test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --kem=X_WING --kdf=HKDF_SHA256 --aead=AES_128_GCM

if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption with AES-128-GCM successful."
else
  echo "--- Decryption with AES-128-GCM failed."
  exit 1
fi

if cmp -s "${DATA_FILE}" "${DECRYPTED_FILE}"; then
  echo "+++ Success: file content is the same after decryption with AES-128-GCM."
else
  echo "--- Failure: file content is not the same after decryption with AES-128-GCM."
  exit 1
fi

#############################################################################
#### Test encryption and decryption with explicit KEM, KDF, and ChaCha20-Poly1305 AEAD
TEST_NAME="test_encrypt_decrypt_succeeds_with_chacha20_poly1305"
echo "+++ Starting test ${TEST_NAME}..."

test_command "${CLI}" --mode=encrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}" \
  --kem=X_WING --kdf=HKDF_SHA256 --aead=CHACHA20_POLY1305

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption with ChaCha20-Poly1305 successful."
else
  echo "--- Encryption with ChaCha20-Poly1305 failed."
  exit 1
fi

test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --kem=X_WING --kdf=HKDF_SHA256 --aead=CHACHA20_POLY1305

if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption with ChaCha20-Poly1305 successful."
else
  echo "--- Decryption with ChaCha20-Poly1305 failed."
  exit 1
fi

if cmp -s "${DATA_FILE}" "${DECRYPTED_FILE}"; then
  echo "+++ Success: file content is the same after decryption with ChaCha20-Poly1305."
else
  echo "--- Failure: file content is not the same after decryption with ChaCha20-Poly1305."
  exit 1
fi

#############################################################################
#### Test that decryption fails when AEAD does not match encryption AEAD
TEST_NAME="test_decrypt_fails_with_mismatched_aead"
echo "+++ Starting test ${TEST_NAME}..."

test_command "${CLI}" --mode=encrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}" \
  --kem=X_WING --kdf=HKDF_SHA256 --aead=AES_256_GCM

if (( TEST_STATUS == 0 )); then
  echo "+++ Encryption with AES-256-GCM successful."
else
  echo "--- Encryption with AES-256-GCM failed."
  exit 1
fi

test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --kem=X_WING --kdf=HKDF_SHA256 --aead=AES_128_GCM

if (( TEST_STATUS > 0 )); then
  echo "+++ Decryption with mismatched AEAD failed as expected."
else
  echo "--- Decryption with mismatched AEAD succeeded but expected to fail."
  exit 1
fi

#############################################################################
#### Test that encryption and decryption fail when KEM does not match the KMS key
TEST_NAME="test_encrypt_decrypt_fails_with_mismatched_kem"
echo "+++ Starting test ${TEST_NAME}..."

test_command "${CLI}" --mode=encrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}" \
  --kem=ML_KEM_768 --kdf=HKDF_SHA256 --aead=AES_256_GCM

if (( TEST_STATUS > 0 )); then
  echo "+++ Encryption with mismatched KEM failed as expected."
else
  echo "--- Encryption with mismatched KEM succeeded but expected to fail."
  exit 1
fi

test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --kem=ML_KEM_768 --kdf=HKDF_SHA256 --aead=AES_256_GCM

if (( TEST_STATUS > 0 )); then
  echo "+++ Decryption with mismatched KEM failed as expected."
else
  echo "--- Decryption with mismatched KEM succeeded but expected to fail."
  exit 1
fi

#############################################################################
#### Test encrypting offline without KMS RPCs and decrypting with KMS
TEST_NAME="test_encrypt_offline_succeeds"
echo "+++ Starting test ${TEST_NAME}..."

test_command "${CLI}" --mode=encrypt-offline \
  --public_key_filename="${PUB_KEY_FILE}" \
  --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}" \
  --context_info="${CONTEXT_INFO}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Offline encryption successful."
else
  echo "--- Offline encryption failed."
  exit 1
fi

test_command "${CLI}" --mode=decrypt --key_name="${KEY_NAME}" \
  --credentials="${CRED_FILE}" --input_filename="${CIPHERTEXT_FILE}" \
  --output_filename="${DECRYPTED_FILE}" \
  --context_info="${CONTEXT_INFO}"

if (( TEST_STATUS == 0 )); then
  echo "+++ Decryption of offline-encrypted ciphertext successful."
else
  echo "--- Decryption of offline-encrypted ciphertext failed."
  exit 1
fi

if cmp -s "${DATA_FILE}" "${DECRYPTED_FILE}"; then
  echo "+++ Success: file content is the same after offline encryption and decryption."
else
  echo "--- Failure: file content is not the same after offline encryption and decryption."
  exit 1
fi

#############################################################################
#### Test that offline encryption fails with invalid public key bytes
TEST_NAME="test_encrypt_offline_fails_with_invalid_public_key"
echo "+++ Starting test ${TEST_NAME}..."

test_command "${CLI}" --mode=encrypt-offline \
  --public_key_filename="${DATA_FILE}" \
  --input_filename="${DATA_FILE}" \
  --output_filename="${CIPHERTEXT_FILE}"

if (( TEST_STATUS > 0 )); then
  echo "+++ Offline encryption with invalid public key failed as expected."
else
  echo "--- Offline encryption with invalid public key succeeded but expected to fail."
  exit 1
fi
