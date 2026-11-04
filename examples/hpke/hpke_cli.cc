// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////
// [START hpke-example]
// A command-line utility for testing Tink HPKE hybrid encryption and decryption
// with Google Cloud KMS KEM keys.
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/log/absl_check.h"
#include "absl/log/absl_log.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/credentials.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/key_management_connection.h"
#include "google/cloud/options.h"
#include "absl/flags/parse.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/integration/gcpkms/gcp_kms_hpke_decrypt.h"
#include "tink/integration/gcpkms/gcp_kms_hpke_encrypt.h"
#include "tink/partial_key_access.h"

ABSL_FLAG(std::string, mode, "",
          "Mode of operation {encrypt|encrypt-offline|decrypt}");
ABSL_FLAG(std::string, key_name, "",
          "Resource name of the KMS CryptoKeyVersion to use, in the form "
          "projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*; "
          "required when mode is encrypt or decrypt");
ABSL_FLAG(std::string, input_filename, "", "Input file name");
ABSL_FLAG(std::string, output_filename, "", "Output file name");
ABSL_FLAG(std::string, credentials, "",
          "Optional Google Cloud service account credentials file path; if not "
          "specified, the default credentials are used");
ABSL_FLAG(std::string, context_info, "",
          "Optional context info for HPKE encryption or decryption");
ABSL_FLAG(
    std::string, public_key_filename, "",
    "Public key file name: holds raw public key bytes previously fetched from "
    "Cloud KMS; required when mode is encrypt-offline");
ABSL_FLAG(std::string, kem, "X_WING",
          "HPKE KEM algorithm {X_WING|ML_KEM_768|ML_KEM_1024}");
ABSL_FLAG(std::string, kdf, "HKDF_SHA256", "HPKE KDF algorithm {HKDF_SHA256}");
ABSL_FLAG(std::string, aead, "AES_256_GCM",
          "HPKE AEAD algorithm {AES_128_GCM|AES_256_GCM|CHACHA20_POLY1305}");

namespace {

using ::crypto::tink::GetPartialKeyAccess;
using ::crypto::tink::HpkeParameters;
using ::crypto::tink::HpkePublicKey;
using ::crypto::tink::HybridDecrypt;
using ::crypto::tink::HybridEncrypt;
using ::crypto::tink::integration::gcpkms::CreateGcpKmsHybridDecrypt;
using ::crypto::tink::integration::gcpkms::CreateGcpKmsHybridEncrypt;
using ::crypto::tink::integration::gcpkms::CreateGcpKmsHybridEncryptWithNoRpcs;
using ::crypto::tink::integration::gcpkms::CreateHpkePublicKeyWithNoRpcs;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1::MakeKeyManagementServiceConnection;

constexpr absl::string_view kEncrypt = "encrypt";
constexpr absl::string_view kEncryptOffline = "encrypt-offline";
constexpr absl::string_view kDecrypt = "decrypt";

absl::StatusOr<HpkeParameters::KemId> ParseKemId(absl::string_view kem) {
  if (kem == "X_WING") {
    return HpkeParameters::KemId::kXWing;
  }
  if (kem == "ML_KEM_768") {
    return HpkeParameters::KemId::kMlKem768;
  }
  if (kem == "ML_KEM_1024") {
    return HpkeParameters::KemId::kMlKem1024;
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Unsupported KEM algorithm: ", kem));
}

absl::StatusOr<HpkeParameters::KdfId> ParseKdfId(absl::string_view kdf) {
  if (kdf == "HKDF_SHA256") {
    return HpkeParameters::KdfId::kHkdfSha256;
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Unsupported KDF algorithm: ", kdf));
}

absl::StatusOr<HpkeParameters::AeadId> ParseAeadId(absl::string_view aead) {
  if (aead == "AES_128_GCM") {
    return HpkeParameters::AeadId::kAesGcm128;
  }
  if (aead == "AES_256_GCM") {
    return HpkeParameters::AeadId::kAesGcm256;
  }
  if (aead == "CHACHA20_POLY1305") {
    return HpkeParameters::AeadId::kChaCha20Poly1305;
  }
  return absl::InvalidArgumentError(
      absl::StrCat("Unsupported AEAD algorithm: ", aead));
}

absl::StatusOr<HpkeParameters> BuildHpkeParameters(absl::string_view kem,
                                                   absl::string_view kdf,
                                                   absl::string_view aead) {
  absl::StatusOr<HpkeParameters::KemId> kem_id = ParseKemId(kem);
  if (!kem_id.ok()) {
    return kem_id.status();
  }
  absl::StatusOr<HpkeParameters::KdfId> kdf_id = ParseKdfId(kdf);
  if (!kdf_id.ok()) {
    return kdf_id.status();
  }
  absl::StatusOr<HpkeParameters::AeadId> aead_id = ParseAeadId(aead);
  if (!aead_id.ok()) {
    return aead_id.status();
  }
  return HpkeParameters::Builder()
      .SetVariant(HpkeParameters::Variant::kNoPrefix)
      .SetKemId(*kem_id)
      .SetKdfId(*kdf_id)
      .SetAeadId(*aead_id)
      .Build();
}

void ValidateParams() {
  // [START_EXCLUDE]
  std::string mode = absl::GetFlag(FLAGS_mode);
  ABSL_CHECK(mode == kEncrypt || mode == kEncryptOffline || mode == kDecrypt)
      << "Invalid mode " << mode
      << "; must be `encrypt`, `encrypt-offline`, or `decrypt`";
  ABSL_CHECK(!absl::GetFlag(FLAGS_input_filename).empty())
      << "Input file must be specified";
  ABSL_CHECK(!absl::GetFlag(FLAGS_output_filename).empty())
      << "Output file must be specified";
  if (mode == kEncryptOffline) {
    ABSL_CHECK(!absl::GetFlag(FLAGS_public_key_filename).empty())
        << "Public key file must be specified for encrypt-offline mode";
  } else {
    ABSL_CHECK(!absl::GetFlag(FLAGS_key_name).empty())
        << "Key name must be specified for mode " << mode;
  }
  ABSL_CHECK_OK(ParseKemId(absl::GetFlag(FLAGS_kem)).status());
  ABSL_CHECK_OK(ParseKdfId(absl::GetFlag(FLAGS_kdf)).status());
  ABSL_CHECK_OK(ParseAeadId(absl::GetFlag(FLAGS_aead)).status());
  // [END_EXCLUDE]
}

absl::StatusOr<std::string> ReadFile(absl::string_view filename) {
  // [START_EXCLUDE]
  std::ifstream input_stream;
  input_stream.open(std::string(filename),
                    std::ifstream::in | std::ifstream::binary);
  if (!input_stream.is_open()) {
    return absl::InternalError(
        absl::StrCat("Error opening input file ", filename));
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  return input.str();
  // [END_EXCLUDE]
}

absl::Status WriteToFile(absl::string_view data_to_write,
                         absl::string_view filename) {
  // [START_EXCLUDE]
  std::ofstream output_stream;
  output_stream.open(std::string(filename),
                     std::ofstream::out | std::ofstream::binary);
  if (!output_stream.is_open()) {
    return absl::InternalError(
        absl::StrCat("Error opening output file ", filename));
  }
  output_stream << data_to_write;
  return absl::OkStatus();
  // [END_EXCLUDE]
}

}  // namespace

namespace tink_cc_gcpkms_examples {

void KmsHpkeCli(absl::string_view mode, absl::string_view key_name,
                absl::string_view input_filename,
                absl::string_view output_filename,
                absl::string_view credentials, absl::string_view context_info,
                absl::string_view public_key_filename,
                const HpkeParameters& hpke_params) {
  absl::StatusOr<std::string> input_data = ReadFile(input_filename);
  ABSL_CHECK_OK(input_data.status());

  if (mode == kEncryptOffline) {
    // The encryptor is created from pre-fetched raw public key bytes and HPKE
    // parameters, without making any calls to Cloud KMS.
    absl::StatusOr<std::string> public_key_bytes =
        ReadFile(public_key_filename);
    ABSL_CHECK_OK(public_key_bytes.status());

    absl::StatusOr<HpkePublicKey> hpke_public_key =
        CreateHpkePublicKeyWithNoRpcs(*public_key_bytes, hpke_params,
                                      GetPartialKeyAccess());
    ABSL_CHECK_OK(hpke_public_key.status());

    absl::StatusOr<std::unique_ptr<HybridEncrypt>> hybrid_encrypt =
        CreateGcpKmsHybridEncryptWithNoRpcs(*hpke_public_key);
    ABSL_CHECK_OK(hybrid_encrypt.status());

    absl::StatusOr<std::string> ciphertext =
        (*hybrid_encrypt)->Encrypt(*input_data, context_info);
    ABSL_CHECK_OK(ciphertext.status());
    ABSL_CHECK_OK(WriteToFile(*ciphertext, output_filename));
    return;
  }

  // Build a Cloud KMS client, optionally using a service account credentials
  // file. When no file is given, Application Default Credentials are used.
  google::cloud::Options options;
  if (!credentials.empty()) {
    absl::StatusOr<std::string> json_creds = ReadFile(credentials);
    ABSL_CHECK_OK(json_creds.status());
    options.set<google::cloud::UnifiedCredentialsOption>(
        google::cloud::MakeServiceAccountCredentials(*json_creds));
  }
  auto kms_client = std::make_shared<KeyManagementServiceClient>(
      MakeKeyManagementServiceConnection(options));

  if (mode == kEncrypt) {
    // Encryption fetches the public key from Cloud KMS and performs HPKE
    // encryption locally.
    absl::StatusOr<std::unique_ptr<HybridEncrypt>> hybrid_encrypt =
        CreateGcpKmsHybridEncrypt(key_name, kms_client, hpke_params);
    ABSL_CHECK_OK(hybrid_encrypt.status());
    absl::StatusOr<std::string> ciphertext =
        (*hybrid_encrypt)->Encrypt(*input_data, context_info);
    ABSL_CHECK_OK(ciphertext.status());
    ABSL_CHECK_OK(WriteToFile(*ciphertext, output_filename));
  } else {  // mode == kDecrypt.
    // Decryption sends the encapsulated key to Cloud KMS for decapsulation and
    // decrypts the payload locally; the private key never leaves KMS.
    absl::StatusOr<std::unique_ptr<HybridDecrypt>> hybrid_decrypt =
        CreateGcpKmsHybridDecrypt(key_name, kms_client, hpke_params);
    ABSL_CHECK_OK(hybrid_decrypt.status());
    absl::StatusOr<std::string> plaintext =
        (*hybrid_decrypt)->Decrypt(*input_data, context_info);
    ABSL_CHECK_OK(plaintext.status());
    ABSL_CHECK_OK(WriteToFile(*plaintext, output_filename));
  }
}

}  // namespace tink_cc_gcpkms_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string key_name = absl::GetFlag(FLAGS_key_name);
  std::string input_filename = absl::GetFlag(FLAGS_input_filename);
  std::string output_filename = absl::GetFlag(FLAGS_output_filename);
  std::string credentials = absl::GetFlag(FLAGS_credentials);
  std::string context_info = absl::GetFlag(FLAGS_context_info);
  std::string public_key_filename = absl::GetFlag(FLAGS_public_key_filename);
  std::string kem = absl::GetFlag(FLAGS_kem);
  std::string kdf = absl::GetFlag(FLAGS_kdf);
  std::string aead = absl::GetFlag(FLAGS_aead);

  absl::StatusOr<HpkeParameters> hpke_params =
      BuildHpkeParameters(kem, kdf, aead);
  ABSL_CHECK_OK(hpke_params.status());

  if (mode == kEncryptOffline) {
    ABSL_LOG(INFO) << "Using pre-fetched public key file "
                   << public_key_filename << " to HPKE encrypt file "
                   << input_filename << " with context info '" << context_info;
  } else {
    ABSL_LOG(INFO) << "Using key " << key_name << " with "
                   << (credentials.empty()
                           ? "default credentials"
                           : absl::StrCat("credentials file ", credentials))
                   << " to HPKE " << mode << " file " << input_filename
                   << " with context info '" << context_info;
  }
  ABSL_LOG(INFO) << "The resulting output will be written to "
                 << output_filename;

  tink_cc_gcpkms_examples::KmsHpkeCli(
      mode, key_name, input_filename, output_filename, credentials,
      context_info, public_key_filename, *hpke_params);
  return 0;
}
// [END hpke-example]
