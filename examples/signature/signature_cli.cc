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
// [START signature-example]
// A command-line utility for testing Tink digital signatures with Google Cloud
// KMS asymmetric keys.
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include "absl/flags/parse.h"
#include "google/cloud/kms/v1/resources.pb.h"
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
#include "tink/integration/gcpkms/gcp_kms_public_key_sign.h"
#include "tink/integration/gcpkms/gcp_kms_public_key_verify.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/signature_public_key.h"

ABSL_FLAG(std::string, mode, "",
          "Mode of operation {sign|verify|verify-offline}");
ABSL_FLAG(std::string, key_name, "",
          "Resource name of the KMS CryptoKeyVersion to use, in the form "
          "projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*");
ABSL_FLAG(std::string, input_filename, "",
          "Input file name; holds the message to sign or verify");
ABSL_FLAG(std::string, signature_filename, "",
          "Signature file name; written by `sign`, read by `verify`");
ABSL_FLAG(std::string, credentials, "",
          "Optional Google Cloud service account credentials file path; if not "
          "specified, the default credentials are used");
ABSL_FLAG(
    std::string, public_key_filename, "",
    "Public key file name: holds public key material previously fetched from "
    "Cloud KMS; required when mode is verify-offline");
ABSL_FLAG(std::string, algorithm, "",
          "CryptoKeyVersion algorithm enum name (e.g., EC_SIGN_P256_SHA256, "
          "RSA_SIGN_PSS_2048_SHA256); required when mode is verify-offline");

namespace {

using ::crypto::tink::PublicKeySign;
using ::crypto::tink::PublicKeyVerify;
using ::crypto::tink::SignaturePublicKey;
using ::crypto::tink::integration::gcpkms::CreateGcpKmsPublicKeySign;
using ::crypto::tink::integration::gcpkms::CreateGcpKmsPublicKeyVerify;
using ::crypto::tink::integration::gcpkms::CreateGcpKmsPublicKeyVerifyWithNoRpcs;
using ::crypto::tink::integration::gcpkms::CreateSignaturePublicKeyWithNoRpcs;
using ::google::cloud::kms::v1::CryptoKeyVersion;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1::MakeKeyManagementServiceConnection;

constexpr absl::string_view kSign = "sign";
constexpr absl::string_view kVerify = "verify";
constexpr absl::string_view kVerifyOffline = "verify-offline";

void ValidateParams() {
  // [START_EXCLUDE]
  std::string mode = absl::GetFlag(FLAGS_mode);
  ABSL_CHECK(mode == kSign || mode == kVerify || mode == kVerifyOffline)
      << "Invalid mode " << mode
      << "; must be `sign`, `verify`, or `verify-offline`";
  ABSL_CHECK(!absl::GetFlag(FLAGS_input_filename).empty())
      << "Input file must be specified";
  ABSL_CHECK(!absl::GetFlag(FLAGS_signature_filename).empty())
      << "Signature file must be specified";

  if (mode == kVerifyOffline) {
    ABSL_CHECK(!absl::GetFlag(FLAGS_public_key_filename).empty())
        << "Public key file must be specified for verify-offline mode";
    ABSL_CHECK(!absl::GetFlag(FLAGS_algorithm).empty())
        << "Algorithm must be specified for verify-offline mode";
  } else {
    ABSL_CHECK(!absl::GetFlag(FLAGS_key_name).empty())
        << "Key name must be specified for mode " << mode;
  }
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

void KmsSignatureCli(absl::string_view mode, absl::string_view key_name,
                     absl::string_view input_filename,
                     absl::string_view signature_filename,
                     absl::string_view credentials,
                     absl::string_view public_key_filename,
                     absl::string_view algorithm) {
  absl::StatusOr<std::string> message = ReadFile(input_filename);
  ABSL_CHECK_OK(message.status());

  if (mode == kVerifyOffline) {
    // The verifier is created from pre-fetched public key material and matching
    // algorithm, without making any calls to Cloud KMS.
    absl::StatusOr<std::string> public_key_pem = ReadFile(public_key_filename);
    ABSL_CHECK_OK(public_key_pem.status());

    CryptoKeyVersion::CryptoKeyVersionAlgorithm algo;
    ABSL_CHECK(
        CryptoKeyVersion::CryptoKeyVersionAlgorithm_Parse(algorithm, &algo))
        << "Invalid algorithm " << algorithm;

    absl::StatusOr<std::unique_ptr<SignaturePublicKey>> signature_public_key =
        CreateSignaturePublicKeyWithNoRpcs(*public_key_pem, algo,
                                           crypto::tink::GetPartialKeyAccess());
    ABSL_CHECK_OK(signature_public_key.status());

    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
        CreateGcpKmsPublicKeyVerifyWithNoRpcs(**signature_public_key);
    ABSL_CHECK_OK(verifier.status());

    absl::StatusOr<std::string> signature = ReadFile(signature_filename);
    ABSL_CHECK_OK(signature.status());
    ABSL_CHECK_OK((*verifier)->Verify(*signature, *message));
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

  if (mode == kSign) {
    // The signer sends the message to Cloud KMS for each Sign call;
    // the private key never leaves KMS.

    absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
        CreateGcpKmsPublicKeySign(key_name, kms_client);
    ABSL_CHECK_OK(signer.status());
    absl::StatusOr<std::string> signature = (*signer)->Sign(*message);
    ABSL_CHECK_OK(signature.status());
    ABSL_CHECK_OK(WriteToFile(*signature, signature_filename));
  } else {  // mode == kVerify.
    // The verifier fetches the public key from Cloud KMS once, then verifies
    // locally; no per-operation KMS calls are made.
    absl::StatusOr<std::string> signature = ReadFile(signature_filename);
    ABSL_CHECK_OK(signature.status());
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
        CreateGcpKmsPublicKeyVerify(key_name, kms_client);
    ABSL_CHECK_OK(verifier.status());
    ABSL_CHECK_OK((*verifier)->Verify(*signature, *message));
  }
}

}  // namespace tink_cc_gcpkms_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string key_name = absl::GetFlag(FLAGS_key_name);
  std::string input_filename = absl::GetFlag(FLAGS_input_filename);
  std::string signature_filename = absl::GetFlag(FLAGS_signature_filename);
  std::string credentials = absl::GetFlag(FLAGS_credentials);
  std::string public_key_filename = absl::GetFlag(FLAGS_public_key_filename);
  std::string algorithm = absl::GetFlag(FLAGS_algorithm);

  if (mode == kVerifyOffline) {
    ABSL_LOG(INFO) << "Using pre-fetched public key file "
                   << public_key_filename << " with algorithm " << algorithm
                   << " to verify file " << input_filename << '\n';
  } else {
    ABSL_LOG(INFO) << "Using key " << key_name << " with "
                   << (credentials.empty()
                           ? "default credentials"
                           : absl::StrCat("credentials file ", credentials))
                   << " to " << mode << " file " << input_filename << '\n';
  }
  ABSL_LOG(INFO) << "The signature will be "
                 << (mode == kSign ? "written to " : "read from ")
                 << signature_filename << '\n';

  tink_cc_gcpkms_examples::KmsSignatureCli(
      mode, key_name, input_filename, signature_filename, credentials,
      public_key_filename, algorithm);
  return 0;
}
// [END signature-example]
