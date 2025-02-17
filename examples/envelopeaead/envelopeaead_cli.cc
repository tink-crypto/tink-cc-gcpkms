// Copyright 2023 Google LLC
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
// [START envelopeaead-example]
// A command-line utility for testing Tink Envelope AEAD with Google Cloud KMS.
#include <fstream>
#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include "absl/flags/parse.h"
#include "absl/flags/flag.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/aead/aead_config.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/kms_envelope_aead.h"
#include "tink/integration/gcpkms/gcp_kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

ABSL_FLAG(std::string, mode, "", "Mode of operation {encrypt|decrypt}");
ABSL_FLAG(std::string, kek_uri, "", "URI of the KMS Key Encryption Key to use");
ABSL_FLAG(std::string, input_filename, "", "Input file name");
ABSL_FLAG(std::string, output_filename, "", "Output file name");
ABSL_FLAG(std::string, credentials, "",
          "Optional Google Cloud KMS credentials file path; if not specified, "
          "use the default credentials");
ABSL_FLAG(std::string, associated_data, "", "Optional associated data");

namespace {

using ::crypto::tink::Aead;
using ::crypto::tink::AeadKeyTemplates;
using ::crypto::tink::integration::gcpkms::GcpKmsClient;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KeyTemplate;

constexpr absl::string_view kEncrypt = "encrypt";
constexpr absl::string_view kDecrypt = "decrypt";

void ValidateParams() {
  // [START_EXCLUDE]
  CHECK(absl::GetFlag(FLAGS_mode) == kEncrypt ||
        absl::GetFlag(FLAGS_mode) == kDecrypt)
      << "Invalid mode " << absl::GetFlag(FLAGS_mode)
      << "; must be `encrypt` or `decrypt`";
  CHECK(!absl::GetFlag(FLAGS_kek_uri).empty())
      << "Keyset file must be specified";
  CHECK(!absl::GetFlag(FLAGS_input_filename).empty())
      << "Input file must be specified";
  CHECK(!absl::GetFlag(FLAGS_output_filename).empty())
      << "Output file must be specified";
  // [END_EXCLUDE]
}

absl::StatusOr<std::string> ReadFile(absl::string_view filename) {
  // [START_EXCLUDE]
  std::ifstream input_stream;
  input_stream.open(std::string(filename), std::ifstream::in);
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

void KmsEnvelopAeadCli(absl::string_view mode, absl::string_view kek_uri,
                       absl::string_view input_filename,
                       absl::string_view output_filename,
                       absl::string_view credentials,
                       absl::string_view associated_data) {
  CHECK_OK(crypto::tink::AeadConfig::Register());
  // Obtain a remote Aead that can use the KEK.
  absl::StatusOr<std::unique_ptr<GcpKmsClient>> gcp_kms_client =
      GcpKmsClient::New(kek_uri, credentials);
  CHECK_OK(gcp_kms_client.status());
  absl::StatusOr<std::unique_ptr<Aead>> remote_aead =
      (*gcp_kms_client)->GetAead(kek_uri);
  CHECK_OK(remote_aead.status());
  // Define the DEK template.
  KeyTemplate dek_key_template = AeadKeyTemplates::Aes256Gcm();
  // Create a KmsEnvelopeAead instance.
  absl::StatusOr<std::unique_ptr<Aead>> aead =
      crypto::tink::KmsEnvelopeAead::New(dek_key_template,
                                         *std::move(remote_aead));
  CHECK_OK(aead.status());

  absl::StatusOr<std::string> input_file_content = ReadFile(input_filename);
  CHECK_OK(input_file_content.status());
  if (mode == kEncrypt) {
    // Generate the ciphertext.
    absl::StatusOr<std::string> encrypt_result =
        (*aead)->Encrypt(*input_file_content, associated_data);
    CHECK_OK(encrypt_result.status());
    CHECK_OK(WriteToFile(encrypt_result.value(), output_filename));
  } else {  // mode == kDecrypt.
    // Recover the plaintext.
    absl::StatusOr<std::string> decrypt_result =
        (*aead)->Decrypt(*input_file_content, associated_data);
    CHECK_OK(decrypt_result.status());
    CHECK_OK(WriteToFile(decrypt_result.value(), output_filename));
  }
}

}  // namespace tink_cc_gcpkms_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string kek_uri = absl::GetFlag(FLAGS_kek_uri);
  std::string input_filename = absl::GetFlag(FLAGS_input_filename);
  std::string output_filename = absl::GetFlag(FLAGS_output_filename);
  std::string credentials = absl::GetFlag(FLAGS_credentials);
  std::string associated_data = absl::GetFlag(FLAGS_associated_data);

  LOG(INFO) << "Using kek-uri " << kek_uri << " with "
            << (credentials.empty()
                    ? "default credentials"
                    : absl::StrCat("credentials file ", credentials))
            << " to envelope " << mode << " file " << input_filename
            << " with associated data '" << associated_data << "'." << '\n';
  LOG(INFO) << "The resulting output will be written to " << output_filename
            << '\n';

  tink_cc_gcpkms_examples::KmsEnvelopAeadCli(mode, kek_uri, input_filename,
                                             output_filename, credentials,
                                             associated_data);
  return 0;
}
// [END envelopeaead-example]
