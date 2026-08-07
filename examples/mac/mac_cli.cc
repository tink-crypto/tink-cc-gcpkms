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
// [START mac-example]
// A command-line utility for testing Tink message authentication codes (MACs)
// with Google Cloud KMS MAC keys.
#include <fstream>
#include <memory>
#include <sstream>
#include <string>

#include "absl/flags/parse.h"
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
#include "tink/integration/gcpkms/gcp_kms_mac.h"
#include "tink/mac.h"

ABSL_FLAG(std::string, mode, "", "Mode of operation {compute|verify}");
ABSL_FLAG(std::string, key_name, "",
          "Resource name of the KMS CryptoKeyVersion to use, in the form "
          "projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*");
ABSL_FLAG(std::string, input_filename, "",
          "Input file name; holds the message to authenticate or verify");
ABSL_FLAG(std::string, mac_filename, "",
          "MAC file name; written by `compute`, read by `verify`");
ABSL_FLAG(std::string, credentials, "",
          "Optional Google Cloud service account credentials file path; if not "
          "specified, the default credentials are used");

namespace {

using ::crypto::tink::Mac;
using ::crypto::tink::integration::gcpkms::CreateGcpKmsMac;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1::MakeKeyManagementServiceConnection;

constexpr absl::string_view kCompute = "compute";
constexpr absl::string_view kVerify = "verify";

void ValidateParams() {
  // [START_EXCLUDE]
  ABSL_CHECK(absl::GetFlag(FLAGS_mode) == kCompute ||
             absl::GetFlag(FLAGS_mode) == kVerify)
      << "Invalid mode " << absl::GetFlag(FLAGS_mode)
      << "; must be `compute` or `verify`";
  ABSL_CHECK(!absl::GetFlag(FLAGS_key_name).empty())
      << "Key name must be specified";
  ABSL_CHECK(!absl::GetFlag(FLAGS_input_filename).empty())
      << "Input file must be specified";
  ABSL_CHECK(!absl::GetFlag(FLAGS_mac_filename).empty())
      << "MAC file must be specified";
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

void KmsMacCli(absl::string_view mode, absl::string_view key_name,
               absl::string_view input_filename, absl::string_view mac_filename,
               absl::string_view credentials) {
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

  absl::StatusOr<std::string> message = ReadFile(input_filename);
  ABSL_CHECK_OK(message.status());

  // Cloud KMS acts as a crypto oracle: both computing and verifying the MAC
  // send the message to KMS; the key never leaves KMS.
  absl::StatusOr<std::unique_ptr<Mac>> mac =
      CreateGcpKmsMac(key_name, kms_client);
  ABSL_CHECK_OK(mac.status());

  if (mode == kCompute) {
    absl::StatusOr<std::string> tag = (*mac)->ComputeMac(*message);
    ABSL_CHECK_OK(tag.status());
    ABSL_CHECK_OK(WriteToFile(*tag, mac_filename));
  } else {  // mode == kVerify.
    absl::StatusOr<std::string> tag = ReadFile(mac_filename);
    ABSL_CHECK_OK(tag.status());
    ABSL_CHECK_OK((*mac)->VerifyMac(*tag, *message))
        << "MAC verification failed";
  }
}

}  // namespace tink_cc_gcpkms_examples

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);

  ValidateParams();

  std::string mode = absl::GetFlag(FLAGS_mode);
  std::string key_name = absl::GetFlag(FLAGS_key_name);
  std::string input_filename = absl::GetFlag(FLAGS_input_filename);
  std::string mac_filename = absl::GetFlag(FLAGS_mac_filename);
  std::string credentials = absl::GetFlag(FLAGS_credentials);

  ABSL_LOG(INFO) << "Using key " << key_name << " with "
                 << (credentials.empty()
                         ? "default credentials"
                         : absl::StrCat("credentials file ", credentials))
                 << " to " << mode << " file " << input_filename << '\n';
  ABSL_LOG(INFO) << "The MAC will be "
                 << (mode == kCompute ? "written to " : "read from ")
                 << mac_filename << '\n';

  tink_cc_gcpkms_examples::KmsMacCli(mode, key_name, input_filename,
                                     mac_filename, credentials);
  return 0;
}
// [END mac-example]
