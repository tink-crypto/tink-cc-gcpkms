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

#include "tink/integration/gcpkms/internal/gcp_kms_test_client.h"

#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/credentials.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/key_management_connection.h"
#include "google/cloud/options.h"
#include "tink/integration/gcpkms/internal/test_file_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace internal {
namespace {

using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1::MakeKeyManagementServiceConnection;

constexpr absl::string_view kCredentialsPath = "testdata/gcp/credential.json";
constexpr absl::string_view kRootPemPath = "google_root_pem/file/downloaded";



}  // namespace

void SetGrpcDefaultSslRootsForTesting() {
  absl::StatusOr<std::string> root_pem_path =
      crypto::tink::internal::RunfilesPath(kRootPemPath);
  if (!root_pem_path.ok() || root_pem_path->empty()) {
    return;
  }
  setenv("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", root_pem_path->c_str(),
         /*overwrite=*/false);
}

absl::StatusOr<std::shared_ptr<KeyManagementServiceClient>>
CreateKmsClientForTesting() {
  absl::StatusOr<std::string> credentials_path =
      crypto::tink::internal::RunfilesPath(kCredentialsPath);
  if (!credentials_path.ok()) {
    return credentials_path.status();
  }
  absl::StatusOr<std::string> json_credentials =
      crypto::tink::internal::ReadFile(*credentials_path);
  if (!json_credentials.ok()) {
    return json_credentials.status();
  }

  google::cloud::Options options;
  options.set<google::cloud::UnifiedCredentialsOption>(
      google::cloud::MakeServiceAccountCredentials(*json_credentials));
  return std::make_shared<KeyManagementServiceClient>(
      MakeKeyManagementServiceConnection(options));
}

}  // namespace internal
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
