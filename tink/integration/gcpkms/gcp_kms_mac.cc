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
#include "tink/integration/gcpkms/gcp_kms_mac.h"

#include <memory>
#include <string>

#include "absl/base/nullability.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "re2/re2.h"
#include "tink/mac.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::google::cloud::kms_v1::KeyManagementServiceClient;

//  TODO: move it to the shared util library
static constexpr LazyRE2 kKmsKeyNameFormat = {
    "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/"
    "cryptoKeyVersions/.*"};

// GcpKmsMac is an implementation of Mac that forwards MAC computation requests
// to Google Cloud KMS (https://cloud.google.com/kms/).
class GcpKmsMac : public Mac {
 public:
  absl::StatusOr<std::string> ComputeMac(absl::string_view data) const override;

  absl::Status VerifyMac(absl::string_view mac_value,
                         absl::string_view data) const override;

  GcpKmsMac(absl::string_view key_name,
            std::shared_ptr<KeyManagementServiceClient> kms_client)
      : key_name_(key_name), kms_client_(kms_client) {}

 private:
  // The resourcename of a crypto key version in GCP KMS.
  std::string key_name_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

absl::StatusOr<std::string> GcpKmsMac::ComputeMac(
    absl::string_view data) const {
  return absl::UnimplementedError("Not implemented");
}

absl::Status GcpKmsMac::VerifyMac(absl::string_view mac_value,
                                  absl::string_view data) const {
  return absl::UnimplementedError("Not implemented");
}

}  // namespace

absl::StatusOr<std::unique_ptr<Mac>> CreateGcpKmsMac(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client) {
  if (!RE2::FullMatch(key_name, *kKmsKeyNameFormat)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(key_name,
                     " does not match the KMS key version name format: ",
                     kKmsKeyNameFormat->pattern()));
  }
  if (kms_client == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "KMS client cannot be null.");
  }
  return absl::make_unique<GcpKmsMac>(key_name, kms_client);
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
