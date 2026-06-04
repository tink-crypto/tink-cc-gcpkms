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

#include <cstdint>
#include <memory>
#include <string>

#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/status_or.h"
#include "tink/integration/gcpkms/gcp_kms_util.h"
#include "tink/mac.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::google::cloud::kms::v1::MacSignRequest;
using ::google::cloud::kms::v1::MacSignResponse;
using ::google::cloud::kms::v1::MacVerifyRequest;
using ::google::cloud::kms::v1::MacVerifyResponse;
using ::google::cloud::kms_v1::KeyManagementServiceClient;

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
  // Creates a MacSignRequest with keyname, data and the CRC32C of the data.
  MacSignRequest request;
  request.set_name(key_name_);
  request.set_data(data);
  request.mutable_data_crc32c()->set_value(
      static_cast<uint32_t>(absl::ComputeCrc32c(data)));

  google::cloud::StatusOr<MacSignResponse> response =
      kms_client_->MacSign(request);
  if (!response.ok()) {
    return absl::Status(
        ToAbslStatusCode(response.status().code()),
        absl::StrCat("GCP KMS MacSign failed: ", response.status().message()));
  }
  // Checks if response.name matches key_name.
  if (response->name() != key_name_) {
    return absl::Status(
        absl::StatusCode::kInternal,
        "The key name in the response does not match the requested key name.");
  }
  if (!response->verified_data_crc32c()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Checking the input checksum failed.");
  }
  // Computes CRC32C over response.mac and compare with response.mac_crc32c.
  uint32_t given_crc32c = static_cast<uint32_t>(response->mac_crc32c().value());
  uint32_t computed_crc32c =
      static_cast<uint32_t>(absl::ComputeCrc32c(response->mac()));
  if (computed_crc32c != given_crc32c) {
    return absl::Status(absl::StatusCode::kInternal, "MAC checksum mismatch.");
  }

  return response->mac();
}

absl::Status GcpKmsMac::VerifyMac(absl::string_view mac_value,
                                  absl::string_view data) const {
  // Creates a MacVerifyRequest with keyname, data, mac_value and their CRC32C.
  MacVerifyRequest request;
  request.set_name(key_name_);
  request.set_data(data);
  // Computes CRC32C over data.
  request.mutable_data_crc32c()->set_value(
      static_cast<uint32_t>(absl::ComputeCrc32c(data)));
  request.set_mac(mac_value);
  request.mutable_mac_crc32c()->set_value(
      static_cast<uint32_t>(absl::ComputeCrc32c(mac_value)));

  // Executes the KMS rpc with this MacVerifyRequest and receives the response.
  google::cloud::StatusOr<MacVerifyResponse> response =
      kms_client_->MacVerify(request);
  if (!response.ok()) {
    return absl::Status(ToAbslStatusCode(response.status().code()),
                        absl::StrCat("GCP KMS MacVerify failed: ",
                                     response.status().message()));
  }
  // Checks if response.name matches key_name.
  if (response->name() != key_name_) {
    return absl::Status(
        absl::StatusCode::kInternal,
        "The key name in the response does not match the requested key name.");
  }
  // Checks response.verified_data_crc32c.
  if (!response->verified_data_crc32c()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Checking the input data checksum failed.");
  }
  // Checks response.verified_mac_crc32c
  if (!response->verified_mac_crc32c()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Checking the MAC checksum failed.");
  }
  if (!response->success()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "MAC verification failed.");
  }
  // Checks if response.verified_success_integrity matches response.success.
  // This field is designed to protect the integrity of the success boolean.
  if (response->verified_success_integrity() != response->success()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Checking the verification result integrity failed.");
  }

  return absl::OkStatus();
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
  return std::make_unique<GcpKmsMac>(key_name, kms_client);
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
