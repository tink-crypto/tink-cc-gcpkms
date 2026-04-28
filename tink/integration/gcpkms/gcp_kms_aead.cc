// Copyright 2019 Google LLC
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

#include "tink/integration/gcpkms/gcp_kms_aead.h"

#include <cstdint>
#include <memory>
#include <string>

#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "grpcpp/client_context.h"
#include "grpcpp/support/status.h"
#include "absl/crc/crc32c.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "re2/re2.h"
#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

static constexpr LazyRE2 kKmsKeyNameFormat = {
    "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/.*"};

using ::google::cloud::kms::v1::DecryptRequest;
using ::google::cloud::kms::v1::DecryptResponse;
using ::google::cloud::kms::v1::EncryptRequest;
using ::google::cloud::kms::v1::EncryptResponse;
using ::google::cloud::kms::v1::KeyManagementService;

absl::StatusOr<std::unique_ptr<Aead>> NewGcpKmsAead(
    absl::string_view key_name,
    std::shared_ptr<google::cloud::kms_v1::KeyManagementServiceClient>
        kms_client) {
  if (!RE2::FullMatch(key_name, *kKmsKeyNameFormat)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(key_name, " does not match the KMS key name format: ",
                     kKmsKeyNameFormat->pattern()));
  }
  if (kms_client == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "KMS client cannot be null.");
  }
  return absl::WrapUnique(new GcpKmsAead(key_name, kms_client));
}

absl::StatusOr<std::unique_ptr<Aead>> GcpKmsAead::New(
    absl::string_view key_name,
    std::shared_ptr<KeyManagementService::Stub> kms_stub) {
  if (!RE2::FullMatch(key_name, *kKmsKeyNameFormat)) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(key_name, " does not match the KMS key name format: ",
                     kKmsKeyNameFormat->pattern()));
  }
  if (kms_stub == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "KMS stub cannot be null.");
  }
  return absl::WrapUnique(new GcpKmsAead(key_name, kms_stub));
}

absl::StatusOr<std::string> GcpKmsAead::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  EncryptRequest req;
  req.set_name(key_name_);
  req.set_plaintext(plaintext);
  req.set_additional_authenticated_data(associated_data);
  // Set request-side CRC32C so the KMS server can verify request integrity
  // and confirm receipt via the verified_*_crc32c response fields. See
  // https://cloud.google.com/kms/docs/data-integrity-guidelines.
  req.mutable_plaintext_crc32c()->set_value(
      static_cast<int64_t>(absl::ComputeCrc32c(plaintext)));
  req.mutable_additional_authenticated_data_crc32c()->set_value(
      static_cast<int64_t>(absl::ComputeCrc32c(associated_data)));

  if (kms_client_) {
    auto response = kms_client_->Encrypt(req);
    if (!response.ok()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("GCP KMS encryption failed: ",
                                       response.status().message()));
    }
    if (!response->verified_plaintext_crc32c()) {
      return absl::Status(
          absl::StatusCode::kInternal,
          absl::StrCat(
              "KMS request for ", key_name_,
              " is missing the checksum field plaintext_crc32c, and other "
              "information may be missing from the response. Please retry a "
              "limited number of times in case the error is transient."));
    }
    if (!response->verified_additional_authenticated_data_crc32c()) {
      return absl::Status(
          absl::StatusCode::kInternal,
          absl::StrCat(
              "KMS request for ", key_name_,
              " is missing the checksum field "
              "additional_authenticated_data_crc32c, and other information "
              "may be missing from the response. Please retry a limited "
              "number of times in case the error is transient."));
    }
    if (response->ciphertext_crc32c().value() !=
        static_cast<int64_t>(absl::ComputeCrc32c(response->ciphertext()))) {
      return absl::Status(
          absl::StatusCode::kInternal,
          absl::StrCat(
              "KMS response corrupted in transit for ", key_name_,
              ": the checksum in field ciphertext_crc32c did not match the "
              "data in field ciphertext. Please retry in case this is a "
              "transient error."));
    }
    return response->ciphertext();
  }

  EncryptResponse resp;
  grpc::ClientContext context;
  context.AddMetadata("x-goog-request-params",
                      absl::StrCat("name=", key_name_));

  grpc::Status status = kms_stub_->Encrypt(&context, req, &resp);

  if (!status.ok()) {
    return absl::Status(
        static_cast<absl::StatusCode>(status.error_code()),
        absl::StrCat("GCP KMS encryption failed: ", status.error_message()));
  }
  if (!resp.verified_plaintext_crc32c()) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "KMS request for ", key_name_,
            " is missing the checksum field plaintext_crc32c, and other "
            "information may be missing from the response. Please retry a "
            "limited number of times in case the error is transient."));
  }
  if (!resp.verified_additional_authenticated_data_crc32c()) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "KMS request for ", key_name_,
            " is missing the checksum field "
            "additional_authenticated_data_crc32c, and other information may "
            "be missing from the response. Please retry a limited number of "
            "times in case the error is transient."));
  }
  if (resp.ciphertext_crc32c().value() !=
      static_cast<int64_t>(absl::ComputeCrc32c(resp.ciphertext()))) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "KMS response corrupted in transit for ", key_name_,
            ": the checksum in field ciphertext_crc32c did not match the "
            "data in field ciphertext. Please retry in case this is a "
            "transient error."));
  }
  return resp.ciphertext();
}

absl::StatusOr<std::string> GcpKmsAead::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  DecryptRequest req;
  req.set_name(key_name_);
  req.set_ciphertext(ciphertext);
  req.set_additional_authenticated_data(associated_data);
  if (kms_client_) {
    auto response = kms_client_->Decrypt(req);
    if (!response.ok()) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("GCP KMS decryption failed: ",
                                       response.status().message()));
    }
    return response->plaintext();
  }

  DecryptResponse resp;
  grpc::ClientContext context;
  context.AddMetadata("x-goog-request-params",
                      absl::StrCat("name=", key_name_));

  grpc::Status status = kms_stub_->Decrypt(&context, req, &resp);

  if (!status.ok()) {
    return absl::Status(
        static_cast<absl::StatusCode>(status.error_code()),
        absl::StrCat("GCP KMS decryption failed: ", status.error_message()));
  }
  return resp.plaintext();
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
