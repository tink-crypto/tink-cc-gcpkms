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

#include "tink/integration/gcpkms/internal/gcp_kms_util.h"
#include <memory>

#include "google/cloud/kms/v1/resources.pb.h"
#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/status.h"
#include "google/cloud/status_or.h"
#include "re2/re2.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace internal {

using ::google::cloud::kms::v1::CryptoKeyVersion;
using ::google::cloud::kms::v1::GetPublicKeyRequest;
using ::google::cloud::kms::v1::PublicKey;
using ::google::cloud::kms_v1::KeyManagementServiceClient;

static constexpr LazyRE2 kKmsKeyNameFormat = {
    "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/"
    "cryptoKeyVersions/.*"};

absl::StatusCode ToAbslStatusCode(google::cloud::StatusCode code) {
  switch (code) {
    case google::cloud::StatusCode::kOk:
      return absl::StatusCode::kOk;
    case google::cloud::StatusCode::kCancelled:
      return absl::StatusCode::kCancelled;
    case google::cloud::StatusCode::kUnknown:
      return absl::StatusCode::kUnknown;
    case google::cloud::StatusCode::kInvalidArgument:
      return absl::StatusCode::kInvalidArgument;
    case google::cloud::StatusCode::kDeadlineExceeded:
      return absl::StatusCode::kDeadlineExceeded;
    case google::cloud::StatusCode::kNotFound:
      return absl::StatusCode::kNotFound;
    case google::cloud::StatusCode::kAlreadyExists:
      return absl::StatusCode::kAlreadyExists;
    case google::cloud::StatusCode::kPermissionDenied:
      return absl::StatusCode::kPermissionDenied;
    case google::cloud::StatusCode::kResourceExhausted:
      return absl::StatusCode::kResourceExhausted;
    case google::cloud::StatusCode::kFailedPrecondition:
      return absl::StatusCode::kFailedPrecondition;
    case google::cloud::StatusCode::kAborted:
      return absl::StatusCode::kAborted;
    case google::cloud::StatusCode::kOutOfRange:
      return absl::StatusCode::kOutOfRange;
    case google::cloud::StatusCode::kUnimplemented:
      return absl::StatusCode::kUnimplemented;
    case google::cloud::StatusCode::kInternal:
      return absl::StatusCode::kInternal;
    case google::cloud::StatusCode::kUnavailable:
      return absl::StatusCode::kUnavailable;
    case google::cloud::StatusCode::kDataLoss:
      return absl::StatusCode::kDataLoss;
    case google::cloud::StatusCode::kUnauthenticated:
      return absl::StatusCode::kUnauthenticated;
    default:
      return absl::StatusCode::kUnknown;
  }
}

bool IsPqcAlgorithm(CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_65:
    case CryptoKeyVersion::PQ_SIGN_SLH_DSA_SHA2_128S:
      return true;
    default:
      return false;
  }
}

absl::Status VerifyPublicKeyChecksum(const PublicKey& key) {
  absl::crc32c_t given_crc32c(key.public_key().crc32c_checksum().value());
  absl::crc32c_t computed_crc32c(absl::ComputeCrc32c(key.public_key().data()));
  if (computed_crc32c != given_crc32c) {
    return absl::InternalError("GCP KMS GetPublicKey checksum mismatch.");
  }
  return absl::OkStatus();
}

absl::StatusOr<PublicKey> FetchKmsPublicKey(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client) {
  GetPublicKeyRequest request;
  request.set_name(key_name);
  request.set_public_key_format(PublicKey::PEM);
  google::cloud::StatusOr<PublicKey> response =
      kms_client->GetPublicKey(request);
  // Retry with NIST_PQC if PEM is unsupported, or if PEM succeeded but the
  // algorithm is PQC (we prefer raw bytes for PQC keys).
  if ((!response.ok() &&
       absl::StrContains(response.status().message(),
                         "Only NIST_PQC format is supported")) ||
      (response.ok() && IsPqcAlgorithm(response->algorithm()))) {
    request.set_public_key_format(PublicKey::NIST_PQC);
    response = kms_client->GetPublicKey(request);
  }
  if (!response.ok()) {
    return absl::Status(ToAbslStatusCode(response.status().code()),
                        absl::StrCat("GCP KMS GetPublicKey failed: ",
                                     response.status().message()));
  }
  if (response->name() != key_name) {
    return absl::InternalError(
        "The key name in the response does not match the requested key name.");
  }
  absl::Status checksum_status = VerifyPublicKeyChecksum(*response);
  if (!checksum_status.ok()) {
    return checksum_status;
  }
  return *response;
}

absl::Status ValidateResourceName(absl::string_view key_name) {
  if (!RE2::FullMatch(key_name, *kKmsKeyNameFormat)) {
    return absl::InvalidArgumentError(absl::StrCat(
        key_name, " does not match the KMS key version name format: ",
                     kKmsKeyNameFormat->pattern()));
  }
  return absl::OkStatus();
}

}  // namespace internal
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
