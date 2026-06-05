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

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/status.h"
#include "re2/re2.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace internal {

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
