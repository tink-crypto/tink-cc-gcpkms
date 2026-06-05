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

#ifndef TINK_INTEGRATION_GCPKMS_INTERNAL_GCP_KMS_UTIL_H_
#define TINK_INTEGRATION_GCPKMS_INTERNAL_GCP_KMS_UTIL_H_

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "google/cloud/status.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace internal {

// Converts a Google Cloud StatusCode to an Abseil StatusCode.
absl::StatusCode ToAbslStatusCode(google::cloud::StatusCode code);

// Validates the format of the given KMS key name.
//
// Valid values for `key_name` have the following format:
//    projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*.
// See https://cloud.google.com/kms/docs/object-hierarchy for more info.
absl::Status ValidateResourceName(absl::string_view key_name);

}  // namespace internal
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_GCPKMS_INTERNAL_GCP_KMS_UTIL_H_
