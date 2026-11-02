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

#ifndef TINK_INTEGRATION_GCPKMS_GCP_KMS_HPKE_DECRYPT_H_
#define TINK_INTEGRATION_GCPKMS_GCP_KMS_HPKE_DECRYPT_H_

#include <memory>

#include "absl/base/nullability.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid_decrypt.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

// Creates a new HybridDecrypt object with the specified parameters
// that is bound to the key specified in `key_name` and uses the `kms_client`
// to communicate with Cloud KMS.
//
// `CreateGcpKmsHybridDecrypt` fetches the public key from KMS to validate the
// key name and parameters. The returned `HybridDecrypt` calls the Decapsulate
// KMS RPC for Decrypt operations.
//
// Valid values for `key_name` have the following format:
//    projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*.
// See https://cloud.google.com/kms/docs/object-hierarchy for more info.
absl::StatusOr<std::unique_ptr<HybridDecrypt>> CreateGcpKmsHybridDecrypt(
    absl::string_view key_name,
    absl_nonnull
    std::shared_ptr<google::cloud::kms_v1::KeyManagementServiceClient>
        kms_client,
    const HpkeParameters& hpke_parameters);

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_GCPKMS_GCP_KMS_HPKE_DECRYPT_H_
