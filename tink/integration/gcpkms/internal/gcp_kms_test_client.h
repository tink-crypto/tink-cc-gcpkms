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

#ifndef TINK_INTEGRATION_GCPKMS_INTERNAL_GCP_KMS_TEST_CLIENT_H_
#define TINK_INTEGRATION_GCPKMS_INTERNAL_GCP_KMS_TEST_CLIENT_H_

#include <memory>

#include "absl/status/statusor.h"
#include "google/cloud/kms/v1/key_management_client.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace internal {

// Points gRPC at the root certificates bundled with the test, which are needed
// on macOS where gRPC does not use the system trust store. Does nothing if the
// certificates cannot be located, in which case gRPC falls back to its own
// defaults; leaving gRPC with an empty trust store would break every RPC.
//
// Call this once per test binary, from a global test environment.
void SetGrpcDefaultSslRootsForTesting();

// Creates a Cloud KMS client that authenticates with the service account
// credentials in `testdata/gcp/credential.json`.
//
// Note that the credentials checked into this repository are invalid. To run
// tests that use this client, replace them with your own; see
// `testdata/gcp/README.md`.
absl::StatusOr<
    std::shared_ptr<google::cloud::kms_v1::KeyManagementServiceClient>>
CreateKmsClientForTesting();

}  // namespace internal
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_GCPKMS_INTERNAL_GCP_KMS_TEST_CLIENT_H_
