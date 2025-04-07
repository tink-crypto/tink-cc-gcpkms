// Copyright 2024 Google LLC
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

#ifndef TINK_INTEGRATION_GCPKMS_GCP_KMS_PUBLIC_KEY_VERIFY_H_
#define TINK_INTEGRATION_GCPKMS_GCP_KMS_PUBLIC_KEY_VERIFY_H_

#include <memory>

#include "absl/base/nullability.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "tink/partial_key_access_token.h"
#include "tink/public_key_verify.h"
#include "tink/signature/signature_public_key.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

// Creates a new PublicKeyVerify object that is bound to the key specified
// in `key_name`, and uses the `kms_client` to communicate with Cloud KMS.
//
// Note that this verifier only reaches out to Cloud KMS once, to retrieve the
// public key associated with the specified CryptoKeyVersion. Later verification
// operations are performed locally.
//
// Valid values for `key_name` have the following format:
//    projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*.
// See https://cloud.google.com/kms/docs/object-hierarchy for more info.
absl::StatusOr<std::unique_ptr<PublicKeyVerify>> CreateGcpKmsPublicKeyVerify(
    absl::string_view key_name,
    /*absl_nonnull - not yet supported*/
    std::shared_ptr<google::cloud::kms_v1::KeyManagementServiceClient>
        kms_client);

// Creates a Tink signature public key with the specified CryptoKeyVersion
// from Cloud KMS.
//
// Valid values for `key_name` have the following format:
//    projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*.
// See https://cloud.google.com/kms/docs/object-hierarchy for more info.
absl::StatusOr<std::shared_ptr<const SignaturePublicKey>>
CreateSignaturePublicKey(absl::string_view key_name,
                         /*absl_nonnull - not yet supported*/ std::shared_ptr<
                             google::cloud::kms_v1::KeyManagementServiceClient>
                             kms_client);

// Creates a Tink signature public key from a PEM-formatted key previously
// fetched from KMS, and the associated CryptoKeyVersion algorithm.
//
// See
// https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys.cryptoKeyVersions/getPublicKey
// for more info about fetching the public key from Cloud KMS.
absl::StatusOr<std::unique_ptr<SignaturePublicKey>>
CreateSignaturePublicKeyWithNoRpcs(
    absl::string_view pem,
    google::cloud::kms::v1::CryptoKeyVersion::CryptoKeyVersionAlgorithm
        algorithm,
    PartialKeyAccessToken token);

// Creates a new PublicKeyVerify object that is bound to the Tink signature
// public key.
//
// The input key can be obtained through `CreateSignaturePublicKeyWithNoRpcs`,
// which does not call KMS and instead takes in a PEM-formatted key directly.
absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
CreateGcpKmsPublicKeyVerifyWithNoRpcs(const SignaturePublicKey& key);

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_GCPKMS_GCP_KMS_PUBLIC_KEY_VERIFY_H_
