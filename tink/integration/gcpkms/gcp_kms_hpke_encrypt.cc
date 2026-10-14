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

#include "tink/integration/gcpkms/gcp_kms_hpke_encrypt.h"

#include <memory>
#include <optional>

#include "absl/base/nullability.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "tink/hybrid/config_2026.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid_encrypt.h"
#include "tink/integration/gcpkms/internal/gcp_kms_util.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::google::cloud::kms::v1::CryptoKeyVersion;
using ::google::cloud::kms::v1::PublicKey;
using ::google::cloud::kms_v1::KeyManagementServiceClient;

}  // namespace

absl::StatusOr<HpkePublicKey> CreateHpkePublicKey(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client,
    const crypto::tink::HpkeParameters& params) {
  absl::StatusOr<internal::KemAlgorithmInfo> kem_info =
      internal::GetKemAlgorithmInfo(params.GetKemId());
  if (!kem_info.ok()) {
    return kem_info.status();
  }
  absl::Status key_name_validation_status =
      internal::ValidateResourceName(key_name);
  if (!key_name_validation_status.ok()) {
    return key_name_validation_status;
  }
  if (kms_client == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "KMS client cannot be null.");
  }

  absl::StatusOr<PublicKey> response =
      internal::FetchKmsPublicKey(key_name, kms_client, kem_info->format);
  if (!response.ok()) {
    return response.status();
  }
  if (response->algorithm() != kem_info->algorithm) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Algorithm mismatch: expected ",
                     CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(
                         kem_info->algorithm),
                     ", got ",
                     CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(
                         response->algorithm())));
  }

  return HpkePublicKey::Create(params, response->public_key().data(),
                               /*id_requirement=*/std::nullopt,
                               GetPartialKeyAccess());
}

absl::StatusOr<std::unique_ptr<HybridEncrypt>> CreateGcpKmsHybridEncrypt(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client,
    const crypto::tink::HpkeParameters& params) {
  absl::StatusOr<HpkePublicKey> public_key =
      CreateHpkePublicKey(key_name, kms_client, params);
  if (!public_key.ok()) {
    return public_key.status();
  }
  return CreateGcpKmsHybridEncryptWithNoRpcs(*public_key);
}

absl::StatusOr<HpkePublicKey> CreateHpkePublicKeyWithNoRpcs(
    absl::string_view public_key, const crypto::tink::HpkeParameters& params,
    PartialKeyAccessToken token) {
  // Validate that the KEM algorithm is supported.
  absl::StatusOr<internal::KemAlgorithmInfo> kem_info =
      internal::GetKemAlgorithmInfo(params.GetKemId());
  if (!kem_info.ok()) {
    return kem_info.status();
  }
  return HpkePublicKey::Create(params, public_key,
                               /*id_requirement=*/std::nullopt, token);
}

absl::StatusOr<std::unique_ptr<HybridEncrypt>>
CreateGcpKmsHybridEncryptWithNoRpcs(const HpkePublicKey& key) {
  if (key.GetParameters().HasIdRequirement()) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Cannot create primitive for key with ID requirement.");
  }
  // Validate that the KEM algorithm is supported.
  absl::StatusOr<internal::KemAlgorithmInfo> kem_info =
      internal::GetKemAlgorithmInfo(key.GetParameters().GetKemId());
  if (!kem_info.ok()) {
    return kem_info.status();
  }
  KeysetHandleBuilder builder;
  builder.AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
      key, KeyStatus::kEnabled, /*is_primary=*/true));
  absl::StatusOr<KeysetHandle> handle = builder.Build();
  if (!handle.ok()) {
    return handle.status();
  }
  return handle->GetPrimitive<HybridEncrypt>(ConfigHybrid2026());
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
