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

#include "tink/integration/gcpkms/gcp_kms_hpke_decrypt.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/status.h"
#include "google/cloud/status_or.h"
#include "openssl/aead.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid_decrypt.h"
#include "tink/integration/gcpkms/internal/gcp_kms_util.h"
#include "tink/secret_data.h"
#include "tink/util/secret_data.h"  // IWYU pragma: keep

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::google::cloud::StatusOr;
using ::google::cloud::kms::v1::CryptoKeyVersion;
using ::google::cloud::kms::v1::DecapsulateRequest;
using ::google::cloud::kms::v1::DecapsulateResponse;
using ::google::cloud::kms::v1::PublicKey;
using ::google::cloud::kms_v1::KeyManagementServiceClient;

struct BoringSslHpkeParams {
  const EVP_HPKE_KEM* kem;
  const EVP_HPKE_KDF* kdf;
  const EVP_HPKE_AEAD* aead;
};

absl::StatusOr<BoringSslHpkeParams> FromParameters(
    const HpkeParameters& parameters) {
  const EVP_HPKE_KEM* kem = nullptr;
  switch (parameters.GetKemId()) {
    case HpkeParameters::KemId::kXWing:
      kem = EVP_hpke_xwing();
      break;
    case HpkeParameters::KemId::kMlKem768:
      kem = EVP_hpke_mlkem768();
      break;
    case HpkeParameters::KemId::kMlKem1024:
      kem = EVP_hpke_mlkem1024();
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported HPKE KEM algorithm: ",
                                       parameters.GetKemId()));
  }

  const EVP_HPKE_KDF* kdf = nullptr;
  switch (parameters.GetKdfId()) {
    case HpkeParameters::KdfId::kHkdfSha256:
      kdf = EVP_hpke_hkdf_sha256();
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported HPKE KDF algorithm: ",
                                       parameters.GetKdfId()));
  }

  const EVP_HPKE_AEAD* aead = nullptr;
  switch (parameters.GetAeadId()) {
    case HpkeParameters::AeadId::kAesGcm128:
      aead = EVP_hpke_aes_128_gcm();
      break;
    case HpkeParameters::AeadId::kAesGcm256:
      aead = EVP_hpke_aes_256_gcm();
      break;
    case HpkeParameters::AeadId::kChaCha20Poly1305:
      aead = EVP_hpke_chacha20_poly1305();
      break;
    default:
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported HPKE AEAD algorithm: ",
                                       parameters.GetAeadId()));
  }

  return BoringSslHpkeParams{kem, kdf, aead};
}

absl::StatusOr<SecretData> DecapsulateUsingCloudKms(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client,
    absl::string_view encapsulated_key) {
  DecapsulateRequest request;
  request.set_name(key_name);
  request.set_ciphertext(std::string(encapsulated_key));
  request.mutable_ciphertext_crc32c()->set_value(
      static_cast<uint32_t>(absl::ComputeCrc32c(encapsulated_key)));

  StatusOr<DecapsulateResponse> response = kms_client->Decapsulate(request);
  if (!response.ok()) {
    return absl::Status(internal::ToAbslStatusCode(response.status().code()),
                        absl::StrCat("GCP KMS Decapsulate failed: ",
                                     response.status().message()));
  }
  if (response->name() != key_name) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("The key name in the response (", response->name(),
                     ") does not match the requested key name (", key_name,
                     ")."));
  }
  if (!response->verified_ciphertext_crc32c()) {
    return absl::Status(absl::StatusCode::kInternal,
                        "The request to KMS was corrupted in-transit "
                        "(verified_ciphertext_crc32c is false).");
  }
  if (!response->has_shared_secret_crc32c() ||
      response->shared_secret_crc32c() !=
          static_cast<uint32_t>(
              absl::ComputeCrc32c(response->shared_secret()))) {
    return absl::Status(absl::StatusCode::kInternal,
                        "The KMS response is corrupted in-transit "
                        "(shared_secret_crc32c mismatch).");
  }
#if defined(TINK_CPP_SECRET_DATA_IS_STD_VECTOR)
  return util::SecretDataFromStringView(response->shared_secret());
#else
  return SecretData(response->shared_secret());
#endif
}

absl::StatusOr<std::string> OpenWithSharedSecret(
    const BoringSslHpkeParams& hpke_params, const SecretData& shared_secret,
    absl::string_view ciphertext, absl::string_view context_info) {
  bssl::UniquePtr<EVP_HPKE_CTX> context(EVP_HPKE_CTX_new());
  if (context == nullptr) {
    return absl::Status(absl::StatusCode::kInternal,
                        "Unable to allocate HPKE recipient context.");
  }
  if (!EVP_HPKE_CTX_setup_recipient_with_shared_secret(
          context.get(), hpke_params.kem, hpke_params.kdf, hpke_params.aead,
          shared_secret.data(), shared_secret.size(),
          reinterpret_cast<const uint8_t*>(context_info.data()),
          context_info.size())) {
    return absl::Status(absl::StatusCode::kUnknown,
                        "Unable to setup HPKE recipient context.");
  }
  std::string plaintext(ciphertext.size(), '\0');
  size_t out_len;
  if (!EVP_HPKE_CTX_open(
          context.get(), reinterpret_cast<uint8_t*>(plaintext.data()), &out_len,
          plaintext.size(), reinterpret_cast<const uint8_t*>(ciphertext.data()),
          ciphertext.size(), /*ad=*/nullptr, /*ad_len=*/0)) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "Unable to open ciphertext.");
  }
  plaintext.resize(out_len);
  return plaintext;
}

class GcpKmsHybridDecrypt : public HybridDecrypt {
 public:
  GcpKmsHybridDecrypt(
      absl::string_view key_name,
      absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client,
      const BoringSslHpkeParams& hpke_params)
      : key_name_(key_name),
        kms_client_(std::move(kms_client)),
        hpke_params_(hpke_params) {}

  absl::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override {
    size_t encapsulated_key_len = EVP_HPKE_KEM_enc_len(hpke_params_.kem);
    size_t aead_tag_len =
        EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(hpke_params_.aead));
    if (ciphertext.size() < encapsulated_key_len + aead_tag_len) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          "Ciphertext is too short.");
    }
    absl::string_view encapsulated_key =
        ciphertext.substr(0, encapsulated_key_len);
    absl::string_view aead_ciphertext = ciphertext.substr(encapsulated_key_len);

    absl::StatusOr<SecretData> shared_secret =
        DecapsulateUsingCloudKms(key_name_, kms_client_, encapsulated_key);
    if (!shared_secret.ok()) {
      return shared_secret.status();
    }
    return OpenWithSharedSecret(hpke_params_, *shared_secret, aead_ciphertext,
                                context_info);
  }

 private:
  std::string key_name_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
  BoringSslHpkeParams hpke_params_;
};

}  // namespace

absl::StatusOr<std::unique_ptr<HybridDecrypt>> CreateGcpKmsHybridDecrypt(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client,
    const crypto::tink::HpkeParameters& hpke_parameters) {
  absl::StatusOr<internal::KemAlgorithmInfo> kem_info =
      internal::GetKemAlgorithmInfo(hpke_parameters.GetKemId());
  if (!kem_info.ok()) {
    return kem_info.status();
  }
  absl::StatusOr<BoringSslHpkeParams> hpke_params =
      FromParameters(hpke_parameters);
  if (!hpke_params.ok()) {
    return hpke_params.status();
  }
  if (hpke_parameters.HasIdRequirement()) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Cannot create primitive for parameters with ID requirement.");
  }
  absl::Status validation_status = internal::ValidateResourceName(key_name);
  if (!validation_status.ok()) {
    return validation_status;
  }
  if (kms_client == nullptr) {
    return absl::Status(absl::StatusCode::kInvalidArgument,
                        "KMS client cannot be null.");
  }

  absl::StatusOr<PublicKey> public_key =
      internal::FetchKmsPublicKey(key_name, kms_client, kem_info->format);
  if (!public_key.ok()) {
    return public_key.status();
  }
  if (public_key->algorithm() != kem_info->algorithm) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Algorithm mismatch: expected ",
                     CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(
                         kem_info->algorithm),
                     ", got ",
                     CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(
                         public_key->algorithm())));
  }

  return std::make_unique<GcpKmsHybridDecrypt>(key_name, std::move(kms_client),
                                               *hpke_params);
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
