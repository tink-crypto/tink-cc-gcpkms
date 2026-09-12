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

#include "tink/integration/gcpkms/gcp_kms_public_key_verify.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include "absl/base/nullability.h"
#include "absl/functional/overload.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "tink/integration/gcpkms/internal/gcp_kms_util.h"
#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/partial_key_access_token.h"
#include "tink/pem/signature_key_parser.h"
#include "tink/public_key_verify.h"
#include "tink/signature/config_2026.h"
#include "tink/signature/ecdsa_parameters.h"
#include "tink/signature/ecdsa_public_key.h"
#include "tink/signature/key_gen_config_2026.h"
#include "tink/signature/ml_dsa_parameters.h"
#include "tink/signature/ml_dsa_public_key.h"
#include "tink/signature/rsa_ssa_pkcs1_parameters.h"
#include "tink/signature/rsa_ssa_pkcs1_public_key.h"
#include "tink/signature/rsa_ssa_pss_parameters.h"
#include "tink/signature/rsa_ssa_pss_public_key.h"
#include "tink/signature/signature_config.h"
#include "tink/signature/signature_parameters.h"
#include "tink/signature/signature_public_key.h"
#include "tink/signature/slh_dsa_parameters.h"
#include "tink/signature/slh_dsa_public_key.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::google::cloud::kms::v1::CryptoKeyVersion;
using ::google::cloud::kms::v1::PublicKey;
using ::google::cloud::kms_v1::KeyManagementServiceClient;

// Returns whether or not the algorithm is currently supported for verification
// through Tink. Not all Cloud KMS algorithms are supported.
bool IsValidAlgorithm(
    const CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
    case CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case CryptoKeyVersion::EC_SIGN_P384_SHA384:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_44:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_65:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_87:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_44_EXTERNAL_MU:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_65_EXTERNAL_MU:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_87_EXTERNAL_MU:
    case CryptoKeyVersion::PQ_SIGN_SLH_DSA_SHA2_128S:
      return true;
    default:
      return false;
  }
}

// Parameters used by the GcpSignaturePublicKey class.
class GcpSignaturePublicKeyParameters : public SignatureParameters {
 public:
  // Copyable and movable.
  GcpSignaturePublicKeyParameters(
      const GcpSignaturePublicKeyParameters& other) = default;
  GcpSignaturePublicKeyParameters& operator=(
      const GcpSignaturePublicKeyParameters& other) = default;
  GcpSignaturePublicKeyParameters(GcpSignaturePublicKeyParameters&& other) =
      default;
  GcpSignaturePublicKeyParameters& operator=(
      GcpSignaturePublicKeyParameters&& other) = default;

  // Creates a new GcpSignaturePublicKey parameters object.
  static absl::StatusOr<GcpSignaturePublicKeyParameters> Create(
      absl::string_view public_key,
      CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
    if (!IsValidAlgorithm(algorithm)) {
      return absl::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
    }

    return GcpSignaturePublicKeyParameters(public_key, algorithm);
  }

  absl::string_view GetPublicKey() const { return public_key_; }
  CryptoKeyVersion::CryptoKeyVersionAlgorithm GetAlgorithm() const {
    return algorithm_;
  }

  bool HasIdRequirement() const override {
    // No ID requirements, we don't prepend/append values to signatures.
    return false;
  }

  bool operator==(const Parameters& other) const override {
    const GcpSignaturePublicKeyParameters* that =
        dynamic_cast<const GcpSignaturePublicKeyParameters*>(&other);
    if (that == nullptr) {
      return false;
    }
    return algorithm_ == that->algorithm_ && public_key_ == that->public_key_;
  }

  std::unique_ptr<Parameters> Clone() const override {
    return std::make_unique<GcpSignaturePublicKeyParameters>(*this);
  }

 private:
  explicit GcpSignaturePublicKeyParameters(
      absl::string_view public_key,
      CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm)
      : public_key_(std::string(public_key)), algorithm_(algorithm) {}

  std::string public_key_;
  CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm_;
};

class GcpSignaturePublicKey : public SignaturePublicKey {
 public:
  // Copyable and movable.
  GcpSignaturePublicKey(const GcpSignaturePublicKey& other) = default;
  GcpSignaturePublicKey& operator=(const GcpSignaturePublicKey& other) =
      default;
  GcpSignaturePublicKey(GcpSignaturePublicKey&& other) = default;
  GcpSignaturePublicKey& operator=(GcpSignaturePublicKey&& other) = default;

  static absl::StatusOr<GcpSignaturePublicKey> Create(
      absl::string_view public_key,
      CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
      PartialKeyAccessToken token) {
    absl::StatusOr<GcpSignaturePublicKeyParameters> params =
        GcpSignaturePublicKeyParameters::Create(public_key, algorithm);
    if (!params.ok()) {
      return params.status();
    }
    return GcpSignaturePublicKey(*params);
  }

  absl::string_view GetPublicKey() const {
    return GetParameters().GetPublicKey();
  }

  CryptoKeyVersion::CryptoKeyVersionAlgorithm GetAlgorithm() const {
    return GetParameters().GetAlgorithm();
  }

  absl::string_view GetOutputPrefix() const override { return ""; }
  const GcpSignaturePublicKeyParameters& GetParameters() const override {
    return parameters_;
  }
  std::optional<int32_t> GetIdRequirement() const override {
    // No ID requirement.
    return std::nullopt;
  }

  bool operator==(const Key& other) const override {
    const GcpSignaturePublicKey* that =
        dynamic_cast<const GcpSignaturePublicKey*>(&other);
    if (that == nullptr) return false;
    return GetParameters() == that->GetParameters();
  }

  std::unique_ptr<Key> Clone() const override {
    return std::make_unique<GcpSignaturePublicKey>(*this);
  }

 private:
  explicit GcpSignaturePublicKey(GcpSignaturePublicKeyParameters params)
      : parameters_(params) {}

  GcpSignaturePublicKeyParameters parameters_;
};

// Builds a Tink keyset entry for the given ML-DSA instance and raw public key.
absl::StatusOr<crypto::tink::KeysetHandleBuilder::Entry> GetMlDsaKeysetEntry(
    const MlDsaParameters::Instance instance, absl::string_view public_key) {
  absl::StatusOr<MlDsaParameters> params =
      MlDsaParameters::Create(instance, MlDsaParameters::Variant::kNoPrefix);
  if (!params.ok()) {
    return params.status();
  }
  absl::StatusOr<MlDsaPublicKey> signature_public_key = MlDsaPublicKey::Create(
      *params, public_key, std::nullopt, GetPartialKeyAccess());
  if (!signature_public_key.ok()) {
    return signature_public_key.status();
  }
  return crypto::tink::KeysetHandleBuilder::Entry::CreateFromKey(
      std::make_shared<const MlDsaPublicKey>(*std::move(signature_public_key)),
      crypto::tink::KeyStatus::kEnabled,
      /*is_primary=*/true);
}

// Converts the given raw PQC key into a Tink Keyset Handle.
absl::StatusOr<KeysetHandle> GetTinkKeySetHandleFromPqcKey(
    const CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    absl::string_view public_key) {
  auto keyset_handle_builder = crypto::tink::KeysetHandleBuilder();
  switch (algorithm) {
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_44:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_44_EXTERNAL_MU: {
      absl::StatusOr<crypto::tink::KeysetHandleBuilder::Entry> entry =
          GetMlDsaKeysetEntry(MlDsaParameters::Instance::kMlDsa44, public_key);
      if (!entry.ok()) {
        return entry.status();
      }
      keyset_handle_builder.AddEntry(*std::move(entry));
      break;
    }
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_65:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_65_EXTERNAL_MU: {
      absl::StatusOr<crypto::tink::KeysetHandleBuilder::Entry> entry =
          GetMlDsaKeysetEntry(MlDsaParameters::Instance::kMlDsa65, public_key);
      if (!entry.ok()) {
        return entry.status();
      }
      keyset_handle_builder.AddEntry(*std::move(entry));
      break;
    }
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_87:
    case CryptoKeyVersion::PQ_SIGN_ML_DSA_87_EXTERNAL_MU: {
      absl::StatusOr<crypto::tink::KeysetHandleBuilder::Entry> entry =
          GetMlDsaKeysetEntry(MlDsaParameters::Instance::kMlDsa87, public_key);
      if (!entry.ok()) {
        return entry.status();
      }
      keyset_handle_builder.AddEntry(*std::move(entry));
      break;
    }
    case CryptoKeyVersion::PQ_SIGN_SLH_DSA_SHA2_128S: {
      absl::StatusOr<SlhDsaParameters> params = SlhDsaParameters::Create(
          SlhDsaParameters::HashType::kSha2, /*private_key_size_in_bytes=*/64,
          SlhDsaParameters::SignatureType::kSmallSignature,
          SlhDsaParameters::Variant::kNoPrefix);
      if (!params.ok()) {
        return params.status();
      }
      auto signature_public_key = SlhDsaPublicKey::Create(
          *params, public_key, std::nullopt, GetPartialKeyAccess());
      if (!signature_public_key.ok()) {
        return signature_public_key.status();
      }
      crypto::tink::KeysetHandleBuilder::Entry entry =
          crypto::tink::KeysetHandleBuilder::Entry::CreateFromKey(
              std::make_shared<const SlhDsaPublicKey>(
                  std::move(*signature_public_key)),
              crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true);
      keyset_handle_builder.AddEntry(std::move(entry));
      break;
    }
    default:
      return absl::InternalError(absl::StrCat(
          "The given algorithm ",
          CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(algorithm),
          " is not supported for verification."));
  }

  return keyset_handle_builder.Build(KeyGenConfigSignature2026());
}

absl::StatusOr<PublicKey> GetGcpKmsPublicKey(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client) {
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
      internal::FetchKmsPublicKey(key_name, kms_client);
  if (!response.ok()) {
    return response.status();
  }

  if (!IsValidAlgorithm(response->algorithm())) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Unsupported algorithm: ", response->algorithm()));
  }
  // Getting the value is ok as status is checked above, and needed for
  // implicit conversion.
  return response.value();
}

using KeyParams =
    std::variant<EcdsaParameters, RsaSsaPkcs1Parameters, RsaSsaPssParameters>;
using TinkPublicKey =
    std::variant<EcdsaPublicKey, RsaSsaPkcs1PublicKey, RsaSsaPssPublicKey>;

absl::StatusOr<KeyParams> GetKeyParams(
    const CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case CryptoKeyVersion::EC_SIGN_P256_SHA256:
      return EcdsaParameters::Builder()
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetCurveType(EcdsaParameters::CurveType::kNistP256)
          .SetHashType(EcdsaParameters::HashType::kSha256)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return EcdsaParameters::Builder()
          .SetSignatureEncoding(EcdsaParameters::SignatureEncoding::kDer)
          .SetCurveType(EcdsaParameters::CurveType::kNistP384)
          .SetHashType(EcdsaParameters::HashType::kSha384)
          .SetVariant(EcdsaParameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256:
      return RsaSsaPssParameters::Builder()
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetModulusSizeInBits(2048)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256:
      return RsaSsaPssParameters::Builder()
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetModulusSizeInBits(3072)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256:
      return RsaSsaPssParameters::Builder()
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha256)
          .SetSaltLengthInBytes(32)
          .SetModulusSizeInBits(4096)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512:
      return RsaSsaPssParameters::Builder()
          .SetMgf1HashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSigHashType(RsaSsaPssParameters::HashType::kSha512)
          .SetSaltLengthInBytes(64)
          .SetModulusSizeInBits(4096)
          .SetVariant(RsaSsaPssParameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
      return RsaSsaPkcs1Parameters::Builder()
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetModulusSizeInBits(2048)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
      return RsaSsaPkcs1Parameters::Builder()
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetModulusSizeInBits(3072)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
      return RsaSsaPkcs1Parameters::Builder()
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha256)
          .SetModulusSizeInBits(4096)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return RsaSsaPkcs1Parameters::Builder()
          .SetHashType(RsaSsaPkcs1Parameters::HashType::kSha512)
          .SetModulusSizeInBits(4096)
          .SetVariant(RsaSsaPkcs1Parameters::Variant::kNoPrefix)
          .Build();
    default:
      return absl::InternalError(absl::StrCat(
          "The given algorithm ",
          CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(algorithm),
          " is not supported for verification."));
  }
}

// Converts the given PEM key into a Tink Keyset Handle.
absl::StatusOr<KeysetHandle> GetTinkKeySetHandleFromPemKey(
    const CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    absl::string_view pem_key) {
  absl::StatusOr<KeyParams> key_params = GetKeyParams(algorithm);
  if (!key_params.ok()) {
    return key_params.status();
  }

  absl::StatusOr<TinkPublicKey> public_key = std::visit(
      absl::Overload(
          [&pem_key](
              const EcdsaParameters& params) -> absl::StatusOr<TinkPublicKey> {
            return tink_pem::PemToEcdsaPublicKey(pem_key, params,
                                                 GetPartialKeyAccess());
          },
          [&pem_key](const RsaSsaPkcs1Parameters& params)
              -> absl::StatusOr<TinkPublicKey> {
            return tink_pem::PemToRsaSsaPkcs1PublicKey(pem_key, params,
                                                       GetPartialKeyAccess());
          },
          [&pem_key](const RsaSsaPssParameters& params)
              -> absl::StatusOr<TinkPublicKey> {
            return tink_pem::PemToRsaSsaPssPublicKey(pem_key, params,
                                                     GetPartialKeyAccess());
          }),
      *key_params);
  if (!public_key.ok()) {
    return public_key.status();
  }
  KeysetHandleBuilder builder;
  std::visit(
      [&builder](const auto& key) {
        builder.AddEntry(KeysetHandleBuilder::Entry::CreateFromCopyableKey(
            key, KeyStatus::kEnabled,
            /*is_primary=*/true));
      },
      *public_key);
  return builder.Build(KeyGenConfigSignature2026());
}

// Uses the right internal verifier based on the KMS `algorithm`, and converts
// the public key to the right format accordingly.
absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
GetInternalVerifierForAlgorithm(
    CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    absl::string_view public_key) {
  absl::StatusOr<KeysetHandle> keyset_handle;
  if (internal::IsPqcAlgorithm(algorithm)) {
    keyset_handle = GetTinkKeySetHandleFromPqcKey(algorithm, public_key);
  } else {
    keyset_handle = GetTinkKeySetHandleFromPemKey(algorithm, public_key);
  }
  if (!keyset_handle.ok()) {
    return keyset_handle.status();
  }
  return keyset_handle->GetPrimitive<crypto::tink::PublicKeyVerify>(
      ConfigSignature2026());
}

// GcpKmsPublicKeyVerify is an implementation of PublicKeyVerify that uses an
// internal verifier based on the KMS algorithm (https://cloud.google.com/kms/).
class GcpKmsPublicKeyVerify : public PublicKeyVerify {
 public:
  explicit GcpKmsPublicKeyVerify(
      std::unique_ptr<PublicKeyVerify> internal_verifier)
      : internal_verifier_(std::move(internal_verifier)) {}

  absl::Status Verify(absl::string_view signature,
                      absl::string_view data) const override {
    return internal_verifier_->Verify(signature, data);
  }

 private:
  std::unique_ptr<PublicKeyVerify> internal_verifier_;
};
}  // namespace

absl::StatusOr<std::shared_ptr<const SignaturePublicKey>>
CreateSignaturePublicKey(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client) {
  auto gcp_kms_public_key = GetGcpKmsPublicKey(key_name, kms_client);
  if (!gcp_kms_public_key.ok()) {
    return gcp_kms_public_key.status();
  }

  // Needed for the cast to crypto::tink::SignaturePublicKey.
  auto register_status = SignatureConfig::Register();
  if (!register_status.ok()) {
    return register_status;
  }
  absl::StatusOr<KeysetHandle> tink_keyset_handle;
  if (internal::IsPqcAlgorithm(gcp_kms_public_key->algorithm())) {
    tink_keyset_handle =
        GetTinkKeySetHandleFromPqcKey(gcp_kms_public_key->algorithm(),
                                      gcp_kms_public_key->public_key().data());
  } else {
    tink_keyset_handle =
        GetTinkKeySetHandleFromPemKey(gcp_kms_public_key->algorithm(),
                                      gcp_kms_public_key->public_key().data());
  }
  if (!tink_keyset_handle.ok()) {
    return tink_keyset_handle.status();
  }

  // Assumes the public key is set as primary key in the keyset.
  // Validate to return error instead of crashing.
  auto keyset_validation = tink_keyset_handle->Validate();
  if (!keyset_validation.ok()) {
    return keyset_validation;
  }

  auto key = tink_keyset_handle->GetPrimary().GetKey();
  auto signature_public_key =
      std::dynamic_pointer_cast<const crypto::tink::SignaturePublicKey>(key);
  if (signature_public_key == nullptr) {
    return absl::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "Failed to cast key to crypto::tink::SignaturePublicKey. Keyset: ",
            tink_keyset_handle->GetKeysetInfo()));
  }
  return signature_public_key;
}

absl::StatusOr<std::unique_ptr<PublicKeyVerify>> CreateGcpKmsPublicKeyVerify(
    absl::string_view key_name,
    absl_nonnull std::shared_ptr<KeyManagementServiceClient> kms_client) {
  auto gcp_kms_public_key = GetGcpKmsPublicKey(key_name, kms_client);
  if (!gcp_kms_public_key.ok()) {
    return gcp_kms_public_key.status();
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      GetInternalVerifierForAlgorithm(gcp_kms_public_key->algorithm(),
                                      gcp_kms_public_key->public_key().data());
  if (!verifier.ok()) {
    return verifier.status();
  }
  return std::make_unique<GcpKmsPublicKeyVerify>(*std::move(verifier));
}

absl::StatusOr<std::unique_ptr<SignaturePublicKey>>
CreateSignaturePublicKeyWithNoRpcs(
    absl::string_view public_key,
    CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    PartialKeyAccessToken token) {
  absl::StatusOr<GcpSignaturePublicKey> key =
      GcpSignaturePublicKey::Create(public_key, algorithm, token);
  if (!key.ok()) {
    return key.status();
  }
  return std::make_unique<GcpSignaturePublicKey>(*key);
}

absl::StatusOr<std::unique_ptr<PublicKeyVerify>>
CreateGcpKmsPublicKeyVerifyWithNoRpcs(const SignaturePublicKey& key) {
  const GcpSignaturePublicKey* public_key =
      dynamic_cast<const GcpSignaturePublicKey*>(&key);
  if (public_key == nullptr) {
    return absl::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid SignaturePublicKey, not a GcpSignaturePublicKey.");
  }
  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      GetInternalVerifierForAlgorithm(public_key->GetAlgorithm(),
                                      public_key->GetPublicKey());
  if (!verifier.ok()) {
    return verifier.status();
  }
  return std::make_unique<GcpKmsPublicKeyVerify>(*std::move(verifier));
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
