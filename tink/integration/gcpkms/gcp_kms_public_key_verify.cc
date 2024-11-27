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
#include <memory>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/status_or.h"
#include "re2/re2.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/key.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/public_key_verify.h"
#include "tink/signature/config_v0.h"
#include "tink/signature/signature_config.h"
#include "tink/signature/signature_pem_keyset_reader.h"
#include "tink/signature/signature_public_key.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::cloud::kms::v1::CryptoKeyVersion;
using ::google::cloud::kms::v1::GetPublicKeyRequest;
using ::google::cloud::kms::v1::PublicKey;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::crypto::tink::HashType;

static constexpr LazyRE2 kKmsKeyNameFormat = {
    "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/"
    "cryptoKeyVersions/.*"};

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
  static StatusOr<GcpSignaturePublicKeyParameters> Create(
      absl::string_view pem,
      CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
    if (!IsValidAlgorithm(algorithm)) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported algorithm: ", algorithm));
    }

    return GcpSignaturePublicKeyParameters(pem, algorithm);
  }

  absl::string_view GetPem() const { return pem_; }
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
    return pem_ == that->pem_ && algorithm_ == that->algorithm_;
  }

 private:
  explicit GcpSignaturePublicKeyParameters(
      absl::string_view pem,
      CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm)
      : pem_(pem), algorithm_(algorithm) {}

  absl::string_view pem_;
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

  static StatusOr<GcpSignaturePublicKey> Create(
      absl::string_view pem,
      CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
      PartialKeyAccessToken token) {
    StatusOr<GcpSignaturePublicKeyParameters> params =
        GcpSignaturePublicKeyParameters::Create(pem, algorithm);
    if (!params.ok()) {
      return params.status();
    }
    return GcpSignaturePublicKey(*params);
  }

  absl::string_view GetPem() const { return GetParameters().GetPem(); }
  CryptoKeyVersion::CryptoKeyVersionAlgorithm GetAlgorithm() const {
    return GetParameters().GetAlgorithm();
  }

  absl::string_view GetOutputPrefix() const override { return ""; }
  const GcpSignaturePublicKeyParameters& GetParameters() const override {
    return parameters_;
  }
  absl::optional<int32_t> GetIdRequirement() const override {
    // No ID requirement.
    return absl::nullopt;
  }

  bool operator==(const Key& other) const override {
    const GcpSignaturePublicKey* that =
        dynamic_cast<const GcpSignaturePublicKey*>(&other);
    if (that == nullptr) return false;
    return GetParameters() == that->GetParameters();
  }

  virtual std::unique_ptr<Key> Clone() const {
    return std::make_unique<GcpSignaturePublicKey>(*this);
  }

 private:
  explicit GcpSignaturePublicKey(GcpSignaturePublicKeyParameters params)
      : parameters_(params) {}

  GcpSignaturePublicKeyParameters parameters_;
};

// Returns the proper key size in bits for the given KMS algorithm.
StatusOr<size_t> GetKeySizeFromAlgorithm(
    const CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case CryptoKeyVersion::EC_SIGN_P256_SHA256:
      return 256;
    case CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return 384;
    case CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
      return 2048;
    case CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
      return 3072;
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return 4096;
    default:
      return absl::InternalError(absl::StrCat(
          "Unsupported algorithm: ",
          CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(algorithm)));
  }
}

// Returns the proper Hash for the given KMS algorithm.
StatusOr<HashType> GetHashFromAlgorithm(
    const CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
      return HashType::SHA256;
    case CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return HashType::SHA384;
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return HashType::SHA512;
    default:
      return absl::InternalError(absl::StrCat(
          "The given algorithm ",
          CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(algorithm),
          " does not support digests."));
  }
}

StatusOr<PublicKey> GetGcpKmsPublicKey(
    absl::string_view key_name,
    absl::Nonnull<std::shared_ptr<KeyManagementServiceClient>> kms_client) {
  if (!RE2::FullMatch(key_name, *kKmsKeyNameFormat)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(key_name, " does not match the KMS key name format: ",
                     kKmsKeyNameFormat->pattern()));
  }
  if (kms_client == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "KMS client cannot be null.");
  }

  // Retrieve the related public key from KMS.
  GetPublicKeyRequest request;
  request.set_name(key_name);
  google::cloud::StatusOr<PublicKey> response =
      kms_client->GetPublicKey(request);
  if (!response.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("GCP KMS GetPublicKey failed: ",
                                     response.status().message()));
  }

  // Perform integrity checks.
  if (response->name() != key_name) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("The key name in the response does not "
                                     "match the requested key name.",
                                     response.status().message()));
  }
  absl::crc32c_t given_crc32c =
      static_cast<absl::crc32c_t>(response->pem_crc32c().value());
  absl::crc32c_t computed_crc32c = absl::ComputeCrc32c(response->pem());
  if (computed_crc32c != given_crc32c) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Public key checksum mismatch.",
                                     response.status().message()));
  }

  if (!IsValidAlgorithm(response->algorithm())) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Unsupported algorithm: ", response->algorithm()));
  }
  // Getting the value is ok as status is checked above, and needed for
  // implicit conversion.
  return response.value();
}

// Converts the given PEM key into a Tink Keyset Handle.
StatusOr<std::unique_ptr<KeysetHandle>> GetTinkKeySetHandleFromPemKey(
    const CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    absl::string_view pem_key) {
  StatusOr<HashType> hash_type = GetHashFromAlgorithm(algorithm);
  if (!hash_type.ok()) {
    return hash_type.status();
  }
  StatusOr<size_t> key_size = GetKeySizeFromAlgorithm(algorithm);
  if (!key_size.ok()) {
    return key_size.status();
  }

  SignaturePemKeysetReaderBuilder builder = SignaturePemKeysetReaderBuilder(
      SignaturePemKeysetReaderBuilder::PemReaderType::PUBLIC_KEY_VERIFY);
  switch (algorithm) {
    case CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case CryptoKeyVersion::EC_SIGN_P384_SHA384: {
      builder.Add({.serialized_key = std::string(pem_key),
                   .parameters = {
                       .key_type = PemKeyType::PEM_EC,
                       .algorithm = PemAlgorithm::ECDSA_DER,
                       .key_size_in_bits = *key_size,
                       .hash_type = *hash_type,
                   }});
      break;
    }
    case CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512: {
      builder.Add({.serialized_key = std::string(pem_key),
                   .parameters = {
                       .key_type = PemKeyType::PEM_RSA,
                       .algorithm = PemAlgorithm::RSASSA_PKCS1,
                       .key_size_in_bits = *key_size,
                       .hash_type = *hash_type,
                   }});
      break;
    }
    case CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512: {
      builder.Add({.serialized_key = std::string(pem_key),
                   .parameters = {
                       .key_type = PemKeyType::PEM_RSA,
                       .algorithm = PemAlgorithm::RSASSA_PSS,
                       .key_size_in_bits = *key_size,
                       .hash_type = *hash_type,
                   }});
      break;
    }
    default:
      return absl::InternalError(absl::StrCat(
          "The given algorithm ",
          CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(algorithm),
          " is not supported for verification."));
  }
  StatusOr<std::unique_ptr<KeysetReader>> keyset = builder.Build();
  if (!keyset.ok()) {
    return keyset.status();
  }
  return CleartextKeysetHandle::Read(std::move(*keyset));
}

// Uses the right internal verifier based on the KMS `algorithm`, and converts
// the public key to the right format accordingly.
StatusOr<std::unique_ptr<PublicKeyVerify>> GetInternalVerifierForAlgorithm(
    CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    absl::string_view pem_key) {
  StatusOr<std::unique_ptr<KeysetHandle>> keyset_handle =
      GetTinkKeySetHandleFromPemKey(algorithm, pem_key);
  if (!keyset_handle.ok()) {
    return keyset_handle.status();
  }
  return (*keyset_handle)
      ->GetPrimitive<crypto::tink::PublicKeyVerify>(
          crypto::tink::ConfigSignatureV0());
}

// GcpKmsPublicKeyVerify is an implementation of PublicKeyVerify that uses an
// internal verifier based on the KMS algorithm (https://cloud.google.com/kms/).
class GcpKmsPublicKeyVerify : public PublicKeyVerify {
 public:
  explicit GcpKmsPublicKeyVerify(
      std::unique_ptr<PublicKeyVerify> internal_verifier)
      : internal_verifier_(std::move(internal_verifier)) {}

  Status Verify(absl::string_view signature,
                absl::string_view data) const override {
    return internal_verifier_->Verify(signature, data);
  }

 private:
  std::unique_ptr<PublicKeyVerify> internal_verifier_;
};
}  // namespace

StatusOr<std::shared_ptr<const SignaturePublicKey>> CreateSignaturePublicKey(
    absl::string_view key_name,
    absl::Nonnull<std::shared_ptr<KeyManagementServiceClient>> kms_client) {
  auto gcp_kms_public_key = GetGcpKmsPublicKey(key_name, kms_client);
  if (!gcp_kms_public_key.ok()) {
    return gcp_kms_public_key.status();
  }

  // Needed for the cast to crypto::tink::SignaturePublicKey.
  auto register_status = SignatureConfig::Register();
  if (!register_status.ok()) {
    return register_status;
  }
  auto tink_keyset_handle = GetTinkKeySetHandleFromPemKey(
      gcp_kms_public_key->algorithm(), gcp_kms_public_key->pem());
  if (!tink_keyset_handle.ok()) {
    return tink_keyset_handle.status();
  }

  // Assumes the pem_key is set as primary key in the keyset.
  // Validate to return error instead of crashing.
  auto keyset_validation = tink_keyset_handle.value()->Validate();
  if (!keyset_validation.ok()) {
    return keyset_validation;
  }

  auto key = tink_keyset_handle.value()->GetPrimary().GetKey();
  auto signature_public_key =
      std::dynamic_pointer_cast<const crypto::tink::SignaturePublicKey>(key);
  if (signature_public_key == nullptr) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "Failed to cast key to crypto::tink::SignaturePublicKey. Keyset: ",
            tink_keyset_handle.value()->GetKeysetInfo()));
  }
  return signature_public_key;
}

StatusOr<std::unique_ptr<PublicKeyVerify>> CreateGcpKmsPublicKeyVerify(
    absl::string_view key_name,
    absl::Nonnull<std::shared_ptr<KeyManagementServiceClient>> kms_client) {
  auto gcp_kms_public_key = GetGcpKmsPublicKey(key_name, kms_client);
  if (!gcp_kms_public_key.ok()) {
    return gcp_kms_public_key.status();
  }
  StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      GetInternalVerifierForAlgorithm(gcp_kms_public_key->algorithm(),
                                      gcp_kms_public_key->pem());
  if (!verifier.ok()) {
    return verifier.status();
  }
  return absl::make_unique<GcpKmsPublicKeyVerify>(*std::move(verifier));
}

StatusOr<std::unique_ptr<SignaturePublicKey>>
CreateSignaturePublicKeyWithNoRpcs(
    absl::string_view pem,
    CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
    PartialKeyAccessToken token) {
  StatusOr<GcpSignaturePublicKey> key =
      GcpSignaturePublicKey::Create(pem, algorithm, token);
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<GcpSignaturePublicKey>(*key);
}

StatusOr<std::unique_ptr<PublicKeyVerify>>
CreateGcpKmsPublicKeyVerifyWithNoRpcs(const SignaturePublicKey& key) {
  const GcpSignaturePublicKey* public_key =
      dynamic_cast<const GcpSignaturePublicKey*>(&key);
  if (public_key == nullptr) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Invalid SignaturePublicKey, not a GcpSignaturePublicKey.");
  }
  StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      GetInternalVerifierForAlgorithm(public_key->GetAlgorithm(),
                                      public_key->GetPem());
  if (!verifier.ok()) {
    return verifier.status();
  }
  return absl::make_unique<GcpKmsPublicKeyVerify>(*std::move(verifier));
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
