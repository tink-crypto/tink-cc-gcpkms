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

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/cloud/status.h"
#include "google/cloud/status_or.h"
#include "tink/hybrid/config_2026.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_private_key.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid/key_gen_config_2026.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyset_handle.h"
#include "tink/partial_key_access.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kKeyNameXWing =
    "projects/test-project/locations/us-central1/keyRings/test-keyring/"
    "cryptoKeys/xwing-key/cryptoKeyVersions/1";
constexpr absl::string_view kKeyNameMlKem768 =
    "projects/test-project/locations/us-central1/keyRings/test-keyring/"
    "cryptoKeys/mlkem768-key/cryptoKeyVersions/1";
constexpr absl::string_view kKeyNameMlKem1024 =
    "projects/test-project/locations/us-central1/keyRings/test-keyring/"
    "cryptoKeys/mlkem1024-key/cryptoKeyVersions/1";
constexpr absl::string_view kKeyNameErrorGetPublicKey =
    "projects/test-project/locations/us-central1/keyRings/test-keyring/"
    "cryptoKeys/error-key/cryptoKeyVersions/1";
constexpr absl::string_view kKeyNameCrcError =
    "projects/test-project/locations/us-central1/keyRings/test-keyring/"
    "cryptoKeys/crc-error-key/cryptoKeyVersions/1";

class TestGcpKmsHybridEncrypt : public testing::Test {
 public:
  static void SetUpTestSuite() { (void)ConfigHybrid2026(); }

  void SetUp() override {
    mock_connection_ = std::make_shared<MockKeyManagementServiceConnection>();
    kms_client_ =
        std::make_shared<KeyManagementServiceClient>(mock_connection_);

    // Generate valid test key material using Tink public APIs.
    absl::StatusOr<HpkeParameters> xwing_params =
        HpkeParameters::Builder()
            .SetKemId(HpkeParameters::KemId::kXWing)
            .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
            .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
            .SetVariant(HpkeParameters::Variant::kNoPrefix)
            .Build();
    ASSERT_THAT(xwing_params, IsOk());
    xwing_params_ = *xwing_params;

    absl::StatusOr<std::unique_ptr<KeysetHandle>> xwing_handle =
        KeysetHandle::GenerateNewFromParameters(*xwing_params_,
                                                KeyGenConfigHybrid2026());
    ASSERT_THAT(xwing_handle, IsOk());
    absl::StatusOr<std::unique_ptr<HybridDecrypt>> xwing_decrypt =
        (*xwing_handle)->GetPrimitive<HybridDecrypt>(ConfigHybrid2026());
    ASSERT_THAT(xwing_decrypt, IsOk());
    xwing_decrypt_ = *std::move(xwing_decrypt);
    const auto* xwing_private_key = dynamic_cast<const HpkePrivateKey*>(
        (*xwing_handle)->GetPrimary().GetKey().get());
    ASSERT_NE(xwing_private_key, nullptr);
    xwing_public_key_bytes_ =
        std::string(xwing_private_key->GetPublicKey().GetPublicKeyBytes(
            GetPartialKeyAccess()));

    absl::StatusOr<HpkeParameters> mlkem768_params =
        HpkeParameters::Builder()
            .SetKemId(HpkeParameters::KemId::kMlKem768)
            .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
            .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
            .SetVariant(HpkeParameters::Variant::kNoPrefix)
            .Build();
    ASSERT_THAT(mlkem768_params, IsOk());
    mlkem768_params_ = *mlkem768_params;

    absl::StatusOr<std::unique_ptr<KeysetHandle>> mlkem768_handle =
        KeysetHandle::GenerateNewFromParameters(*mlkem768_params_,
                                                KeyGenConfigHybrid2026());
    ASSERT_THAT(mlkem768_handle, IsOk());
    absl::StatusOr<std::unique_ptr<HybridDecrypt>> mlkem768_decrypt =
        (*mlkem768_handle)->GetPrimitive<HybridDecrypt>(ConfigHybrid2026());
    ASSERT_THAT(mlkem768_decrypt, IsOk());
    mlkem768_decrypt_ = *std::move(mlkem768_decrypt);
    const auto* mlkem768_private_key = dynamic_cast<const HpkePrivateKey*>(
        (*mlkem768_handle)->GetPrimary().GetKey().get());
    ASSERT_NE(mlkem768_private_key, nullptr);
    mlkem768_public_key_bytes_ =
        std::string(mlkem768_private_key->GetPublicKey().GetPublicKeyBytes(
            GetPartialKeyAccess()));

    absl::StatusOr<HpkeParameters> mlkem1024_params =
        HpkeParameters::Builder()
            .SetKemId(HpkeParameters::KemId::kMlKem1024)
            .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
            .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
            .SetVariant(HpkeParameters::Variant::kNoPrefix)
            .Build();
    ASSERT_THAT(mlkem1024_params, IsOk());
    mlkem1024_params_ = *mlkem1024_params;

    absl::StatusOr<std::unique_ptr<KeysetHandle>> mlkem1024_handle =
        KeysetHandle::GenerateNewFromParameters(*mlkem1024_params_,
                                                KeyGenConfigHybrid2026());
    ASSERT_THAT(mlkem1024_handle, IsOk());
    absl::StatusOr<std::unique_ptr<HybridDecrypt>> mlkem1024_decrypt =
        (*mlkem1024_handle)->GetPrimitive<HybridDecrypt>(ConfigHybrid2026());
    ASSERT_THAT(mlkem1024_decrypt, IsOk());
    mlkem1024_decrypt_ = *std::move(mlkem1024_decrypt);
    const auto* mlkem1024_private_key = dynamic_cast<const HpkePrivateKey*>(
        (*mlkem1024_handle)->GetPrimary().GetKey().get());
    ASSERT_NE(mlkem1024_private_key, nullptr);
    mlkem1024_public_key_bytes_ =
        std::string(mlkem1024_private_key->GetPublicKey().GetPublicKeyBytes(
            GetPartialKeyAccess()));
  }

  void SetupMockGetPublicKey() {
    EXPECT_CALL(*mock_connection_, GetPublicKey)
        .WillRepeatedly([this](const kmsV1::GetPublicKeyRequest& request)
                            -> google::cloud::StatusOr<kmsV1::PublicKey> {
          kmsV1::PublicKey response;
          response.set_name(request.name());
          if (request.name() == kKeyNameXWing) {
            if (request.public_key_format() !=
                kmsV1::PublicKey::XWING_RAW_BYTES) {
              return google::cloud::Status(
                  google::cloud::StatusCode::kInvalidArgument,
                  "Format must be XWING_RAW_BYTES");
            }
            response.set_algorithm(kmsV1::CryptoKeyVersion::KEM_XWING);
            response.mutable_public_key()->set_data(xwing_public_key_bytes_);
          } else if (request.name() == kKeyNameMlKem768) {
            if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
              return google::cloud::Status(
                  google::cloud::StatusCode::kInvalidArgument,
                  "Format must be NIST_PQC");
            }
            response.set_algorithm(kmsV1::CryptoKeyVersion::ML_KEM_768);
            response.mutable_public_key()->set_data(mlkem768_public_key_bytes_);
          } else if (request.name() == kKeyNameMlKem1024) {
            if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
              return google::cloud::Status(
                  google::cloud::StatusCode::kInvalidArgument,
                  "Format must be NIST_PQC");
            }
            response.set_algorithm(kmsV1::CryptoKeyVersion::ML_KEM_1024);
            response.mutable_public_key()->set_data(
                mlkem1024_public_key_bytes_);
          } else if (request.name() == kKeyNameErrorGetPublicKey) {
            return google::cloud::Status(
                google::cloud::StatusCode::kPermissionDenied,
                "Permission denied");
          } else if (request.name() == kKeyNameCrcError) {
            response.set_algorithm(kmsV1::CryptoKeyVersion::KEM_XWING);
            response.mutable_public_key()->set_data(xwing_public_key_bytes_);
            response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
                12345);
            return response;
          }

          response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
              static_cast<uint32_t>(
                  absl::ComputeCrc32c(response.public_key().data())));
          return response;
        });
  }

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
  std::optional<HpkeParameters> xwing_params_;
  std::optional<HpkeParameters> mlkem768_params_;
  std::optional<HpkeParameters> mlkem1024_params_;
  std::string xwing_public_key_bytes_;
  std::string mlkem768_public_key_bytes_;
  std::string mlkem1024_public_key_bytes_;
  std::unique_ptr<HybridDecrypt> xwing_decrypt_;
  std::unique_ptr<HybridDecrypt> mlkem768_decrypt_;
  std::unique_ptr<HybridDecrypt> mlkem1024_decrypt_;
};

TEST_F(TestGcpKmsHybridEncrypt, NullKmsClientFails) {
  std::shared_ptr<KeyManagementServiceClient> null_kms_client = nullptr;
  EXPECT_THAT(
      CreateHpkePublicKey(kKeyNameXWing, null_kms_client, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("KMS client cannot be null")));
  EXPECT_THAT(
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, null_kms_client, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsHybridEncrypt, InvalidKeyNameFails) {
  EXPECT_THAT(
      CreateHpkePublicKey("invalid_name", kms_client_, *xwing_params_).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("does not match")));
  EXPECT_THAT(
      CreateGcpKmsHybridEncrypt("invalid_name", kms_client_, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("does not match")));
}

TEST_F(TestGcpKmsHybridEncrypt, UnsupportedKemFails) {
  absl::StatusOr<HpkeParameters> p256_params =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(p256_params, IsOk());
  EXPECT_THAT(
      CreateHpkePublicKey(kKeyNameXWing, kms_client_, *p256_params).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Unsupported HPKE KEM algorithm")));
  EXPECT_THAT(CreateHpkePublicKeyWithNoRpcs(xwing_public_key_bytes_,
                                            *p256_params, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported HPKE KEM algorithm")));
  EXPECT_THAT(
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *p256_params)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Unsupported HPKE KEM algorithm")));
}

TEST_F(TestGcpKmsHybridEncrypt, IdRequirementFails) {
  SetupMockGetPublicKey();
  absl::StatusOr<HpkeParameters> tink_params =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .SetVariant(HpkeParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());
  EXPECT_THAT(
      CreateHpkePublicKey(kKeyNameXWing, kms_client_, *tink_params).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot create key without ID requirement")));
  EXPECT_THAT(CreateHpkePublicKeyWithNoRpcs(xwing_public_key_bytes_,
                                            *tink_params, GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Cannot create key without ID requirement")));
  EXPECT_THAT(
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *tink_params)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Cannot create key without ID requirement")));
}

TEST_F(TestGcpKmsHybridEncrypt, GetPublicKeyRpcFails) {
  SetupMockGetPublicKey();
  EXPECT_THAT(CreateGcpKmsHybridEncrypt(kKeyNameErrorGetPublicKey, kms_client_,
                                        *xwing_params_)
                  .status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS GetPublicKey failed")));
}

TEST_F(TestGcpKmsHybridEncrypt, ChecksumMismatchFails) {
  SetupMockGetPublicKey();
  EXPECT_THAT(
      CreateGcpKmsHybridEncrypt(kKeyNameCrcError, kms_client_, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("checksum mismatch")));
}

TEST_F(TestGcpKmsHybridEncrypt, AlgorithmMismatchFromKmsFails) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce([this](const kmsV1::GetPublicKeyRequest& request)
                    -> google::cloud::StatusOr<kmsV1::PublicKey> {
        kmsV1::PublicKey response;
        response.set_name(request.name());
        response.set_algorithm(kmsV1::CryptoKeyVersion::ML_KEM_1024);
        response.mutable_public_key()->set_data(mlkem1024_public_key_bytes_);
        response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
            static_cast<uint32_t>(
                absl::ComputeCrc32c(response.public_key().data())));
        return response;
      });
  EXPECT_THAT(CreateGcpKmsHybridEncrypt(kKeyNameMlKem768, kms_client_,
                                        *mlkem768_params_)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Algorithm mismatch")));
}

TEST_F(TestGcpKmsHybridEncrypt, CreateHpkePublicKeyWithNoRpcsSuccess) {
  absl::StatusOr<HpkePublicKey> xwing_key = CreateHpkePublicKeyWithNoRpcs(
      xwing_public_key_bytes_, *xwing_params_, GetPartialKeyAccess());
  ASSERT_THAT(xwing_key, IsOk());
  EXPECT_EQ(xwing_key->GetPublicKeyBytes(GetPartialKeyAccess()),
            xwing_public_key_bytes_);

  absl::StatusOr<HpkePublicKey> mlkem768_key = CreateHpkePublicKeyWithNoRpcs(
      mlkem768_public_key_bytes_, *mlkem768_params_, GetPartialKeyAccess());
  ASSERT_THAT(mlkem768_key, IsOk());
  EXPECT_EQ(mlkem768_key->GetPublicKeyBytes(GetPartialKeyAccess()),
            mlkem768_public_key_bytes_);

  absl::StatusOr<HpkePublicKey> mlkem1024_key = CreateHpkePublicKeyWithNoRpcs(
      mlkem1024_public_key_bytes_, *mlkem1024_params_, GetPartialKeyAccess());
  ASSERT_THAT(mlkem1024_key, IsOk());
  EXPECT_EQ(mlkem1024_key->GetPublicKeyBytes(GetPartialKeyAccess()),
            mlkem1024_public_key_bytes_);
}

TEST_F(TestGcpKmsHybridEncrypt,
       CreateHpkePublicKeyWithNoRpcsInvalidKeyLengthFails) {
  EXPECT_THAT(CreateHpkePublicKeyWithNoRpcs("too_short", *xwing_params_,
                                            GetPartialKeyAccess())
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid public key length")));
}

TEST_F(TestGcpKmsHybridEncrypt,
       CreateGcpKmsHybridEncryptWithNoRpcsIdRequirementFails) {
  absl::StatusOr<HpkeParameters> tink_params =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
          .SetVariant(HpkeParameters::Variant::kTink)
          .Build();
  ASSERT_THAT(tink_params, IsOk());
  absl::StatusOr<HpkePublicKey> tink_key =
      HpkePublicKey::Create(*tink_params, xwing_public_key_bytes_,
                            /*id_requirement=*/42, GetPartialKeyAccess());
  ASSERT_THAT(tink_key, IsOk());
  EXPECT_THAT(CreateGcpKmsHybridEncryptWithNoRpcs(*tink_key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ID requirement")));
}

TEST_F(TestGcpKmsHybridEncrypt,
       CreateGcpKmsHybridEncryptWithNoRpcsUnsupportedKemFails) {
  absl::StatusOr<HpkeParameters> x25519_params =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemX25519HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(x25519_params, IsOk());
  absl::StatusOr<HpkePublicKey> x25519_key = HpkePublicKey::Create(
      *x25519_params, std::string(32, 'a'), /*id_requirement=*/std::nullopt,
      GetPartialKeyAccess());
  ASSERT_THAT(x25519_key, IsOk());
  EXPECT_THAT(CreateGcpKmsHybridEncryptWithNoRpcs(*x25519_key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported HPKE KEM algorithm")));
}

TEST_F(TestGcpKmsHybridEncrypt, EndToEndXWingEncryptAndDecryptSuccess) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(encrypt, IsOk());

  std::string plaintext = "Secret payload with X-Wing";
  std::string context_info = "Context 123";
  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt(plaintext, context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_FALSE(ciphertext->empty());

  // Verify decryption using local Tink HybridDecrypt primitive.
  EXPECT_THAT(xwing_decrypt_->Decrypt(*ciphertext, context_info),
              IsOkAndHolds(plaintext));
}

TEST_F(TestGcpKmsHybridEncrypt, EndToEndMlKem768EncryptAndDecryptSuccess) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameMlKem768, kms_client_,
                                *mlkem768_params_);
  ASSERT_THAT(encrypt, IsOk());

  std::string plaintext = "Secret payload with ML-KEM-768";
  std::string context_info = "Context 456";
  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt(plaintext, context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_FALSE(ciphertext->empty());

  // Verify decryption using local Tink HybridDecrypt primitive.
  EXPECT_THAT(mlkem768_decrypt_->Decrypt(*ciphertext, context_info),
              IsOkAndHolds(plaintext));
}

TEST_F(TestGcpKmsHybridEncrypt, EndToEndMlKem1024EncryptAndDecryptSuccess) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameMlKem1024, kms_client_,
                                *mlkem1024_params_);
  ASSERT_THAT(encrypt, IsOk());

  std::string plaintext = "Secret payload with ML-KEM-1024";
  std::string context_info = "Context 789";
  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt(plaintext, context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_FALSE(ciphertext->empty());

  // Verify decryption using local Tink HybridDecrypt primitive.
  EXPECT_THAT(mlkem1024_decrypt_->Decrypt(*ciphertext, context_info),
              IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
