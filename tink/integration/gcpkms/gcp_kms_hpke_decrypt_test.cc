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
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/cloud/status.h"
#include "google/cloud/status_or.h"
#include "openssl/aead.h"
#include "openssl/hpke.h"
#include "openssl/mlkem.h"
#include "openssl/xwing.h"
#include "tink/hybrid/config_2026.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/integration/gcpkms/gcp_kms_hpke_encrypt.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::crypto::tink::test::HexDecodeOrDie;
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

class TestGcpKmsHybridDecrypt : public testing::Test {
 public:
  static void SetUpTestSuite() { (void)ConfigHybrid2026(); }

  void SetUp() override {
    mock_connection_ = std::make_shared<MockKeyManagementServiceConnection>();
    kms_client_ =
        std::make_shared<KeyManagementServiceClient>(mock_connection_);

    xwing_public_key_bytes_.resize(XWING_PUBLIC_KEY_BYTES);
    ASSERT_EQ(XWING_generate_key(
                  reinterpret_cast<uint8_t*>(xwing_public_key_bytes_.data()),
                  &xwing_private_key_),
              1);

    mlkem768_public_key_bytes_.resize(MLKEM768_PUBLIC_KEY_BYTES);
    MLKEM768_generate_key(
        reinterpret_cast<uint8_t*>(mlkem768_public_key_bytes_.data()),
        /*optional_out_seed=*/nullptr, &mlkem768_private_key_);

    mlkem1024_public_key_bytes_.resize(MLKEM1024_PUBLIC_KEY_BYTES);
    MLKEM1024_generate_key(
        reinterpret_cast<uint8_t*>(mlkem1024_public_key_bytes_.data()),
        /*optional_out_seed=*/nullptr, &mlkem1024_private_key_);

    absl::StatusOr<HpkeParameters> xwing_params =
        HpkeParameters::Builder()
            .SetKemId(HpkeParameters::KemId::kXWing)
            .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
            .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
            .SetVariant(HpkeParameters::Variant::kNoPrefix)
            .Build();
    ASSERT_THAT(xwing_params, IsOk());
    xwing_params_ = *xwing_params;

    absl::StatusOr<HpkeParameters> mlkem768_params =
        HpkeParameters::Builder()
            .SetKemId(HpkeParameters::KemId::kMlKem768)
            .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
            .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
            .SetVariant(HpkeParameters::Variant::kNoPrefix)
            .Build();
    ASSERT_THAT(mlkem768_params, IsOk());
    mlkem768_params_ = *mlkem768_params;
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

  void SetupMockDecapsulate() {
    EXPECT_CALL(*mock_connection_, Decapsulate)
        .WillRepeatedly(
            [this](const kmsV1::DecapsulateRequest& request)
                -> google::cloud::StatusOr<kmsV1::DecapsulateResponse> {
              if (!request.has_ciphertext_crc32c() ||
                  request.ciphertext_crc32c().value() !=
                      static_cast<uint32_t>(
                          absl::ComputeCrc32c(request.ciphertext()))) {
                return google::cloud::Status(
                    google::cloud::StatusCode::kInvalidArgument,
                    "Ciphertext CRC32C mismatch in request");
              }

              kmsV1::DecapsulateResponse response;
              response.set_name(request.name());
              response.set_verified_ciphertext_crc32c(true);

              std::string shared_secret;
              if (request.name() == kKeyNameXWing) {
                if (request.ciphertext().size() != XWING_CIPHERTEXT_BYTES) {
                  return google::cloud::Status(
                      google::cloud::StatusCode::kInvalidArgument,
                      "Invalid X-Wing ciphertext size");
                }
                shared_secret.resize(XWING_SHARED_SECRET_BYTES);
                if (!XWING_decap(
                        reinterpret_cast<uint8_t*>(shared_secret.data()),
                        reinterpret_cast<const uint8_t*>(
                            request.ciphertext().data()),
                        &xwing_private_key_)) {
                  return google::cloud::Status(
                      google::cloud::StatusCode::kInvalidArgument,
                      "XWING_decap failed");
                }
              } else if (request.name() == kKeyNameMlKem768) {
                shared_secret.resize(MLKEM_SHARED_SECRET_BYTES);
                if (!MLKEM768_decap(
                        reinterpret_cast<uint8_t*>(shared_secret.data()),
                        reinterpret_cast<const uint8_t*>(
                            request.ciphertext().data()),
                        request.ciphertext().size(), &mlkem768_private_key_)) {
                  return google::cloud::Status(
                      google::cloud::StatusCode::kInvalidArgument,
                      "MLKEM768_decap failed");
                }
              } else if (request.name() == kKeyNameMlKem1024) {
                shared_secret.resize(MLKEM_SHARED_SECRET_BYTES);
                if (!MLKEM1024_decap(
                        reinterpret_cast<uint8_t*>(shared_secret.data()),
                        reinterpret_cast<const uint8_t*>(
                            request.ciphertext().data()),
                        request.ciphertext().size(), &mlkem1024_private_key_)) {
                  return google::cloud::Status(
                      google::cloud::StatusCode::kInvalidArgument,
                      "MLKEM1024_decap failed");
                }
              } else {
                return google::cloud::Status(
                    google::cloud::StatusCode::kNotFound, "Key not found");
              }

              response.set_shared_secret(shared_secret);
              response.set_shared_secret_crc32c(
                  static_cast<uint32_t>(absl::ComputeCrc32c(shared_secret)));
              return response;
            });
  }

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
  std::optional<HpkeParameters> xwing_params_;
  std::optional<HpkeParameters> mlkem768_params_;
  std::string xwing_public_key_bytes_;
  std::string mlkem768_public_key_bytes_;
  std::string mlkem1024_public_key_bytes_;
  XWING_private_key xwing_private_key_;
  MLKEM768_private_key mlkem768_private_key_;
  MLKEM1024_private_key mlkem1024_private_key_;
};

TEST_F(TestGcpKmsHybridDecrypt, NullKmsClientFails) {
  std::shared_ptr<KeyManagementServiceClient> null_kms_client = nullptr;
  EXPECT_THAT(
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, null_kms_client, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsHybridDecrypt, InvalidKeyNameFails) {
  EXPECT_THAT(
      CreateGcpKmsHybridDecrypt("invalid_name", kms_client_, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("does not match")));
}

TEST_F(TestGcpKmsHybridDecrypt, UnsupportedKemFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kDhkemP256HkdfSha256)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT(
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *params).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Unsupported HPKE KEM algorithm")));
}

TEST_F(TestGcpKmsHybridDecrypt, UnsupportedKdfFails) {
  absl::StatusOr<HpkeParameters> params =
      HpkeParameters::Builder()
          .SetKemId(HpkeParameters::KemId::kXWing)
          .SetKdfId(HpkeParameters::KdfId::kHkdfSha384)
          .SetAeadId(HpkeParameters::AeadId::kAesGcm128)
          .SetVariant(HpkeParameters::Variant::kNoPrefix)
          .Build();
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT(
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *params).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Unsupported HPKE KDF algorithm")));
}

TEST_F(TestGcpKmsHybridDecrypt, IdRequirementFails) {
  for (HpkeParameters::Variant variant :
       {HpkeParameters::Variant::kTink, HpkeParameters::Variant::kCrunchy}) {
    absl::StatusOr<HpkeParameters> params =
        HpkeParameters::Builder()
            .SetKemId(HpkeParameters::KemId::kXWing)
            .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
            .SetAeadId(HpkeParameters::AeadId::kAesGcm256)
            .SetVariant(variant)
            .Build();
    ASSERT_THAT(params, IsOk());
    EXPECT_THAT(
        CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *params).status(),
        StatusIs(absl::StatusCode::kInvalidArgument,
                 HasSubstr("ID requirement")));
  }
}

TEST_F(TestGcpKmsHybridDecrypt, GetPublicKeyRpcFails) {
  SetupMockGetPublicKey();
  EXPECT_THAT(CreateGcpKmsHybridDecrypt(kKeyNameErrorGetPublicKey, kms_client_,
                                        *xwing_params_)
                  .status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS GetPublicKey failed")));
}

TEST_F(TestGcpKmsHybridDecrypt, GetPublicKeyNameMismatchFails) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce([this](const kmsV1::GetPublicKeyRequest&)
                    -> google::cloud::StatusOr<kmsV1::PublicKey> {
        kmsV1::PublicKey response;
        response.set_name("wrong_key_name");
        response.set_algorithm(kmsV1::CryptoKeyVersion::KEM_XWING);
        response.mutable_public_key()->set_data(xwing_public_key_bytes_);
        response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
            static_cast<uint32_t>(
                absl::ComputeCrc32c(response.public_key().data())));
        return response;
      });
  EXPECT_THAT(
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInternal,
               HasSubstr("does not match the requested key name")));
}

TEST_F(TestGcpKmsHybridDecrypt, GetPublicKeyChecksumMismatchFails) {
  SetupMockGetPublicKey();
  EXPECT_THAT(
      CreateGcpKmsHybridDecrypt(kKeyNameCrcError, kms_client_, *xwing_params_)
          .status(),
      StatusIs(absl::StatusCode::kInternal, HasSubstr("checksum mismatch")));
}

TEST_F(TestGcpKmsHybridDecrypt, AlgorithmMismatchFromKmsFails) {
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
  EXPECT_THAT(CreateGcpKmsHybridDecrypt(kKeyNameMlKem768, kms_client_,
                                        *mlkem768_params_)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Algorithm mismatch")));
}

TEST_F(TestGcpKmsHybridDecrypt, CiphertextTooShortFails) {
  SetupMockGetPublicKey();
  EXPECT_CALL(*mock_connection_, Decapsulate).Times(0);

  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(decrypt, IsOk());

  EXPECT_THAT((*decrypt)->Decrypt("too_short", "context"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Ciphertext is too short")));
  EXPECT_THAT((*decrypt)->Decrypt(std::string(XWING_CIPHERTEXT_BYTES - 1, 'a'),
                                  "context"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Ciphertext is too short")));
  size_t aead_tag_len =
      EVP_AEAD_max_overhead(EVP_HPKE_AEAD_aead(EVP_hpke_aes_256_gcm()));
  EXPECT_THAT((*decrypt)->Decrypt(
                  std::string(XWING_CIPHERTEXT_BYTES + aead_tag_len - 1, 'a'),
                  "context"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Ciphertext is too short")));
}

TEST_F(TestGcpKmsHybridDecrypt, DecapsulateRpcFails) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_CALL(*mock_connection_, Decapsulate)
      .WillOnce([](const kmsV1::DecapsulateRequest&) {
        return google::cloud::Status(
            google::cloud::StatusCode::kPermissionDenied, "Access denied");
      });

  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS Decapsulate failed")));
}

TEST_F(TestGcpKmsHybridDecrypt, DecapsulateNameMismatchFails) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_CALL(*mock_connection_, Decapsulate)
      .WillOnce([](const kmsV1::DecapsulateRequest&) {
        kmsV1::DecapsulateResponse response;
        response.set_name("wrong_key_name");
        response.set_verified_ciphertext_crc32c(true);
        return response;
      });

  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("does not match the requested key name")));
}

TEST_F(TestGcpKmsHybridDecrypt, DecapsulateUnverifiedCiphertextCrc32cFails) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_CALL(*mock_connection_, Decapsulate)
      .WillOnce([](const kmsV1::DecapsulateRequest& request) {
        kmsV1::DecapsulateResponse response;
        response.set_name(request.name());
        response.set_verified_ciphertext_crc32c(false);
        return response;
      });

  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("verified_ciphertext_crc32c is false")));
}

TEST_F(TestGcpKmsHybridDecrypt, DecapsulateMissingSharedSecretCrc32cFails) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_CALL(*mock_connection_, Decapsulate)
      .WillOnce([](const kmsV1::DecapsulateRequest& request) {
        kmsV1::DecapsulateResponse response;
        response.set_name(request.name());
        response.set_verified_ciphertext_crc32c(true);
        response.set_shared_secret(std::string(32, 'a'));
        return response;
      });

  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("shared_secret_crc32c mismatch")));
}

TEST_F(TestGcpKmsHybridDecrypt, DecapsulateSharedSecretCrc32cMismatchFails) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_CALL(*mock_connection_, Decapsulate)
      .WillOnce([](const kmsV1::DecapsulateRequest& request) {
        kmsV1::DecapsulateResponse response;
        response.set_name(request.name());
        response.set_verified_ciphertext_crc32c(true);
        response.set_shared_secret(std::string(32, 'a'));
        response.set_shared_secret_crc32c(99999);
        return response;
      });

  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("shared_secret_crc32c mismatch")));
}

TEST_F(TestGcpKmsHybridDecrypt, DecapsulateInvalidSharedSecretLengthFails) {
  SetupMockGetPublicKey();
  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(kKeyNameXWing, kms_client_, *xwing_params_);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_CALL(*mock_connection_, Decapsulate)
      .WillOnce([](const kmsV1::DecapsulateRequest& request) {
        kmsV1::DecapsulateResponse response;
        response.set_name(request.name());
        response.set_verified_ciphertext_crc32c(true);
        std::string invalid_shared_secret(16, 'a');
        response.set_shared_secret(invalid_shared_secret);
        response.set_shared_secret_crc32c(
            static_cast<uint32_t>(absl::ComputeCrc32c(invalid_shared_secret)));
        return response;
      });

  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kUnknown,
                       HasSubstr("Unable to setup HPKE recipient context")));
}

struct EndToEndTestCase {
  std::string test_name;
  absl::string_view key_name;
  HpkeParameters::KemId kem_id;
  HpkeParameters::AeadId aead_id;
  size_t encapsulated_key_len;
  std::string expected_encapsulated_key_hex;
  std::string aead_ciphertext_hex;
  std::string fixed_shared_secret_hex;
  std::string expected_plaintext_hex;
  std::string context_info_hex;
};

class TestGcpKmsHybridDecryptEndToEnd
    : public TestGcpKmsHybridDecrypt,
      public testing::WithParamInterface<EndToEndTestCase> {
 protected:
  absl::StatusOr<HpkeParameters> GetHpkeParameters() const {
    const EndToEndTestCase& test_case = GetParam();
    return HpkeParameters::Builder()
        .SetKemId(test_case.kem_id)
        .SetKdfId(HpkeParameters::KdfId::kHkdfSha256)
        .SetAeadId(test_case.aead_id)
        .SetVariant(HpkeParameters::Variant::kNoPrefix)
        .Build();
  }
};

TEST_P(TestGcpKmsHybridDecryptEndToEnd, EncryptAndDecrypt) {
  const EndToEndTestCase& test_case = GetParam();
  SetupMockGetPublicKey();
  SetupMockDecapsulate();
  absl::StatusOr<HpkeParameters> params = GetHpkeParameters();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(decrypt, IsOk());

  std::string plaintext = "Secret payload";
  std::string context_info = "Context 123";
  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt(plaintext, context_info);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, context_info),
              IsOkAndHolds(plaintext));
}

TEST_P(TestGcpKmsHybridDecryptEndToEnd, EmptyPlaintextAndContextInfoSucceeds) {
  const EndToEndTestCase& test_case = GetParam();
  SetupMockGetPublicKey();
  SetupMockDecapsulate();
  absl::StatusOr<HpkeParameters> params = GetHpkeParameters();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext = (*encrypt)->Encrypt("", "");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, ""), IsOkAndHolds(""));
}

TEST_P(TestGcpKmsHybridDecryptEndToEnd, CorruptedEncapsulatedKeyFails) {
  const EndToEndTestCase& test_case = GetParam();
  SetupMockGetPublicKey();
  SetupMockDecapsulate();
  absl::StatusOr<HpkeParameters> params = GetHpkeParameters();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  // Corrupt the first byte of the encapsulated key.
  (*ciphertext)[0] ^= 0x01;
  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unable to open ciphertext")));
}

TEST_P(TestGcpKmsHybridDecryptEndToEnd, InvalidAeadCiphertextFails) {
  const EndToEndTestCase& test_case = GetParam();
  SetupMockGetPublicKey();
  SetupMockDecapsulate();
  absl::StatusOr<HpkeParameters> params = GetHpkeParameters();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());

  // Corrupt the last byte of the AEAD ciphertext.
  (*ciphertext)[ciphertext->size() - 1] ^= 0x01;
  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unable to open ciphertext")));
}

TEST_P(TestGcpKmsHybridDecryptEndToEnd, WrongContextInfoFails) {
  const EndToEndTestCase& test_case = GetParam();
  SetupMockGetPublicKey();
  SetupMockDecapsulate();
  absl::StatusOr<HpkeParameters> params = GetHpkeParameters();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context_a");
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_THAT((*decrypt)->Decrypt(*ciphertext, "context_b"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unable to open ciphertext")));
}

TEST_P(TestGcpKmsHybridDecryptEndToEnd, EmptyAeadCiphertextFails) {
  const EndToEndTestCase& test_case = GetParam();
  SetupMockGetPublicKey();
  EXPECT_CALL(*mock_connection_, Decapsulate).Times(0);
  absl::StatusOr<HpkeParameters> params = GetHpkeParameters();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      CreateGcpKmsHybridEncrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(encrypt, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(decrypt, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encrypt)->Encrypt("plaintext", "context");
  ASSERT_THAT(ciphertext, IsOk());
  // Truncate to exactly encapsulated_key_len so AEAD ciphertext is empty.
  std::string encapsulated_key_only =
      ciphertext->substr(0, test_case.encapsulated_key_len);
  EXPECT_THAT((*decrypt)->Decrypt(encapsulated_key_only, "context"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Ciphertext is too short")));
}

TEST_P(TestGcpKmsHybridDecryptEndToEnd, DecryptFixedTestVector) {
  const EndToEndTestCase& test_case = GetParam();
  std::string expected_encapsulated_key =
      HexDecodeOrDie(test_case.expected_encapsulated_key_hex);
  std::string aead_ciphertext = HexDecodeOrDie(test_case.aead_ciphertext_hex);
  std::string fixed_shared_secret =
      HexDecodeOrDie(test_case.fixed_shared_secret_hex);
  std::string expected_plaintext =
      HexDecodeOrDie(test_case.expected_plaintext_hex);
  std::string context_info = HexDecodeOrDie(test_case.context_info_hex);
  std::string ciphertext =
      absl::StrCat(expected_encapsulated_key, aead_ciphertext);

  SetupMockGetPublicKey();
  EXPECT_CALL(*mock_connection_, Decapsulate)
      .WillOnce([&](const kmsV1::DecapsulateRequest& request)
                    -> google::cloud::StatusOr<kmsV1::DecapsulateResponse> {
        EXPECT_EQ(request.name(), test_case.key_name);
        EXPECT_EQ(request.ciphertext(), expected_encapsulated_key);
        EXPECT_TRUE(request.has_ciphertext_crc32c());
        EXPECT_EQ(request.ciphertext_crc32c().value(),
                  static_cast<uint32_t>(
                      absl::ComputeCrc32c(expected_encapsulated_key)));

        kmsV1::DecapsulateResponse response;
        response.set_name(request.name());
        response.set_verified_ciphertext_crc32c(true);
        response.set_shared_secret(fixed_shared_secret);
        response.set_shared_secret_crc32c(
            static_cast<uint32_t>(absl::ComputeCrc32c(fixed_shared_secret)));
        return response;
      });

  absl::StatusOr<HpkeParameters> params = GetHpkeParameters();
  ASSERT_THAT(params, IsOk());
  absl::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      CreateGcpKmsHybridDecrypt(test_case.key_name, kms_client_, *params);
  ASSERT_THAT(decrypt, IsOk());
  EXPECT_THAT((*decrypt)->Decrypt(ciphertext, context_info),
              IsOkAndHolds(expected_plaintext));
}

INSTANTIATE_TEST_SUITE_P(
    EndToEndTests, TestGcpKmsHybridDecryptEndToEnd,
    testing::Values(
        // Test vector for X-Wing, HKDF-SHA256, AES-256-GCM, NO_PREFIX from
        // draft-connolly-cfrg-xwing-kem-09 and Tink Java (HpkeTestUtil.java).
        EndToEndTestCase{
            /*test_name=*/"XWing",
            /*key_name=*/kKeyNameXWing,
            /*kem_id=*/HpkeParameters::KemId::kXWing,
            /*aead_id=*/HpkeParameters::AeadId::kAesGcm256,
            /*encapsulated_key_len=*/XWING_CIPHERTEXT_BYTES,
            /*expected_encapsulated_key_hex=*/
            "e091314d69d0250e4c79366fcbcd812d9239db3431a2e44c44846146712580192e"
            "6aaa528e437457c2d7cdb1c78c761451262580b29b81c66f07819661e0d9e1104e"
            "abb89a049664e2c0a2f6bf0adaf125059f5c43681df8a77357f79ba9612bece4d1"
            "c920f1d2677a91337d6267c579c229dd1071087354ae86bf993f91c1762ccdd302"
            "d8fd868099411fe7d2ccfaeac036244881d6c02e77d2d60add9013a33abd3a1d50"
            "0d6b6374ddd2bbba00dc6fd3b971f869ad2973974a6dbec5de1c0877042c0001c6"
            "adede2bf0cf2b2cb77e1018e0e4c4db3062f47d1e08848094c0e157ce723c1b10b"
            "6d9c3baff99bd336b124595e9581bfa9e51e9d802eeda16f16f50260cdccce1a9e"
            "d9c4e026b3f2a40e4ddd3a53fab116771b077314b74188e139ed268ce749af8095"
            "2e2e67bd04b8b3fe3d5821dc16dc3267eccc0c3ee9195a8934b4bf8be66baa30ac"
            "08086f9d80cb260b6dcc814ce61f783ffb013f5919aa6e80039403829156b31a2c"
            "54829961ffc451b744a05d36c522836d731fb9afd82907c39f93439d6af8ca6d0f"
            "7406c1b252ca3e4b95ade048562b13167be92d834ebbce3049e8450a33c47b06b8"
            "f749f5bac0d1cc0215677c7c596040e900b660ddf640cc299e5a4a5ce95afd1650"
            "799e27630138af3bba686dbf5f91f9b9b1c4077a69d469e61fcb7308baa81a87b0"
            "a7df13acb7178af1a3d543d39a89d3e26b6dcf4561d0cd5027881a09bcc5d759a5"
            "326581f5772ca958294119e292ae20c6ea4897e802204f3432dc30c8b9e0c1c341"
            "7e932eeb8e8fd11e45bb6c499d34ec81fe4afe27c85e381ebe0d3fda7b9ea99f38"
            "dd8a8370a1fe97d309d0f25b67eb1c8654deb6029bcdc40ee26467c98cb90aebb3"
            "9e622e82427d490201dd6ecbdc0948daf5491834a35f71c9ff44b2fa7c9f15b33e"
            "4f560d435fca4b89663275e930d505067dc5b226651f33ad56f5b1cad803076dd2"
            "c1bcfb4c5f90954f9ceb55835a50a163d8d3c031585a3949797b12c0d090e49dd8"
            "ea87bbdddce53251e026157d6f60bd053b69727589ed178cef36276d471923a306"
            "76fb29e8bb03ece9a3dc7d2c9f5858b3004aaa4a8b1fa15c1371321229348ce93d"
            "32af7a8c819c8783212fe962d73ca30d35decc2503097d6aea205a11af8a30ea2b"
            "b6b5bf208133bf1b0dacfafffd350b96040e692e6ea18fe36f8469419f10cca58f"
            "3bcb8b2d941f05325a484b413c72768dbde9ec63eac2b9f8aab4644d959df2c6b9"
            "ab1cdef720caa7668dc40a65c4b7580673a01be3fe1c1b4f9a1d3eb7ffdd008f4e"
            "a86ef00333cf414df769b6adcf5762005a29cf7c2007bd7017b8c7c1c6a67963d0"
            "7ccb9cc9f0442bdbbdac879ee2a6672ef569e28cd97e0d018c26a3ecda3d21eb83"
            "ce13ff053a3d0e1941d36d2b9c1f274e31287495c70ea2cb4a0b62e10c6596aa2b"
            "9a9ba4166cda79407ce042bb3f1ef845998fd60c019744654c06f41d4570b169b9"
            "56dd0164270c30b7f0ebcf6e8d577b257c87446439d138fe49cbe9fa10a9ee0538"
            "00787cb924bdcf8a9a919837edc747594677a12d2ef24e121591116052c876",
            /*aead_ciphertext_hex=*/
            "63514319041c8aa1472417eab182ba68b932575a40786cf6e3b5bee19b79049c8e"
            "93021dfef49de0f37f7fa574",
            /*fixed_shared_secret_hex=*/
            "8ad011c01f58781b361133d45c21baa5d746c4e770b07241c1b7dec8ffa7c38b",
            /*expected_plaintext_hex=*/
            "4265617574792069732074727574682c20747275746820626561757479",
            /*context_info_hex=*/"4f6465206f6e2061204772656369616e2055726e",
        },
        // Test vector for ML-KEM-768, HKDF-SHA256, AES-128-GCM, NO_PREFIX from
        // NIST FIPS 203 and Tink (hpke_test_vectors.cc).
        EndToEndTestCase{
            /*test_name=*/"MlKem768",
            /*key_name=*/kKeyNameMlKem768,
            /*kem_id=*/HpkeParameters::KemId::kMlKem768,
            /*aead_id=*/HpkeParameters::AeadId::kAesGcm128,
            /*encapsulated_key_len=*/MLKEM768_CIPHERTEXT_BYTES,
            /*expected_encapsulated_key_hex=*/
            "bd48b97bc2c9ef55bcdf65e5c705aad0c190fb3e4271ca78b567a8d3d7070c"
            "6e73e4637cd3341ece8858335b3fec417a3671720717d15546eafeb2d3b72e"
            "04f87064e2819e90c046085e0704c6589f97d911bf18baf54ca0d07a4ccd95"
            "4ee62226d760750d9a908142d19109e7dca776be514bb851eb33ce34a53324"
            "4a5d12300df204b82484f08696588361a0e93f7295d617e7a8d453d78d940a"
            "251a440d74b4130801765d05edf5aa70dc8e7d5718bc9d9914e241c928cdc7"
            "99d4485572ebfa8c8c25a5d055b2317a9aa53f760a995e370c11f8117b213d"
            "5b129579ea5d959433bf01feb3bf93f42e047daa1e4f108ae82c66887e65fa"
            "8f43995251d55d0ba82df473efaaac43d0a777339f2fa40deb812c7a6ceb1a"
            "15817e9408a0a80164fda5d80194cf6ffbbc9fcd21cceac5c091c718486afd"
            "22f046c4d62d9e93c3bccee6f3c7629d5f30e4c7509cc1ba70dcc1d12d4609"
            "aa1525c5a2ad75135a4fdc044ba72e77282a7ff89e976a0d7ee81def2df82e"
            "b96e7057ff9ee94a598376d16b65b918e845be331fea83f391b7eb504e6f1c"
            "98a17867dec5829eac0e63672f09b9ccf3b9b489e191bd5cfceb1da0bb4d18"
            "ae6e9a15d794f81f36c3148dd288c6a3ebd705a2f601acce37551dda6cc1f8"
            "a4a7ea11a2c86254ceca99486d6634251cbda030b9642f68a6f46dcbef3c94"
            "c65f772ecb8341703c30068a3c9fcd263a6149d5a6dbeff9b569f7f68d2373"
            "3f498fbee12d402f980532f3d1ec83b9828ceafb54518447bc2393c973fff6"
            "68ff54fa7958205e3be4eca40fd2523327568b5245355c828a9f6294ed3ef1"
            "79b5eb16bc1e43f61ab069d10c89f59cf447d5a61c8498ff84f48a7cd76832"
            "c8d694e5b090c176caf81be027215cdfaadf5e05e2c80155ffc6eebb1589f3"
            "3abaee00ba8bc7f4794561e9a54616bd505896517940ce8adb2d9e2d0d7781"
            "75a19c987f5791b41af272e89e43c73436fbfb2ead8e8624acf81d81694f21"
            "a13cd1e13ea818f46f66ddce1e93e20f4c3b2fa820ebd224937053c4ed1404"
            "802634a0b1cd3763970ba6f66e13c6e1d833c9e80e4c041cd1c4947cc9cf0b"
            "70fc78b55b2244527bbedc6e618bf96261bec109320ee1a94e84dedd003d37"
            "deca5bc6ac6cd3bb8fa6a92fd62b331179f1557632f91cfb5cd327e643aa86"
            "7dab7801e5e91317191b3ddcec231aa6c1c07c371b5b5a02340cba092605e3"
            "8642aa190275d8324757d1330a0bfef15841e39c9430cb89ce596e0b715b26"
            "aa7c6c4b642f914a9da8ae77f045a112dfd3a0aa9616a817a09c5449b8831a"
            "d12bd17af81af7a5808e572b28c75591bcf69ab8077f8e067df75f4365fa9b"
            "70de24ed1422ea3229d85d0bfb503bc2bffd89c74055b76758cea078a05bd1"
            "2c793a1f9c78f5e90f44d89d5bd14a211ae149c91da17b6ac46774cc3c73a8"
            "07edbfdb3e33002daa2dc2758824435dfc6a0ddfe0bd1db083bf5f5d8e7b18"
            "abd1de1a8706f5c0c8a762d0a3d3f1ce02813345937034b973f94b6114651a"
            "58aacf",
            /*aead_ciphertext_hex=*/
            "be50e7d9e0aac571eac64b27b296bae1254505ec797a79b772fa60bc8f81bfe367"
            "af4ee02107c090f6a60bf8e9f547fd7937ad607ece7d7791817f55411c551f2de6"
            "f1a5b6662868d290dc884377a8a225",
            /*fixed_shared_secret_hex=*/
            "32d764d682b9d0b1e62ae75ac3d01e2426e664d632dd33c0d7bec4deeeac26dd",
            /*expected_plaintext_hex=*/
            "86526d8f8d975a50785055b1f6120e6e76e1088730919310d486016a1c62b9"
            "a797c5f8842c16260f959c1620d43632975a6c3f309b6891398c8c5a4d3148"
            "1180de",
            /*context_info_hex=*/
            "b254a656608933b934b3f81e8f810214c8135eda92a0614c2b926c4a3075b9"
            "f939e6a3c61309f53e",
        },
        // Test vector for ML-KEM-1024, HKDF-SHA256, ChaCha20-Poly1305,
        // NO_PREFIX using NIST FIPS 203 ML-KEM-1024 encapsulated key and shared
        // secret from hpke_test_vectors.cc.
        EndToEndTestCase{
            /*test_name=*/"MlKem1024",
            /*key_name=*/kKeyNameMlKem1024,
            /*kem_id=*/HpkeParameters::KemId::kMlKem1024,
            /*aead_id=*/HpkeParameters::AeadId::kChaCha20Poly1305,
            /*encapsulated_key_len=*/MLKEM1024_CIPHERTEXT_BYTES,
            /*expected_encapsulated_key_hex=*/
            "35ab4e29f97d2828aeb7f746f1eaf17fd41a20542cfc6df50009f6558dfb5c"
            "a5325e1aeed36a8d51bf4eed0244b655b8a5b1434325424669d01f6133b4ac"
            "96b1e9e46dd34fede463f92255bd55c76269858fbbebfc05d69b2873a16f53"
            "da8f16d82070ff41a8094b457e0d6695f3b01aa10764fe164a5b88ab822b7d"
            "996056ebb29a979cecb9a06965181337f60d7690fefb6fc5e37617c6beee69"
            "2ac9777bfa0cb792c6ccc2fff66dc986e2df0e94ec88ec3d06a4fdbee5d56a"
            "53800b6c286e683b1cb603184754414ee5e459a86d3800b435c6d593c04548"
            "7cd18c33b1131011d4e390c8417a6b2480a077ddff5b25c48efe4b79d0b0c9"
            "7ee8546946b52e59a95ea55058a6f265b39c62402831bd9cff4736b7602e79"
            "9d9501e1e134ae33f63d820a144dad11ed2ef598ae648b425fb95600a7a4a7"
            "007bd639a110b3583d65c5e224f699681971eeeccdbf49f2ef22e72c4b14a2"
            "3034ea16c4e0ca61fc1a0a1d25081110a5dcebd5d421d90b64ba00ac0015bc"
            "1b3ec8d59402b351a7099fc6e6f1f1484bb614d3ad7c02af2dbac41615d0c1"
            "4de681f65a229228782f9f692a2d9fd4ed04bceaa429dcc0bc4610c275487d"
            "74fa8dd08d1ac0f2242bb0387ac980088f6187834717cfc856d32a99d7e68f"
            "f318d5c562202ef766274a76c1e6ed5c42ae7fa9140907102a11ca4a1ecf35"
            "e133b41788e7362a8a3eb6bff94523ff1315b076d5e1a81a593cac13235ebd"
            "8d95942026bdda9e0d7cd8ba186344a7d8c407fe05522ff0026d47fd759dc0"
            "9f843cf424ffcce3a18423f0c0b17a816dbaeb950cfcfdc9bc150b51bdf019"
            "022c95cd03940f3b6611e76487962f64e18c1026cdaa74d24f390942ec77fc"
            "9cfb45260153a68fa22ed7d283306539b66aa0dc03abeeb79ac99d9bc84a7c"
            "822b57c41b7eeadd0037380724b1780f24b265e09988fa40e6f59d6dfb3903"
            "e4c55b6f0e0c204fe6b7cfc0d172f58614cf1f76ada5b4e1fa27606c182970"
            "fd032a8d81917fe5a11efad9dd41cfc805b3211c2c2eb59f65fe0c7af68a39"
            "3a12c78de044a9c2678afff346f7fc6c69427bbe1f9068fef9478c788912ac"
            "87340297aa1d685e06a7c86ac141127cc1f6dc7c20da5b7f61289b4e881390"
            "e4ec28d5ef64da41c2701cc74a24e9212f17388102224cefe260ece85faceb"
            "3d1f5e67a2af99fbd10eb951d038cf455901f8996dc1bc091f41d8543d4440"
            "684872742ea50ebb21cf4ac21d5148e1588f9173943010ab0d00cd2a04c72c"
            "68a897768cf6ef195c3f7650462a7b3bc5b9edeba690dcc3ba8e818cb5e5c2"
            "b8a7c57905f07c711e587e33bedba755cff2f2c41177a0ea984d377aea7b01"
            "48c8def3c515924351b30eadf795610d386e10e37001594fa66be43a1d39a8"
            "3a4737b31d04fb4310fd62fa56fbaa4a2c6dbb7029be979887bb2635f2863b"
            "b92aa6f145b44170fe476c8969c7de535deaf7f302673144c90c24dbc6df6b"
            "b81b72e24a091aa120f75cbb659caaae465b66ea64db727cead53d65f167a3"
            "cab1e97e4c7f3e9332500ae9d1745a725289f1327c8cfd6d9380d45eb7bf03"
            "e37825fa8e438b462e8db54351528f9550b763a003a46335f79f3ada75f916"
            "b028a364a16c527d2ea9a21fd587e8a34339d66156d6a0055a15a51d1206a8"
            "24d2ae94e95382e888150ada59d606ac4b17f855563c737f50ec449a7d7c1a"
            "7cf2801a81578a5d0c6afbecf25cde3b333bc1d25af54c67a5b21293338814"
            "0810a1dad0895add3452c0ad0e4cd83b055c5ded7c8f463a28154948acc99e"
            "6695dc523a8255c1ffb29b86d3330ad153776bb340dad43c5ea59a69009d3d"
            "ff057e019cddcd0ac055ba22ba04cb241f3b082c05695a5b07602194d714e8"
            "4bad39e37017eacd7ca7026c307c67a4f63d08a0b0f5155a6b9a79564a10cd"
            "23cecf28659a04a7732aebfb9edaa486bcdf6fbd1a115477f221027a21f9e3"
            "a1db0ce995fd1b92759cfa3778d202a43cbc767a2cd4bf7cf7461e74de3e2a"
            "eaeb1a30884563c3f44928085427f6205b43d2a93cb7927bd0eca44783d1c6"
            "5cad1d968e434daf6b851ab2b8d9f1516afb9ea65dac8715a1e83eee0be7c3"
            "1a82d33d581a910baae404c06e954cf3281d19c3665756cf262f6d028832a6"
            "bf16cfc860f7a7538a19e1558e2fdaa56bd26ecba4c7342f28250f498cbc10"
            "75b181c762dd3afbdaa42f3267f736faecdc",
            /*aead_ciphertext_hex=*/
            "111bb453ef9ce9d45e1822e2b3bb4854722c6c2e32088504bc5cfb5b162b2f5f0a"
            "8c5889d8cd40f104b6d73d3a64b0bde8fd96737c22b5f38389130df67630cea3d3"
            "4af633eccab3d6a45e15",
            /*fixed_shared_secret_hex=*/
            "a850624b012b23fbf010e3efa1d46f7d765ddd56ac53e045685d2a5d054067cd",
            /*expected_plaintext_hex=*/
            "c8a4153f9b7e2d06c5478f1a3e6d9c0b25748f3e9a6c1b4d8e7f5a2b0d9e8c"
            "1f7a4b6d3e9f2a7c5b8e1d4f0a3c7b8e2d5f1a4c9b8d2e6f3a7c1b5d9e",
            /*context_info_hex=*/
            "b9e8c67f3a2d1e0c4b59f7d6a5c3b2e18d9f0a786e5c4d3b2a1f0987e6d5c4"
            "b3",
        }),
    [](const testing::TestParamInfo<EndToEndTestCase>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
