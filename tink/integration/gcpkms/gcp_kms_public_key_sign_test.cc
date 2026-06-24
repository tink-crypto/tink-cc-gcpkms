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

#include "tink/integration/gcpkms/gcp_kms_public_key_sign.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/cloud/status.h"
#include "google/cloud/status_or.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::Status;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kData = "data for signing";
constexpr absl::string_view kDigest = "digest for signing";
// SHA-256 digest of kData. Pre-hash signature algorithms (e.g. HASH_SLH_DSA)
// send this digest to Cloud KMS instead of the raw data.
constexpr absl::string_view kSha256DigestOfKData(
    "\xbd\xb2\x45\x2d\xfd\xc4\x32\xf6"
    "\x75\xfe\x3b\x38\x3b\x03\xc9\x34"
    "\x3e\x61\x8b\x25\x7b\xe1\xc1\xfc"
    "\x9b\xe1\xc9\xda\x14\x76\xb0\x71",
    32);
// TODO(b/514763989): Reorganize these later.
constexpr absl::string_view kKeyNameRequiresData1 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1";
constexpr absl::string_view kKeyNameRequiresData2 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/2";
constexpr absl::string_view kKeyNameRequiresDigest =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/3";
constexpr absl::string_view kKeyNameErrorGetPublicKey =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/4";
constexpr absl::string_view kKeyNameErrorAsymmetricSign =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/5";
constexpr absl::string_view kKeyNameErrorCrc32c =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/6";
constexpr absl::string_view kKeyNameErrorCrc32cNotVerified =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/7";
constexpr absl::string_view kKeyNameErrorWrongKeyName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/8";
constexpr absl::string_view kKeyNameErrorUnsupportedAlgorithm =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/9";
constexpr absl::string_view kKeyNameErrorChecksumMismatchGetPublicKey =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/10";
constexpr absl::string_view kKeyNameErrorChecksumMismatchGetPublicKeyPqc =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/11";
constexpr absl::string_view kKeyNameMlDsa65 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/12";
constexpr absl::string_view kKeyNameMlDsa44 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/13";
constexpr absl::string_view kKeyNameMlDsa87 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/14";
constexpr absl::string_view kKeyNameHashSlhDsa =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/15";

// Identifies a key version under test and how many GetPublicKey calls it needs
// during key fetching.
struct RequestParam {
  absl::string_view key_name;
  int get_public_key_times;
};

std::string SignOrDie(const DummyPublicKeySign& signer,
                      absl::string_view data) {
  absl::StatusOr<std::string> signature = signer.Sign(data);
  if (!signature.ok()) {
    ADD_FAILURE() << signature.status();
    return "";
  }
  return *signature;
}

std::unique_ptr<PublicKeySign> CreateGcpKmsPublicKeySignOrDie(
    absl::string_view key_name,
    std::shared_ptr<KeyManagementServiceClient> kms_client) {
  absl::StatusOr<std::unique_ptr<PublicKeySign>> kms_signer =
      CreateGcpKmsPublicKeySign(key_name, std::move(kms_client));
  if (!kms_signer.ok()) {
    ADD_FAILURE() << kms_signer.status();
    return nullptr;
  }
  return std::move(*kms_signer);
}

class TestGcpKmsPublicKeySign : public testing::Test {
 public:
  TestGcpKmsPublicKeySign()
      : mock_connection_(
            std::make_shared<MockKeyManagementServiceConnection>()),
        kms_client_(
            std::make_shared<KeyManagementServiceClient>(mock_connection_)) {}

  // If `captured_request` is non-null, the last request seen by the mock is
  // copied into it so the caller can assert on the request contents.
  void ExpectSign(const DummyPublicKeySign& signer, int times,
                  kmsV1::AsymmetricSignRequest* captured_request = nullptr) {
    EXPECT_CALL(*mock_connection_, AsymmetricSign)
        .Times(times)
        .WillRepeatedly([&, captured_request](
                            kmsV1::AsymmetricSignRequest const& request)
                            -> StatusOr<kmsV1::AsymmetricSignResponse> {
          if (captured_request != nullptr) {
            *captured_request = request;
          }
          if (request.name() == kKeyNameErrorAsymmetricSign) {
            return Status(google::cloud::StatusCode::kPermissionDenied,
                          "Permission denied");
          }

          // Prepare response based on the given data/digest.
          kmsV1::AsymmetricSignResponse response;
          response.set_name(request.name());
          if (request.has_digest()) {
            response.set_verified_digest_crc32c(true);
            response.set_signature(SignOrDie(signer, kDigest));
          } else {
            response.set_verified_data_crc32c(true);
            response.set_signature(SignOrDie(signer, kData));
          }
          response.mutable_signature_crc32c()->set_value(
              static_cast<uint32_t>(absl::ComputeCrc32c(response.signature())));

          // Manipulate the key name value for the: kKeyNameErrorWrongKeyName.
          if (request.name() == kKeyNameErrorWrongKeyName) {
            response.set_name(kKeyNameRequiresData1);
          }
          // Manipulate the crc32c value for the case: kKeyNameErrorCrc32c.
          if (request.name() == kKeyNameErrorCrc32c) {
            response.mutable_signature_crc32c()->set_value(1);
          }
          // Crc32c check failed, set both fields to false, for the case:
          // kKeyNameErrorCrc32cNotVerified.
          if (request.name() == kKeyNameErrorCrc32cNotVerified) {
            response.set_verified_data_crc32c(false);
            response.set_verified_digest_crc32c(false);
          }

          return StatusOr<kmsV1::AsymmetricSignResponse>(response);
        });
  }

  void ExpectGetPublicKey(int times) {
    EXPECT_CALL(*mock_connection_, GetPublicKey)
        .Times(times)
        .WillRepeatedly([&](kmsV1::GetPublicKeyRequest const& request)
                            -> StatusOr<kmsV1::PublicKey> {
          kmsV1::PublicKey response;
          response.set_name(request.name());
          // All use PEM, unless otherwise specified (and overwritten)
          response.set_public_key_format(kmsV1::PublicKey::PEM);
          response.mutable_public_key()->set_data("public key data");
          response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
              static_cast<uint32_t>(
                  absl::ComputeCrc32c(response.public_key().data())));
          if (request.name() == kKeyNameRequiresData1 ||
              request.name() == kKeyNameErrorAsymmetricSign ||
              request.name() == kKeyNameErrorCrc32c ||
              request.name() == kKeyNameErrorCrc32cNotVerified ||
              request.name() == kKeyNameErrorWrongKeyName) {
            // This operates on the data.
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
          } else if (request.name() == kKeyNameRequiresData2) {
            // This operates on the data.
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::EXTERNAL);
          } else if (request.name() == kKeyNameRequiresDigest) {
            // This operates on the digest.
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
          } else if (request.name() == kKeyNameErrorGetPublicKey) {
            return Status(google::cloud::StatusCode::kPermissionDenied,
                          "Permission denied");
          } else if (request.name() == kKeyNameErrorUnsupportedAlgorithm) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_DECRYPT_OAEP_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
          } else if (request.name() ==
                     kKeyNameErrorChecksumMismatchGetPublicKey) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
                1);
          } else if (request.name() ==
                     kKeyNameErrorChecksumMismatchGetPublicKeyPqc) {
            if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
              return Status(
                  google::cloud::StatusCode::kInvalidArgument,
                  "Only NIST_PQC format is supported for PQC algorithms.");
            }
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::PQ_SIGN_SLH_DSA_SHA2_128S);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_public_key_format(kmsV1::PublicKey::NIST_PQC);
            response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
                1);
          } else if (request.name() == kKeyNameMlDsa44) {
            response.set_algorithm(kmsV1::CryptoKeyVersion::PQ_SIGN_ML_DSA_44);
            if (request.public_key_format() == kmsV1::PublicKey::NIST_PQC) {
              response.set_public_key_format(kmsV1::PublicKey::NIST_PQC);
            }
          } else if (request.name() == kKeyNameMlDsa65) {
            response.set_algorithm(kmsV1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65);
            if (request.public_key_format() == kmsV1::PublicKey::NIST_PQC) {
              response.set_public_key_format(kmsV1::PublicKey::NIST_PQC);
            }
          } else if (request.name() == kKeyNameMlDsa87) {
            response.set_algorithm(kmsV1::CryptoKeyVersion::PQ_SIGN_ML_DSA_87);
            if (request.public_key_format() == kmsV1::PublicKey::NIST_PQC) {
              response.set_public_key_format(kmsV1::PublicKey::NIST_PQC);
            }
          } else if (request.name() == kKeyNameHashSlhDsa) {
            // SLH-DSA, including the pre-hash variant, does not support PEM.
            if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
              return Status(
                  google::cloud::StatusCode::kInvalidArgument,
                  "Only NIST_PQC format is supported for PQC algorithms.");
            }
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_public_key_format(kmsV1::PublicKey::NIST_PQC);
          }
          return StatusOr<kmsV1::PublicKey>(response);
        });
  }

  void ExpectPqcGetPublicKey(int times) {
    EXPECT_CALL(*mock_connection_, GetPublicKey)
        .Times(times)
        .WillRepeatedly([&](kmsV1::GetPublicKeyRequest const& request)
                            -> StatusOr<kmsV1::PublicKey> {
          kmsV1::PublicKey response;
          if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
            return Status(
                google::cloud::StatusCode::kInvalidArgument,
                "Only NIST_PQC format is supported for PQC algorithms.");
          }
          response.set_name(request.name());
          response.set_algorithm(
              kmsV1::CryptoKeyVersion::PQ_SIGN_SLH_DSA_SHA2_128S);
          response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
          return StatusOr<kmsV1::PublicKey>(response);
        });
  }

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

TEST_F(TestGcpKmsPublicKeySign, NullKmsClientFails) {
  // The `kms_client` parameter is annotated nonnull, but we want to test the
  // defensive null check. Use a variable instead of passing nullptr directly
  // to avoid a `-Wnonnull` warning.
  std::shared_ptr<KeyManagementServiceClient> null_kms_client = nullptr;
  EXPECT_THAT(CreateGcpKmsPublicKeySign(kKeyNameRequiresData1,
                                        std::move(null_kms_client))
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsPublicKeySign, EmptyKeyNameFails) {
  EXPECT_THAT(CreateGcpKmsPublicKeySign("", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongKeyNameFails) {
  EXPECT_THAT(CreateGcpKmsPublicKeySign("Wrong/Key/Name", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsPublicKeySign, GetPublicKeyFails) {
  ExpectGetPublicKey(1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameErrorGetPublicKey, kms_client_);
  EXPECT_THAT(kmsSigner.status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS GetPublicKey failed")));
}

TEST_F(TestGcpKmsPublicKeySign, ChecksumMismatchFailsGetPublicKey) {
  ExpectGetPublicKey(1);
  auto kmsSigner = CreateGcpKmsPublicKeySign(
      kKeyNameErrorChecksumMismatchGetPublicKey, kms_client_);
  EXPECT_THAT(kmsSigner.status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("GCP KMS GetPublicKey checksum mismatch")));
}

TEST_F(TestGcpKmsPublicKeySign, ChecksumMismatchFailsGetPublicKeyPqc) {
  ExpectGetPublicKey(2);
  auto kmsSigner = CreateGcpKmsPublicKeySign(
      kKeyNameErrorChecksumMismatchGetPublicKeyPqc, kms_client_);
  EXPECT_THAT(kmsSigner.status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("GCP KMS GetPublicKey checksum mismatch")));
}

TEST_F(TestGcpKmsPublicKeySign, UnsupportedAlgorithmFails) {
  ExpectGetPublicKey(1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameErrorUnsupportedAlgorithm, kms_client_);
  EXPECT_THAT(kmsSigner.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                           HasSubstr("is not supported")));
}

TEST_F(TestGcpKmsPublicKeySign, AsymmetricSignFails) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameErrorAsymmetricSign);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  std::unique_ptr<PublicKeySign> kmsSigner =
      CreateGcpKmsPublicKeySignOrDie(kKeyNameErrorAsymmetricSign, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(kmsSigner->Sign(kData).status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS AsymmetricSign failed")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongInputCrc32cFails) {
  DummyPublicKeySign signer =
      DummyPublicKeySign(kKeyNameErrorCrc32cNotVerified);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  std::unique_ptr<PublicKeySign> kmsSigner = CreateGcpKmsPublicKeySignOrDie(
      kKeyNameErrorCrc32cNotVerified, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(kmsSigner->Sign(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Checking the input checksum failed.")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongSignatureCrc32cFails) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameErrorCrc32c);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  std::unique_ptr<PublicKeySign> kmsSigner =
      CreateGcpKmsPublicKeySignOrDie(kKeyNameErrorCrc32c, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(kmsSigner->Sign(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Signature checksum mismatch")));
}

TEST_F(TestGcpKmsPublicKeySign, LargeInputDataFails) {
  ExpectGetPublicKey(1);
  std::string large_data(64 * 1024 + 1, 'A');
  std::unique_ptr<PublicKeySign> kmsSigner =
      CreateGcpKmsPublicKeySignOrDie(kKeyNameRequiresData1, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(
      kmsSigner->Sign(large_data).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger than")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongKeyNameInTheResponseFails) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameErrorWrongKeyName);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  std::unique_ptr<PublicKeySign> kmsSigner =
      CreateGcpKmsPublicKeySignOrDie(kKeyNameErrorWrongKeyName, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(kmsSigner->Sign(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("does not match the requested key name")));
}

// Data-mode algorithms sign the raw data: the request must carry `data` (with
// its checksum) and no digest.
class TestGcpKmsPublicKeySignData
    : public TestGcpKmsPublicKeySign,
      public testing::WithParamInterface<RequestParam> {};

TEST_P(TestGcpKmsPublicKeySignData, PublicKeySignDataRequestCorrect) {
  const RequestParam& param = GetParam();
  DummyPublicKeySign signer = DummyPublicKeySign(param.key_name);
  ExpectGetPublicKey(param.get_public_key_times);
  kmsV1::AsymmetricSignRequest request;
  ExpectSign(signer, /*times*/ 1, &request);
  std::unique_ptr<PublicKeySign> kmsSigner =
      CreateGcpKmsPublicKeySignOrDie(param.key_name, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(kmsSigner->Sign(kData), IsOkAndHolds(SignOrDie(signer, kData)));

  EXPECT_EQ(request.name(), param.key_name);
  EXPECT_EQ(request.data(), kData);
  EXPECT_TRUE(request.has_data_crc32c());
  EXPECT_EQ(request.data_crc32c().value(),
            static_cast<uint32_t>(absl::ComputeCrc32c(kData)));
  EXPECT_FALSE(request.has_digest());
  EXPECT_FALSE(request.has_digest_crc32c());
}

INSTANTIATE_TEST_SUITE_P(
    DataAlgorithms, TestGcpKmsPublicKeySignData,
    testing::Values(
        RequestParam{kKeyNameRequiresData1, /*get_public_key_times=*/1},
        RequestParam{kKeyNameRequiresData2, /*get_public_key_times=*/1},
        RequestParam{kKeyNameMlDsa44, /*get_public_key_times=*/2},
        RequestParam{kKeyNameMlDsa65, /*get_public_key_times=*/2},
        RequestParam{kKeyNameMlDsa87, /*get_public_key_times=*/2}));

// Digest-mode algorithms sign a digest of the data: the request must carry the
// correct SHA-256 digest (with its checksum) and no data.
class TestGcpKmsPublicKeySignDigest
    : public TestGcpKmsPublicKeySign,
      public testing::WithParamInterface<RequestParam> {};

TEST_P(TestGcpKmsPublicKeySignDigest, PublicKeySignDigestRequestCorrect) {
  const RequestParam& param = GetParam();
  DummyPublicKeySign signer = DummyPublicKeySign(param.key_name);
  ExpectGetPublicKey(param.get_public_key_times);
  kmsV1::AsymmetricSignRequest request;
  ExpectSign(signer, /*times*/ 1, &request);
  std::unique_ptr<PublicKeySign> kmsSigner =
      CreateGcpKmsPublicKeySignOrDie(param.key_name, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(kmsSigner->Sign(kData), IsOkAndHolds(SignOrDie(signer, kDigest)));

  EXPECT_EQ(request.name(), param.key_name);
  EXPECT_TRUE(request.data().empty());
  EXPECT_FALSE(request.has_data_crc32c());
  EXPECT_TRUE(request.has_digest());
  EXPECT_EQ(request.digest().digest_case(), kmsV1::Digest::kSha256);
  EXPECT_EQ(request.digest().sha256(), kSha256DigestOfKData);
  EXPECT_TRUE(request.has_digest_crc32c());
  EXPECT_EQ(request.digest_crc32c().value(),
            static_cast<uint32_t>(absl::ComputeCrc32c(kSha256DigestOfKData)));
}

INSTANTIATE_TEST_SUITE_P(
    DigestAlgorithms, TestGcpKmsPublicKeySignDigest,
    testing::Values(RequestParam{kKeyNameRequiresDigest,
                                 /*get_public_key_times=*/1},
                    RequestParam{kKeyNameHashSlhDsa,
                                 /*get_public_key_times=*/2}));


TEST_F(TestGcpKmsPublicKeySign, PublicKeySignSlhDsaAlgorithmSuccess) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameRequiresData1);
  // SLH-DSA does not support PEM format.
  ExpectPqcGetPublicKey(/*times*/ 2);
  ExpectSign(signer, /*times*/ 1);
  std::unique_ptr<PublicKeySign> kmsSigner =
      CreateGcpKmsPublicKeySignOrDie(kKeyNameRequiresData1, kms_client_);
  ASSERT_NE(kmsSigner, nullptr);
  EXPECT_THAT(kmsSigner->Sign(kData), IsOkAndHolds(SignOrDie(signer, kData)));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
