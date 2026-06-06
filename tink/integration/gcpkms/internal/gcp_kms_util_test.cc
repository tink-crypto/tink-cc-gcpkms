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

#include "tink/integration/gcpkms/internal/gcp_kms_util.h"

#include <cstdint>
#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/cloud/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace internal {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::Status;
using ::google::cloud::StatusCode;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kKeyName =
    "projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1";

TEST(GcpKmsStatusUtilTest, ConvertsGoogleCloudStatusCodeToAbslStatusCode) {
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kOk), absl::StatusCode::kOk);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kCancelled),
            absl::StatusCode::kCancelled);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kUnknown), absl::StatusCode::kUnknown);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kInvalidArgument),
            absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kDeadlineExceeded),
            absl::StatusCode::kDeadlineExceeded);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kNotFound),
            absl::StatusCode::kNotFound);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kAlreadyExists),
            absl::StatusCode::kAlreadyExists);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kPermissionDenied),
            absl::StatusCode::kPermissionDenied);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kResourceExhausted),
            absl::StatusCode::kResourceExhausted);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kFailedPrecondition),
            absl::StatusCode::kFailedPrecondition);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kAborted), absl::StatusCode::kAborted);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kOutOfRange),
            absl::StatusCode::kOutOfRange);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kUnimplemented),
            absl::StatusCode::kUnimplemented);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kInternal),
            absl::StatusCode::kInternal);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kUnavailable),
            absl::StatusCode::kUnavailable);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kDataLoss),
            absl::StatusCode::kDataLoss);
  EXPECT_EQ(ToAbslStatusCode(StatusCode::kUnauthenticated),
            absl::StatusCode::kUnauthenticated);
}

class FetchKmsPublicKeyTest : public testing::Test {
 public:
  FetchKmsPublicKeyTest()
      : mock_connection_(
            std::make_shared<MockKeyManagementServiceConnection>()),
        kms_client_(
            std::make_shared<KeyManagementServiceClient>(mock_connection_)) {}

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

TEST_F(FetchKmsPublicKeyTest, RpcFails) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce(
          [](kmsV1::GetPublicKeyRequest const&) -> StatusOr<kmsV1::PublicKey> {
            return Status(StatusCode::kPermissionDenied, "RPC failed");
          });
  EXPECT_THAT(FetchKmsPublicKey(kKeyName, kms_client_).status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS GetPublicKey failed")));
}

TEST_F(FetchKmsPublicKeyTest, NameMismatchFails) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce(
          [](kmsV1::GetPublicKeyRequest const&) -> StatusOr<kmsV1::PublicKey> {
            kmsV1::PublicKey response;
            response.set_name(
                "projects/other/locations/L/keyRings/R/cryptoKeys/K/"
                "cryptoKeyVersions/1");
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
            return StatusOr<kmsV1::PublicKey>(response);
          });
  EXPECT_THAT(FetchKmsPublicKey(kKeyName, kms_client_).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("key name in the response does not match")));
}

TEST_F(FetchKmsPublicKeyTest, ChecksumMismatchFails) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce([](kmsV1::GetPublicKeyRequest const& request)
                    -> StatusOr<kmsV1::PublicKey> {
        kmsV1::PublicKey response;
        response.set_name(request.name());
        response.set_algorithm(kmsV1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
        response.mutable_public_key()->set_data("public key data");
        response.mutable_public_key()->mutable_crc32c_checksum()->set_value(1);
        return StatusOr<kmsV1::PublicKey>(response);
      });
  EXPECT_THAT(FetchKmsPublicKey(kKeyName, kms_client_).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("GCP KMS GetPublicKey checksum mismatch")));
}

TEST_F(FetchKmsPublicKeyTest, RetriesWithNistPqcOnUnsupportedPemError) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillRepeatedly([](kmsV1::GetPublicKeyRequest const& request)
                          -> StatusOr<kmsV1::PublicKey> {
        if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
          return Status(StatusCode::kInvalidArgument,
                        "Only NIST_PQC format is supported");
        }
        kmsV1::PublicKey response;
        response.set_name(request.name());
        response.set_algorithm(
            kmsV1::CryptoKeyVersion::PQ_SIGN_SLH_DSA_SHA2_128S);
        return StatusOr<kmsV1::PublicKey>(response);
      });
  EXPECT_THAT(FetchKmsPublicKey(kKeyName, kms_client_), IsOk());
}

TEST_F(FetchKmsPublicKeyTest, RetriesWithNistPqcForPqcAlgorithm) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillRepeatedly([](kmsV1::GetPublicKeyRequest const& request)
                          -> StatusOr<kmsV1::PublicKey> {
        kmsV1::PublicKey response;
        response.set_name(request.name());
        response.set_algorithm(kmsV1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65);
        return StatusOr<kmsV1::PublicKey>(response);
      });
  EXPECT_THAT(FetchKmsPublicKey(kKeyName, kms_client_), IsOk());
}

TEST_F(FetchKmsPublicKeyTest, NistPqcRetryFails) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillRepeatedly([](kmsV1::GetPublicKeyRequest const& request)
                          -> StatusOr<kmsV1::PublicKey> {
        if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
          return Status(StatusCode::kInvalidArgument,
                        "Only NIST_PQC format is supported");
        }
        return Status(StatusCode::kUnavailable, "NIST_PQC also failed");
      });
  EXPECT_THAT(FetchKmsPublicKey(kKeyName, kms_client_).status(),
              StatusIs(absl::StatusCode::kUnavailable,
                       HasSubstr("GCP KMS GetPublicKey failed")));
}

TEST_F(FetchKmsPublicKeyTest, Success) {
  EXPECT_CALL(*mock_connection_, GetPublicKey)
      .WillOnce([](kmsV1::GetPublicKeyRequest const& request)
                    -> StatusOr<kmsV1::PublicKey> {
        kmsV1::PublicKey response;
        response.set_name(request.name());
        response.set_algorithm(kmsV1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
        response.mutable_public_key()->set_data("public key data");
        response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
            static_cast<uint32_t>(
                absl::ComputeCrc32c(response.public_key().data())));
        return StatusOr<kmsV1::PublicKey>(response);
      });
  EXPECT_THAT(FetchKmsPublicKey(kKeyName, kms_client_), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
