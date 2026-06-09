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

#include "tink/integration/gcpkms/gcp_kms_mac.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/cloud/status.h"
#include "google/cloud/status_or.h"
#include "tink/mac.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::crypto::tink::test::DummyMac;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::Status;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kData = "data for mac";
constexpr absl::string_view kWrongData = "wrong data for mac";
constexpr absl::string_view kVersionName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1";
constexpr absl::string_view kKeyName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1";
constexpr absl::string_view kKeyNameErrorMacSign =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/2";
constexpr absl::string_view kKeyNameErrorCrc32c =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/3";
constexpr absl::string_view kKeyNameErrorCrc32cNotVerified =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/4";
constexpr absl::string_view kKeyNameErrorWrongKeyName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/5";
constexpr absl::string_view kKeyNameErrorMacVerify =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/6";
constexpr absl::string_view kKeyNameVerifyErrorDataCrc32cNotVerified =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/7";
constexpr absl::string_view kKeyNameVerifyErrorMacCrc32cNotVerified =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/8";
constexpr absl::string_view kKeyNameVerifyErrorSuccessIntegrity =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/9";
constexpr absl::string_view kKeyNameVerifyErrorWrongKeyName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/10";
constexpr char kMacName[] = "gcp_kms_mac_test";

std::string ComputeMacOrDie(const DummyMac& mac, absl::string_view data) {
  auto mac_result = mac.ComputeMac(data);
  if (!mac_result.ok()) {
    ADD_FAILURE() << mac_result.status();
    return "";
  }
  return *mac_result;
}

std::string ComputeKmsMacOrDie(const Mac& mac, absl::string_view data) {
  auto mac_result = mac.ComputeMac(data);
  if (!mac_result.ok()) {
    ADD_FAILURE() << mac_result.status();
    return "";
  }
  return *mac_result;
}

std::unique_ptr<Mac> CreateGcpKmsMacOrDie(
    absl::string_view key_name,
    std::shared_ptr<KeyManagementServiceClient> kms_client) {
  auto kms_mac = CreateGcpKmsMac(key_name, kms_client);
  if (!kms_mac.ok()) {
    ADD_FAILURE() << kms_mac.status();
    return nullptr;
  }
  return std::move(*kms_mac);
}

class TestGcpKmsMac : public testing::Test {
 public:
  TestGcpKmsMac()
      : mock_connection_(
            std::make_shared<MockKeyManagementServiceConnection>()),
        kms_client_(
            std::make_shared<KeyManagementServiceClient>(mock_connection_)) {}

  void ExpectMacSign(const DummyMac& mac, int times) {
    EXPECT_CALL(*mock_connection_, MacSign)
        .Times(times)
        .WillRepeatedly([&](kmsV1::MacSignRequest const& request)
                            -> StatusOr<kmsV1::MacSignResponse> {
          if (request.name() == kKeyNameErrorMacSign) {
            return Status(google::cloud::StatusCode::kPermissionDenied,
                          "Permission denied");
          }

          EXPECT_EQ(request.data(), kData);
          EXPECT_EQ(request.data_crc32c().value(),
                    static_cast<uint32_t>(absl::ComputeCrc32c(kData)));

          kmsV1::MacSignResponse response;
          response.set_name(request.name());
          response.set_verified_data_crc32c(true);
          std::string mac_value = ComputeMacOrDie(mac, kData);
          response.set_mac(mac_value);
          response.mutable_mac_crc32c()->set_value(
              static_cast<uint32_t>(absl::ComputeCrc32c(response.mac())));

          if (request.name() == kKeyNameErrorWrongKeyName) {
            response.set_name(kVersionName);
          }
          if (request.name() == kKeyNameErrorCrc32c) {
            response.mutable_mac_crc32c()->set_value(1);
          }
          if (request.name() == kKeyNameErrorCrc32cNotVerified) {
            response.set_verified_data_crc32c(false);
          }

          return StatusOr<kmsV1::MacSignResponse>(response);
        });
  }

  void ExpectMacVerify(const DummyMac& mac, int times) {
    EXPECT_CALL(*mock_connection_, MacVerify)
        .Times(times)
        .WillRepeatedly([&](kmsV1::MacVerifyRequest const& request)
                            -> StatusOr<kmsV1::MacVerifyResponse> {
          if (request.name() == kKeyNameErrorMacVerify) {
            return Status(google::cloud::StatusCode::kPermissionDenied,
                          "Permission denied");
          }

          EXPECT_EQ(request.data_crc32c().value(),
                    static_cast<uint32_t>(absl::ComputeCrc32c(request.data())));
          EXPECT_EQ(request.mac_crc32c().value(),
                    static_cast<uint32_t>(absl::ComputeCrc32c(request.mac())));

          kmsV1::MacVerifyResponse response;
          response.set_name(request.name());
          response.set_verified_data_crc32c(true);
          response.set_verified_mac_crc32c(true);
          response.set_success(
              mac.VerifyMac(request.mac(), request.data()).ok());
          response.set_verified_success_integrity(response.success());
          if (request.name() == kKeyNameVerifyErrorWrongKeyName) {
            response.set_name(kVersionName);
          }
          if (request.name() == kKeyNameVerifyErrorDataCrc32cNotVerified) {
            response.set_verified_data_crc32c(false);
          }
          if (request.name() == kKeyNameVerifyErrorMacCrc32cNotVerified) {
            response.set_verified_mac_crc32c(false);
          }
          if (request.name() == kKeyNameVerifyErrorSuccessIntegrity) {
            response.set_verified_success_integrity(!response.success());
          }

          return StatusOr<kmsV1::MacVerifyResponse>(response);
        });
  }

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

TEST_F(TestGcpKmsMac, NullKmsClientFails) {
  // The `kms_client` parameter is annotated nonnull, but we want to test the
  // defensive null check. Use a variable instead of passing nullptr directly
  // to avoid a `-Wnonnull` warning.
  std::shared_ptr<KeyManagementServiceClient> null_kms_client = nullptr;
  EXPECT_THAT(
      CreateGcpKmsMac(kVersionName, std::move(null_kms_client)).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsMac, EmptyKeyNameFails) {
  EXPECT_THAT(CreateGcpKmsMac("", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsMac, WrongKeyNameFails) {
  EXPECT_THAT(CreateGcpKmsMac("Wrong/Key/Name", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsMac, MacSignPermissionDeniedFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kKeyNameErrorMacSign, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(kms_mac->ComputeMac(kData).status(),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS MacSign failed")));
}

TEST_F(TestGcpKmsMac, WrongInputCrc32cFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kKeyNameErrorCrc32cNotVerified, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(kms_mac->ComputeMac(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Checking the input checksum failed.")));
}

TEST_F(TestGcpKmsMac, WrongMacCrc32cFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kKeyNameErrorCrc32c, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(kms_mac->ComputeMac(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("MAC checksum mismatch")));
}

TEST_F(TestGcpKmsMac, WrongKeyNameInTheResponseFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kKeyNameErrorWrongKeyName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(kms_mac->ComputeMac(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("does not match the requested key name")));
}

TEST_F(TestGcpKmsMac, ComputeAndVerifyMacSuccess) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  std::string mac_value = ComputeKmsMacOrDie(*kms_mac, kData);
  EXPECT_THAT(kms_mac->VerifyMac(mac_value, kData), IsOk());
}

TEST_F(TestGcpKmsMac, ComputeMacLargeInputDataFails) {
  std::string large_data(kMaxMacDataSize + 1, 'A');
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(
      kms_mac->ComputeMac(large_data).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger than")));
}

TEST_F(TestGcpKmsMac, VerifyMacLargeInputDataFails) {
  std::string large_data(kMaxMacDataSize + 1, 'A');
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(
      kms_mac->VerifyMac("some mac", large_data),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger than")));
}

TEST_F(TestGcpKmsMac, VerifyMacLargeInputMacFails) {
  std::string large_mac(kMaxMacValueSize + 1, 'A');
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(
      kms_mac->VerifyMac(large_mac, kData),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger than")));
}

TEST_F(TestGcpKmsMac, KeyNameWithoutCryptoKeyVersionFails) {
  EXPECT_THAT(CreateGcpKmsMac(kKeyName, kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsMac, VerifyMacFailsOnWrongData) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  std::string mac_value = ComputeKmsMacOrDie(*kms_mac, kData);
  EXPECT_THAT(kms_mac->VerifyMac(mac_value, kWrongData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("MAC verification failed")));
}

TEST_F(TestGcpKmsMac, VerifyMacFailsOnWrongMac) {
  DummyMac mac(kMacName);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  EXPECT_THAT(kms_mac->VerifyMac("wrong mac", kData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("MAC verification failed")));
}

TEST_F(TestGcpKmsMac, MacVerifyFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kKeyNameErrorMacVerify, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  std::string mac_value = ComputeKmsMacOrDie(*kms_mac, kData);
  EXPECT_THAT(kms_mac->VerifyMac(mac_value, kData),
              StatusIs(absl::StatusCode::kPermissionDenied,
                       HasSubstr("GCP KMS MacVerify failed")));
}

TEST_F(TestGcpKmsMac, VerifyMacWrongInputDataCrc32cFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac = CreateGcpKmsMacOrDie(
      kKeyNameVerifyErrorDataCrc32cNotVerified, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  std::string mac_value = ComputeKmsMacOrDie(*kms_mac, kData);
  EXPECT_THAT(kms_mac->VerifyMac(mac_value, kData),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Checking the input data checksum failed.")));
}

TEST_F(TestGcpKmsMac, VerifyMacWrongMacCrc32cFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac = CreateGcpKmsMacOrDie(
      kKeyNameVerifyErrorMacCrc32cNotVerified, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  std::string mac_value = ComputeKmsMacOrDie(*kms_mac, kData);
  EXPECT_THAT(kms_mac->VerifyMac(mac_value, kData),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Checking the MAC checksum failed.")));
}

TEST_F(TestGcpKmsMac, VerifyMacWrongSuccessIntegrityFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kKeyNameVerifyErrorSuccessIntegrity, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  std::string mac_value = ComputeKmsMacOrDie(*kms_mac, kData);
  EXPECT_THAT(
      kms_mac->VerifyMac(mac_value, kData),
      StatusIs(
          absl::StatusCode::kInternal,
          HasSubstr("Checking the verification result integrity failed.")));
}

TEST_F(TestGcpKmsMac, VerifyMacWrongKeyNameInTheResponseFails) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  ExpectMacVerify(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kKeyNameVerifyErrorWrongKeyName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  std::string mac_value = ComputeKmsMacOrDie(*kms_mac, kData);
  EXPECT_THAT(kms_mac->VerifyMac(mac_value, kData),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("does not match the requested key name")));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
