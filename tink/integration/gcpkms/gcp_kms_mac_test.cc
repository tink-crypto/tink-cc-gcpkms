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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/cloud/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::crypto::tink::test::DummyMac;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::Status;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kData = "data for mac";
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
constexpr char kMacName[] = "gcp_kms_mac_test";

std::string ComputeMacOrDie(const DummyMac& mac, absl::string_view data) {
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

TEST_F(TestGcpKmsMac, ComputeMacSuccess) {
  DummyMac mac(kMacName);
  ExpectMacSign(mac, /*times=*/1);
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);
  std::string expected_mac = ComputeMacOrDie(mac, kData);
  EXPECT_THAT(kms_mac->ComputeMac(kData), IsOkAndHolds(expected_mac));
}

TEST_F(TestGcpKmsMac, KeyNameWithoutCryptoKeyVersionFails) {
  EXPECT_THAT(CreateGcpKmsMac(kKeyName, kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
