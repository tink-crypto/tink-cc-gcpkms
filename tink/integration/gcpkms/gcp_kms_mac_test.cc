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

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::crypto::tink::test::StatusIs;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kData = "data for mac";
constexpr absl::string_view kVersionName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1";
constexpr absl::string_view kKeyName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1";

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

class TestGcpKmsMacSkeleton : public testing::Test {
 public:
  TestGcpKmsMacSkeleton()
      : mock_connection_(
            std::make_shared<MockKeyManagementServiceConnection>()),
        kms_client_(
            std::make_shared<KeyManagementServiceClient>(mock_connection_)) {}

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

TEST_F(TestGcpKmsMacSkeleton, CreateGcpKmsMacSucceeds) {
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  EXPECT_NE(kms_mac, nullptr);
}

TEST_F(TestGcpKmsMacSkeleton, MethodsAreUnimplemented) {
  std::unique_ptr<Mac> kms_mac =
      CreateGcpKmsMacOrDie(kVersionName, kms_client_);
  ASSERT_NE(kms_mac, nullptr);

  EXPECT_THAT(
      kms_mac->ComputeMac(kData).status(),
      StatusIs(absl::StatusCode::kUnimplemented, HasSubstr("Not implemented")));
  EXPECT_THAT(
      kms_mac->VerifyMac("mac", kData),
      StatusIs(absl::StatusCode::kUnimplemented, HasSubstr("Not implemented")));
}

TEST_F(TestGcpKmsMacSkeleton, NullKmsClientFails) {
  // The `kms_client` parameter is annotated nonnull, but we want to test the
  // defensive null check. Use a variable instead of passing nullptr directly
  // to avoid a `-Wnonnull` warning.
  std::shared_ptr<KeyManagementServiceClient> null_kms_client = nullptr;
  EXPECT_THAT(
      CreateGcpKmsMac(kVersionName, std::move(null_kms_client)).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsMacSkeleton, BadKeyNameFormatFails) {
  EXPECT_THAT(CreateGcpKmsMac("Wrong/Key/Name", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsMacSkeleton, KeyNameWithoutCryptoKeyVersionFails) {
  EXPECT_THAT(CreateGcpKmsMac(kKeyName, kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
