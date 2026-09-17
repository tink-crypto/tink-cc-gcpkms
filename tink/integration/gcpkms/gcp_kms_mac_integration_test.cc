// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "tink/integration/gcpkms/gcp_kms_mac.h"
#include "tink/integration/gcpkms/internal/gcp_kms_test_client.h"
#include "tink/mac.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::testing::Environment;
using ::testing::HasSubstr;
using ::testing::NotNull;

// An HMAC-SHA256 CryptoKeyVersion. Unlike an AEAD key URI, MAC operations are
// bound to a specific CryptoKeyVersion, so the name includes the version.
constexpr absl::string_view kGcpKmsMacKeyName =
    "projects/tink-test-infrastructure/locations/global/keyRings/"
    "unit-and-integration-testing/cryptoKeys/mac-key/cryptoKeyVersions/1";

constexpr absl::string_view kData = "This is some data to authenticate.";
constexpr absl::string_view kOtherData = "This is some other data.";

class GcpKmsMacIntegrationTestEnvironment : public Environment {
 public:
  ~GcpKmsMacIntegrationTestEnvironment() override = default;

  void SetUp() override { internal::SetGrpcDefaultSslRootsForTesting(); }
};

Environment* const kMacEnv = testing::AddGlobalTestEnvironment(
    new GcpKmsMacIntegrationTestEnvironment());

class GcpKmsMacIntegrationTest : public testing::Test {
 protected:
  static void SetUpTestSuite() {
    absl::StatusOr<std::shared_ptr<KeyManagementServiceClient>> kms_client =
        internal::CreateKmsClientForTesting();
    ASSERT_THAT(kms_client, IsOk());
    kms_client_ =
        new std::shared_ptr<KeyManagementServiceClient>(*std::move(kms_client));
  }

  static void TearDownTestSuite() {
    delete kms_client_;
    kms_client_ = nullptr;
  }

  void SetUp() override {
    ASSERT_THAT(kms_client_, NotNull());
    absl::StatusOr<std::unique_ptr<Mac>> mac =
        CreateGcpKmsMac(kGcpKmsMacKeyName, *kms_client_);
    ASSERT_THAT(mac, IsOk());
    mac_ = *std::move(mac);
  }

  static inline std::shared_ptr<KeyManagementServiceClient>*
      kms_client_ = nullptr;
  std::unique_ptr<Mac> mac_;
};

TEST_F(GcpKmsMacIntegrationTest, ComputeAndVerifyMacSuccess) {
  absl::StatusOr<std::string> tag = mac_->ComputeMac(kData);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(mac_->VerifyMac(*tag, kData), IsOk());
}

TEST_F(GcpKmsMacIntegrationTest, ComputeAndVerifyMacMaxDataSizeSuccess) {
  const std::string max_data(kMaxMacDataSize, 'a');
  absl::StatusOr<std::string> tag = mac_->ComputeMac(max_data);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(mac_->VerifyMac(*tag, max_data), IsOk());
}

TEST_F(GcpKmsMacIntegrationTest, ComputeMacIsDeterministic) {
  // HMAC is deterministic, and both calls are pinned to the same
  // CryptoKeyVersion, so the two tags must be identical.
  absl::StatusOr<std::string> tag = mac_->ComputeMac(kData);
  ASSERT_THAT(tag, IsOk());
  absl::StatusOr<std::string> same_tag = mac_->ComputeMac(kData);
  ASSERT_THAT(same_tag, IsOk());

  EXPECT_EQ(*tag, *same_tag);
}

TEST_F(GcpKmsMacIntegrationTest, VerifyMacFailsWithWrongData) {
  absl::StatusOr<std::string> tag = mac_->ComputeMac(kData);
  ASSERT_THAT(tag, IsOk());
  EXPECT_THAT(mac_->VerifyMac(*tag, kOtherData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("MAC verification failed.")));
}

TEST_F(GcpKmsMacIntegrationTest, VerifyMacFailsWithModifiedMac) {
  absl::StatusOr<std::string> tag = mac_->ComputeMac(kData);
  ASSERT_THAT(tag, IsOk());
  ASSERT_FALSE(tag->empty());

  (*tag)[0] ^= 0x01;
  EXPECT_THAT(mac_->VerifyMac(*tag, kData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("MAC verification failed.")));
}

TEST_F(GcpKmsMacIntegrationTest, VerifyMacFailsWithTruncatedMac) {
  absl::StatusOr<std::string> tag = mac_->ComputeMac(kData);
  ASSERT_THAT(tag, IsOk());
  ASSERT_FALSE(tag->empty());
  std::string truncated_tag = tag->substr(0, tag->size() - 1);

  // Cloud KMS rejects the RPC at the API layer with an INVALID_ARGUMENT error
  // when the tag length is invalid.
  EXPECT_THAT(mac_->VerifyMac(truncated_tag, kData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("GCP KMS MacVerify failed")));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
