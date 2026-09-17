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
#include <vector>

#include "google/cloud/kms/v1/resources.pb.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"

#include "absl/status/status_matchers.h"
#include "tink/integration/gcpkms/gcp_kms_public_key_sign.h"
#include "tink/integration/gcpkms/gcp_kms_public_key_verify.h"
#include "tink/integration/gcpkms/internal/gcp_kms_test_client.h"
#include "tink/integration/gcpkms/internal/gcp_kms_util.h"
#include "tink/partial_key_access.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/signature/signature_public_key.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::absl_testing::IsOk;
using ::crypto::tink::test::StatusIs;

using ::google::cloud::kms::v1::PublicKey;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::testing::Environment;
using ::testing::Not;
using ::testing::NotNull;

// KMS key ring hosted in Google Cloud project `tink-test-infrastructure`,
// used for Tink integration tests.
constexpr absl::string_view kKeyVersionPrefix =
    "projects/tink-test-infrastructure/locations/global/keyRings/"
    "unit-and-integration-testing/cryptoKeys/";

// Maximum size of the data that GcpKmsPublicKeySign can sign.
constexpr int kMaxSignDataSize = 64 * 1024;
constexpr absl::string_view kData = "This is some message to sign.";
constexpr absl::string_view kOtherData = "This is some other message.";

// Returns the resource name of version 1 of `crypto_key`. Asymmetric signing is
// bound to a specific CryptoKeyVersion, so the version is part of the name.
std::string KeyVersionName(absl::string_view crypto_key) {
  return absl::StrCat(kKeyVersionPrefix, crypto_key, "/cryptoKeyVersions/1");
}

struct SignatureKeyTestCase {
  // Name of this test case, used to build the gtest test names.
  std::string test_name;
  // Resource name of the CryptoKeyVersion to sign with.
  std::string key_version_name;
  // Format in which Cloud KMS serves this key's public key. PQC keys are served
  // as raw NIST_PQC bytes; all others as PEM.
  PublicKey::PublicKeyFormat public_key_format;
  // Whether Cloud KMS signs the message itself rather than a digest of it, in
  // which case the client-side `kMaxSignDataSize` limit applies.
  bool requires_data_for_sign;
};

std::vector<SignatureKeyTestCase> GetSignatureKeyTestCases() {
  return {
      {"EcdsaP256Sha256", KeyVersionName("signature-key"), PublicKey::PEM,
       /*requires_data_for_sign=*/false},
      {"RsaPss2048Sha256", KeyVersionName("rsa-pss-2048-key"), PublicKey::PEM,
       /*requires_data_for_sign=*/false},
      {"MlDsa65", KeyVersionName("ml-dsa-65-key"), PublicKey::NIST_PQC,
       /*requires_data_for_sign=*/true},
      {"MlDsa65ExternalMu", KeyVersionName("ml-dsa-65-external-mu-key"),
       PublicKey::NIST_PQC, /*requires_data_for_sign=*/false},
      {"SlhDsaSha2128S", KeyVersionName("slh-dsa-128s-key"),
       PublicKey::NIST_PQC, /*requires_data_for_sign=*/true},
  };
}

class GcpKmsSignatureIntegrationTestEnvironment : public Environment {
 public:
  ~GcpKmsSignatureIntegrationTestEnvironment() override = default;

  void SetUp() override { internal::SetGrpcDefaultSslRootsForTesting(); }
};

Environment* const kSignatureEnv = testing::AddGlobalTestEnvironment(
    new GcpKmsSignatureIntegrationTestEnvironment());

class GcpKmsSignatureIntegrationTest
    : public testing::TestWithParam<SignatureKeyTestCase> {
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

  void SetUp() override { ASSERT_THAT(kms_client_, NotNull()); }

  // Signs `data` with Cloud KMS.
  absl::StatusOr<std::string> Sign(absl::string_view data) {
    absl::StatusOr<std::unique_ptr<PublicKeySign>> signer =
        CreateGcpKmsPublicKeySign(GetParam().key_version_name, *kms_client_);
    if (!signer.ok()) {
      return signer.status();
    }
    return (*signer)->Sign(data);
  }

  // Verifies `signature` on `data` with Cloud KMS.
  absl::Status Verify(absl::string_view signature, absl::string_view data) {
    absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
        CreateGcpKmsPublicKeyVerify(GetParam().key_version_name, *kms_client_);
    if (!verifier.ok()) {
      return verifier.status();
    }
    return (*verifier)->Verify(signature, data);
  }

  static std::shared_ptr<KeyManagementServiceClient>* kms_client_;
};

std::shared_ptr<KeyManagementServiceClient>*
    GcpKmsSignatureIntegrationTest::kms_client_ = nullptr;

TEST_P(GcpKmsSignatureIntegrationTest, SignVerifyRoundTripSuccess) {
  absl::StatusOr<std::string> signature = Sign(kData);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(Verify(*signature, kData), IsOk());
}

TEST_P(GcpKmsSignatureIntegrationTest, VerifyFailsWithModifiedMessage) {
  absl::StatusOr<std::string> signature = Sign(kData);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(Verify(*signature, kOtherData),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(GcpKmsSignatureIntegrationTest, VerifyFailsWithModifiedSignature) {
  absl::StatusOr<std::string> signature = Sign(kData);
  ASSERT_THAT(signature, IsOk());

  std::string modified_signature = *signature;
  modified_signature.back() ^= 0x01;
  EXPECT_THAT(Verify(modified_signature, kData),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(GcpKmsSignatureIntegrationTest, VerifyFailsWithTruncatedSignature) {
  absl::StatusOr<std::string> signature = Sign(kData);
  ASSERT_THAT(signature, IsOk());
  ASSERT_FALSE(signature->empty());

  std::string truncated_signature = signature->substr(0, signature->size() - 1);
  EXPECT_THAT(Verify(truncated_signature, kData),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(GcpKmsSignatureIntegrationTest, CreateSignaturePublicKeyReturnsTinkKey) {
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>> public_key =
      CreateSignaturePublicKey(GetParam().key_version_name, *kms_client_);
  ASSERT_THAT(public_key, IsOk());
  ASSERT_THAT(*public_key, NotNull());

  // Cloud KMS signatures carry no Tink prefix, so the key must not add one.
  EXPECT_TRUE((*public_key)->GetOutputPrefix().empty());
}

TEST_P(GcpKmsSignatureIntegrationTest, OfflineVerifyWithNoRpcsSuccess) {
  absl::StatusOr<std::string> signature = Sign(kData);
  ASSERT_THAT(signature, IsOk());

  // Fetch the public key material, then build a verifier from it without
  // further calls to Cloud KMS.
  absl::StatusOr<PublicKey> kms_public_key =
      internal::FetchKmsPublicKey(GetParam().key_version_name, *kms_client_);
  ASSERT_THAT(kms_public_key, IsOk());

  absl::StatusOr<std::unique_ptr<SignaturePublicKey>> public_key =
      CreateSignaturePublicKeyWithNoRpcs(kms_public_key->public_key().data(),
                                         kms_public_key->algorithm(),
                                         GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<PublicKeyVerify>> verifier =
      CreateGcpKmsPublicKeyVerifyWithNoRpcs(**public_key);
  ASSERT_THAT(verifier, IsOk());

  EXPECT_THAT((*verifier)->Verify(*signature, kData), IsOk());
  EXPECT_THAT((*verifier)->Verify(*signature, kOtherData),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(GcpKmsSignatureIntegrationTest, SignVerifyMaxDataSizeSuccess) {
  // Only the algorithms that send the message itself to Cloud KMS are subject
  // to the client-side size limit; the ones that sign a digest are not.
  if (!GetParam().requires_data_for_sign) {
    GTEST_SKIP() << "The key signs a digest, so the limit does not apply.";
  }
  const std::string max_data(kMaxSignDataSize, 'a');

  absl::StatusOr<std::string> signature = Sign(max_data);
  ASSERT_THAT(signature, IsOk());
  EXPECT_THAT(Verify(*signature, max_data), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    GcpKmsSignatureIntegrationTests, GcpKmsSignatureIntegrationTest,
    testing::ValuesIn(GetSignatureKeyTestCases()),
    [](const testing::TestParamInfo<SignatureKeyTestCase>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
