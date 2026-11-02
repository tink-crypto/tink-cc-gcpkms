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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/status_matchers.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "tink/hybrid/hpke_parameters.h"
#include "tink/hybrid/hpke_public_key.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/integration/gcpkms/gcp_kms_hpke_decrypt.h"
#include "tink/integration/gcpkms/gcp_kms_hpke_encrypt.h"
#include "tink/integration/gcpkms/internal/gcp_kms_test_client.h"
#include "tink/partial_key_access.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::testing::Environment;
using ::testing::NotNull;

// KMS key ring hosted in Google Cloud project `tink-test-infrastructure`,
// used for Tink integration tests.
constexpr absl::string_view kKeyVersionPrefix =
    "projects/tink-test-infrastructure/locations/global/keyRings/"
    "unit-and-integration-testing/cryptoKeys/";

constexpr absl::string_view kPlaintext = "This is some plaintext to encrypt.";
constexpr absl::string_view kContextInfo = "This is some context info.";
constexpr absl::string_view kOtherContextInfo = "This is other context info.";

// Returns the resource name of version 1 of `crypto_key`. KEM operations are
// bound to a specific CryptoKeyVersion, so the version is part of the name.
std::string KeyVersionName(absl::string_view crypto_key) {
  return absl::StrCat(kKeyVersionPrefix, crypto_key, "/cryptoKeyVersions/1");
}

struct HpkeKeyTestCase {
  // Name of this test case, used to build the gtest test names.
  std::string test_name;
  // Resource name of the CryptoKeyVersion to encrypt and decrypt with.
  std::string key_version_name;
  // HPKE KEM algorithm identifier.
  HpkeParameters::KemId kem_id;
  // HPKE KDF algorithm identifier.
  HpkeParameters::KdfId kdf_id;
  // HPKE AEAD algorithm identifier.
  HpkeParameters::AeadId aead_id;
};

std::vector<HpkeKeyTestCase> GetHpkeKeyTestCases() {
  return {
      {"XWingAesGcm256", KeyVersionName("xwing-key"),
       HpkeParameters::KemId::kXWing, HpkeParameters::KdfId::kHkdfSha256,
       HpkeParameters::AeadId::kAesGcm256},
      {"MlKem768AesGcm128", KeyVersionName("ml-kem-768-key"),
       HpkeParameters::KemId::kMlKem768, HpkeParameters::KdfId::kHkdfSha256,
       HpkeParameters::AeadId::kAesGcm128},
      {"MlKem1024ChaCha20Poly1305", KeyVersionName("ml-kem-1024-key"),
       HpkeParameters::KemId::kMlKem1024, HpkeParameters::KdfId::kHkdfSha256,
       HpkeParameters::AeadId::kChaCha20Poly1305},
  };
}

class GcpKmsHpkeIntegrationTestEnvironment : public Environment {
 public:
  ~GcpKmsHpkeIntegrationTestEnvironment() override = default;

  void SetUp() override { internal::SetGrpcDefaultSslRootsForTesting(); }
};

Environment* const kHpkeEnv = testing::AddGlobalTestEnvironment(
    new GcpKmsHpkeIntegrationTestEnvironment());

class GcpKmsHpkeIntegrationTest
    : public testing::TestWithParam<HpkeKeyTestCase> {
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

  absl::StatusOr<HpkeParameters> BuildHpkeParameters() const {
    return HpkeParameters::Builder()
        .SetKemId(GetParam().kem_id)
        .SetKdfId(GetParam().kdf_id)
        .SetAeadId(GetParam().aead_id)
        .SetVariant(HpkeParameters::Variant::kNoPrefix)
        .Build();
  }

  // Encrypts `plaintext` with `context_info` using the public key fetched from
  // Cloud KMS.
  absl::StatusOr<std::string> Encrypt(absl::string_view plaintext,
                                      absl::string_view context_info) {
    absl::StatusOr<HpkeParameters> params = BuildHpkeParameters();
    if (!params.ok()) {
      return params.status();
    }
    absl::StatusOr<std::unique_ptr<HybridEncrypt>> encryptor =
        CreateGcpKmsHybridEncrypt(GetParam().key_version_name, *kms_client_,
                                  *params);
    if (!encryptor.ok()) {
      return encryptor.status();
    }
    return (*encryptor)->Encrypt(plaintext, context_info);
  }

  // Decrypts `ciphertext` with `context_info` using Cloud KMS.
  absl::StatusOr<std::string> Decrypt(absl::string_view ciphertext,
                                      absl::string_view context_info) {
    absl::StatusOr<HpkeParameters> params = BuildHpkeParameters();
    if (!params.ok()) {
      return params.status();
    }
    absl::StatusOr<std::unique_ptr<HybridDecrypt>> decryptor =
        CreateGcpKmsHybridDecrypt(GetParam().key_version_name, *kms_client_,
                                  *params);
    if (!decryptor.ok()) {
      return decryptor.status();
    }
    return (*decryptor)->Decrypt(ciphertext, context_info);
  }

  static std::shared_ptr<KeyManagementServiceClient>* kms_client_;
};

std::shared_ptr<KeyManagementServiceClient>*
    GcpKmsHpkeIntegrationTest::kms_client_ = nullptr;

TEST_P(GcpKmsHpkeIntegrationTest, EncryptDecryptRoundTripSuccess) {
  absl::StatusOr<std::string> ciphertext = Encrypt(kPlaintext, kContextInfo);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(Decrypt(*ciphertext, kContextInfo), IsOkAndHolds(kPlaintext));
}

TEST_P(GcpKmsHpkeIntegrationTest,
       EncryptDecryptEmptyPlaintextAndContextInfoSuccess) {
  absl::StatusOr<std::string> ciphertext =
      Encrypt(/*plaintext=*/"", /*context_info=*/"");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(Decrypt(*ciphertext, /*context_info=*/""), IsOkAndHolds(""));
}

TEST_P(GcpKmsHpkeIntegrationTest, DecryptFailsWithModifiedContextInfo) {
  absl::StatusOr<std::string> ciphertext = Encrypt(kPlaintext, kContextInfo);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT(Decrypt(*ciphertext, kOtherContextInfo),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(GcpKmsHpkeIntegrationTest, DecryptFailsWithModifiedCiphertext) {
  absl::StatusOr<std::string> ciphertext = Encrypt(kPlaintext, kContextInfo);
  ASSERT_THAT(ciphertext, IsOk());
  ASSERT_FALSE(ciphertext->empty());

  std::string modified_ciphertext = *ciphertext;
  modified_ciphertext.back() ^= 0x01;
  EXPECT_THAT(Decrypt(modified_ciphertext, kContextInfo),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(GcpKmsHpkeIntegrationTest, DecryptFailsWithTruncatedCiphertext) {
  absl::StatusOr<std::string> ciphertext = Encrypt(kPlaintext, kContextInfo);
  ASSERT_THAT(ciphertext, IsOk());
  ASSERT_FALSE(ciphertext->empty());

  std::string truncated_ciphertext =
      ciphertext->substr(0, ciphertext->size() - 1);
  EXPECT_THAT(Decrypt(truncated_ciphertext, kContextInfo),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(GcpKmsHpkeIntegrationTest, CreateHpkePublicKeyReturnsTinkKey) {
  absl::StatusOr<HpkeParameters> params = BuildHpkeParameters();
  ASSERT_THAT(params, IsOk());

  absl::StatusOr<HpkePublicKey> public_key =
      CreateHpkePublicKey(GetParam().key_version_name, *kms_client_, *params);
  ASSERT_THAT(public_key, IsOk());

  // Cloud KMS ciphertexts carry no Tink prefix, so the key must not add one.
  EXPECT_TRUE(public_key->GetOutputPrefix().empty());
  EXPECT_EQ(public_key->GetParameters(), *params);
}

TEST_P(GcpKmsHpkeIntegrationTest, OfflineEncryptWithNoRpcsSuccess) {
  absl::StatusOr<HpkeParameters> params = BuildHpkeParameters();
  ASSERT_THAT(params, IsOk());

  // Fetch the public key material, then build an encryptor from it without
  // further calls to Cloud KMS.
  absl::StatusOr<HpkePublicKey> kms_public_key =
      CreateHpkePublicKey(GetParam().key_version_name, *kms_client_, *params);
  ASSERT_THAT(kms_public_key, IsOk());

  absl::StatusOr<HpkePublicKey> public_key = CreateHpkePublicKeyWithNoRpcs(
      kms_public_key->GetPublicKeyBytes(GetPartialKeyAccess()), *params,
      GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  absl::StatusOr<std::unique_ptr<HybridEncrypt>> encryptor =
      CreateGcpKmsHybridEncryptWithNoRpcs(*public_key);
  ASSERT_THAT(encryptor, IsOk());

  absl::StatusOr<std::string> ciphertext =
      (*encryptor)->Encrypt(kPlaintext, kContextInfo);
  ASSERT_THAT(ciphertext, IsOk());

  EXPECT_THAT(Decrypt(*ciphertext, kContextInfo), IsOkAndHolds(kPlaintext));
  EXPECT_THAT(Decrypt(*ciphertext, kOtherContextInfo),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

INSTANTIATE_TEST_SUITE_P(
    GcpKmsHpkeIntegrationTests, GcpKmsHpkeIntegrationTest,
    testing::ValuesIn(GetHpkeKeyTestCases()),
    [](const testing::TestParamInfo<HpkeKeyTestCase>& info) {
      return info.param.test_name;
    });

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
