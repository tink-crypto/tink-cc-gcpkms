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

#include "tink/integration/gcpkms/gcp_kms_public_key_verify.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "google/cloud/kms/v1/key_management_client.h"
#include "google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "google/cloud/status.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/public_key_verify.h"
#include "tink/signature/config_v0.h"
#include "tink/signature/signature_config.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::Status;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kData = "data";

// Generated with
// $ openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
// after generating the private key with
// $ openssl ecparam -name prime256v1 -genkey -noout -out ecdsa-private.pem
constexpr absl::string_view kEcdsaPublicKey = R"(
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPu+j4MR6Veo9F2YyKq0AObMM3UoN
K4Z6V0tej/9smL+QfqkILtkY0DROmBbLb/tOg+zi/q6CAG5FuBK7CaZP0g==
-----END PUBLIC KEY-----
)";

// Generated with
// $ echo -n "data" | openssl dgst -sha256 -sign ecdsa-private.pem | base64
constexpr absl::string_view kEcdsaSignature = R"(
MEUCIQD1n5HhsGwZ4hU2LVqTnUqQLlGidxPVVUBPbg8W1FGm4QIgQtSebi2H9/EZPKSsqYnkIFts
zI4jNZYWfcOFOjtJi7o=
)";

// Generated with
// $ openssl rsa -in rsa-private.pem -pubout > rsa-public.pem
// after generating the private key with
// $ openssl genrsa -out rsa-private.pem 2048
constexpr absl::string_view kRsaPublicKey = R"(
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnWdm/pltnPoPL7V+vQzI
YO0xm4d9lTBdWHWyvWIwFbG9ePPI2DS5bAUREY8pW/L7FzhHGvgrkuLgIFP8WTYd
4fm1L+QhhSIIltdnW8IeZobRsmrnz8oN/U6VPN8wGgPUzv1MM/vWQcNfDvv5E/kw
sJAD1e+V6S2rts2f8zFHHP71vXITSumOaVvJTVHZgyWEXA63C2MEQVMhzXrsnJua
5JY9TDAhFHDRiKzng9ZSbRmItutY8+FdlmoZVjWnFnhdloVvn/KzSjv0FmmHwmAI
Tt1aTrN7iWBoy/YBL61yxMMr91gtWh5Dp6KXYErYxS6v5fh5VOmrYJCeMugyokIW
zQIDAQAB
-----END PUBLIC KEY-----
)";

// Generated with
// $ echo -n "data" | openssl pkeyutl -sign -inkey rsa-private.pem
//     -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | base64
constexpr absl::string_view kRsaPkcs1Signature = R"(
NI2jo+WIrKjoyIR/jtlSBT0BJJJ0aDgIi86rXVOqPq35DyULjT1JwtKvgtqocNaeeKDQ4HRQhNKn
ZYeDzQO6nHD6SgngAv0v9FBGTph4VUNZ0To1Bzlk8LP+P/0PWWy59aAHzAFULCiU7/6nP2KSInbR
vg7UmMRXcfw956D3skFZn2dbu/xCRhYuZCiej72s6sNVRC1dHpIBz2+/f7ux4/gJgiYJGC9bvmkR
DzZIy7e3zf1Be7ZT/zAreAbL+Zk8BEvoWItV0YkDUs33MkFY1MCR44grai6fGGOJAxgahlcgvkue
O3tnao5epghHnwamS9I2h8zcBe984Z0MR+NXfw==
)";

// Generated with
// $ echo -n "data" | openssl dgst -sha256 -binary | \
//     openssl pkeyutl -sign -inkey rsa-private.pem -pkeyopt digest:sha256 \
//     -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:32 | base64
constexpr absl::string_view kRsaPssSignature = R"(
FhypcoCQT2X/9tn3qo7s9GSFjPew41hV2OveWlAwElYzke4dlfVIrpgnfpjOMHJuD2BIJc7ePKi2
XPTS+QS3LmWx8Qv4wKUgdluDK0ZD+Dm2MAHfYaLq3J3LqJhjOkcnM2KuYJcUFj40edYkhwg1oYUc
4EEKrSIh72Px6GGJa0nbRuCYx9vm7eH5zx/M4wIpOF+ScczoL6LkOyX8hFB2Ub9LxBh3OPahe/zT
QKy0+gMjUGqjwTxq3EBlkngY0LWh2fE+COhoq6mAddViyVfJjHCApY1KZXPWgg5tzbpttmDf6yKT
StTyAxt686GkeWL0kUzsmkGDQB1Ld6WJ+5KNlQ==
)";

// Generated with:
// openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:secp256k1 \
//   | openssl pkey -pubout
constexpr absl::string_view kSecp256k1PublicKey =
    "-----BEGIN PUBLIC KEY-----\n"
    "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuDj/ROW8F3vyEYnQdmCC/J2EMiaIf8l2\n"
    "A3EQC37iCm/wyddb+6ezGmvKGXRJbutW3jVwcZVdg8Sxutqgshgy6Q==\n"
    "-----END PUBLIC KEY-----";

constexpr absl::string_view kKeyNameEcdsa =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1";
constexpr absl::string_view kKeyNameRsaPkcs1 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/2";
constexpr absl::string_view kKeyNameRsaPss =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/3";
constexpr absl::string_view kKeyNameErrorGetPublicKey =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/4";
constexpr absl::string_view kKeyNameCrcNameError =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/5";
constexpr absl::string_view kKeyNameCrcPemError =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/6";
constexpr absl::string_view kKeyNameEcdsaSecp256k1 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/7";

class TestGcpKmsPublicKeyVerify : public testing::Test {
 public:
  TestGcpKmsPublicKeyVerify()
      : mock_connection_(
            std::make_shared<MockKeyManagementServiceConnection>()),
        kms_client_(
            std::make_shared<KeyManagementServiceClient>(mock_connection_)) {}

  // Public keys generated with openssl match Cloud KMS public keys.
  void ExpectGetPublicKey(int times) {
    EXPECT_CALL(*mock_connection_, GetPublicKey)
        .Times(times)
        .WillRepeatedly([&](kmsV1::GetPublicKeyRequest const& request)
                            -> StatusOr<kmsV1::PublicKey> {
          kmsV1::PublicKey response;
          response.set_name(request.name());
          if (request.name() == kKeyNameCrcNameError) {
            response.set_name("different_key");
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
          } else if (request.name() == kKeyNameEcdsa) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kEcdsaPublicKey);
          } else if (request.name() == kKeyNameRsaPkcs1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsaPublicKey);
          } else if (request.name() == kKeyNameRsaPss) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsaPublicKey);
          } else if (request.name() == kKeyNameEcdsaSecp256k1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_SECP256K1_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::HSM);
            response.set_pem(kSecp256k1PublicKey);
          } else if (request.name() == kKeyNameErrorGetPublicKey) {
            return Status(google::cloud::StatusCode::kInternal,
                          "Internal error");
          }

          response.mutable_pem_crc32c()->set_value(
              static_cast<uint32_t>(absl::ComputeCrc32c(response.pem())));
          if (request.name() == kKeyNameCrcPemError) {
            response.mutable_pem_crc32c()->set_value(1773);
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_P256_SHA256);
          }
          return StatusOr<kmsV1::PublicKey>(response);
        });
  }

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

TEST_F(TestGcpKmsPublicKeyVerify, NullKmsClientFails) {
  EXPECT_THAT(CreateGcpKmsPublicKeyVerify(kKeyNameEcdsa, /*kms_client=*/nullptr)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsPublicKeyVerify, EmptyKeyNameFails) {
  EXPECT_THAT(
      CreateGcpKmsPublicKeyVerify(/*key_name=*/"", kms_client_).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("does not match")));
}

TEST_F(TestGcpKmsPublicKeyVerify, WrongKeyNameFails) {
  EXPECT_THAT(
      CreateGcpKmsPublicKeyVerify(/*key_name=*/"Wrong/Key/Name", kms_client_)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("does not match")));
}

TEST_F(TestGcpKmsPublicKeyVerify, GetPublicKeyFails) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameErrorGetPublicKey, kms_client_);
  EXPECT_THAT(kms_verifier.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("GCP KMS GetPublicKey failed")));
}

TEST_F(TestGcpKmsPublicKeyVerify, GetPublicKeyCrcNameMismatchFails) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameCrcNameError, kms_client_);
  EXPECT_THAT(kms_verifier.status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("The key name in the response")));
}

TEST_F(TestGcpKmsPublicKeyVerify, GetPublicKeyCrcPemMismatchFails) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameCrcPemError, kms_client_);
  EXPECT_THAT(kms_verifier.status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Public key checksum mismatch")));
}

TEST_F(TestGcpKmsPublicKeyVerify,
       CreateGcpKmsPublicKeyVerifyWithEcdsaSecp256k1Fails) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameEcdsaSecp256k1, kms_client_);
  EXPECT_THAT(kms_verifier.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported algorithm")));
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyEcdsaSuccess) {
  ExpectGetPublicKey(1);
  auto kms_verifier = CreateGcpKmsPublicKeyVerify(kKeyNameEcdsa, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kEcdsaSignature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyEcdsaInvalidSignature) {
  ExpectGetPublicKey(1);
  auto kms_verifier = CreateGcpKmsPublicKeyVerify(kKeyNameEcdsa, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kEcdsaSignature, &signature));
  signature[0] ^= 0x01;
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid signature")));
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsaPkcs1Success) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameRsaPkcs1, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPkcs1Signature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsaPkcs1InvalidSignature) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameRsaPkcs1, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPkcs1Signature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
  signature[0] ^= 0x01;
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid signature")));
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsaPssSuccess) {
  ExpectGetPublicKey(1);
  auto kms_verifier = CreateGcpKmsPublicKeyVerify(kKeyNameRsaPss, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPssSignature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsaPssInvalidSignature) {
  ExpectGetPublicKey(1);
  auto kms_verifier = CreateGcpKmsPublicKeyVerify(kKeyNameRsaPss, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPssSignature, &signature));
  signature[0] ^= 0x01;
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid signature")));
}

TEST_F(TestGcpKmsPublicKeyVerify, GetSignaturePublicKeyEcdsaSuccess) {
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameEcdsa, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());

  // Verify a signature with the key.
  auto tink_keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              tink_key.value(), ::crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  EXPECT_THAT(tink_keyset_handle->Validate(), IsOk());

  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kEcdsaSignature, &signature));

  auto verifier = tink_keyset_handle->GetPrimitive<PublicKeyVerify>(
      crypto::tink::ConfigSignatureV0());
  EXPECT_THAT(verifier, IsOk());
  EXPECT_THAT(verifier.value()->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, GetSignaturePublicKeyRsaPkcs1Success) {
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameRsaPkcs1, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());

  // Verify a signature with the key.
  auto tink_keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              std::move(tink_key.value()), ::crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  EXPECT_THAT(tink_keyset_handle->Validate(), IsOk());

  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPkcs1Signature, &signature));

  EXPECT_THAT(tink_keyset_handle->Validate(), IsOk());
  auto verifier = tink_keyset_handle->GetPrimitive<PublicKeyVerify>(
      crypto::tink::ConfigSignatureV0());
  EXPECT_THAT(verifier, IsOk());
  EXPECT_THAT(verifier.value()->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, GetSignaturePublicKeyRsaPssSuccess) {
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameRsaPss, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());

  // Verify a signature with the key.
  auto tink_keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              std::move(tink_key.value()), ::crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  EXPECT_THAT(tink_keyset_handle->Validate(), IsOk());

  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPssSignature, &signature));

  EXPECT_THAT(tink_keyset_handle->Validate(), IsOk());
  auto verifier = tink_keyset_handle->GetPrimitive<PublicKeyVerify>(
      crypto::tink::ConfigSignatureV0());
  EXPECT_THAT(verifier, IsOk());
  EXPECT_THAT(verifier.value()->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, GetSignaturePublicKeyEcdsaSecp256k1Fails) {
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameEcdsaSecp256k1, kms_client_);
  EXPECT_THAT(tink_key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                          HasSubstr("Unsupported algorithm")));
}

TEST_F(TestGcpKmsPublicKeyVerify, CallRegisterTwiceOk) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameEcdsa, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
