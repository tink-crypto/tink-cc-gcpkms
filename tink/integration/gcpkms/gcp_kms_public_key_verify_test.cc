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
// $ openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
// after generating the private key with
// $ openssl ecparam -name secp384r1 -genkey -noout -out ecdsa-private.pem
constexpr absl::string_view kEcdsa384PublicKey = R"(
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEvhSzPPgaNlVa7ALdPv2TU/y7zcztJKMW
Uyb4EFljhW+HwMedJ9rq58P9vCO81GK+uzMElfKXwyh9Hwki3OrHw/U/QpEHrYAc
mjodwJBbZu8a/6Oc2bXN96IwqOhAM70l
-----END PUBLIC KEY-----
)";

// Generated with
// $ echo -n "data" | openssl dgst -sha384 -sign ecdsa-private.pem | base64
constexpr absl::string_view kEcdsa384Signature = R"(
MGUCMEJreAXQPgGuVKNEctuQRAh8sbdWbnxwbOIERx6A7KrXfx/VIGYsEIX9OjIgNGc+pwIxAOVN
n7DccgsZjhOwaL+HsI0RqbBFxRIaLQjlO9JT5BWxbsRX/7nio7krXpcfXFhnDg==
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
// $ openssl rsa -in rsa-private-4096.pem -pubout > rsa-public-4096.pem
// after generating the private key with
// $ openssl genrsa -out rsa-private-4096.pem 4096
constexpr absl::string_view kRsa4096PublicKey = R"(
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1GeEVEj1xv0ppPMAVMmK
PIsx7xt/6lyM2I9Am11HDVZ8+pN9FgGb7hMIXqBQWWhLCStvLBJPSlv+RUsw1GK4
3MD+Yxlc4X132KaC/Z6qIf+aD5FthfETtTEJem7HCTCSEyJXoeXYu69NrN9e+m+V
bcIVFaZ+f31tiDtSZi7fTCVbmSGG9WeqKZe/hKuhOan8lH2IJmxFjOk9hKFVqxB0
wTMFw7enAwLJxDqQMFXVK8zgjfvJ147AIol96VbS7si9Lnff9TfNjzcGfe1hsXNP
g10gLFu2N2LmjD9sb1gfWJGSGTsJiyX/owu+jj7GCWyQhY6hFTvZKbE0c1ZFLYbv
IiUBYJZUBk58iFgO7WA+fync9jDN9nNlw68e3xnqF7iherDS7IqZ5x8d+b+wgJKy
pBJI5hYY3OJB2yp4Ao9K4wQFxvJBBpg3jCGoofVVjrA8lePa3Yb8EHy+z5u5mYNj
VSxw8SXzqNsAgl5aW6c7Gs1c7m+Hpfdi4K+OJl60H0eYF+ks0KVShNRYri6q347D
IVpX3Qc6YOGPUHUj9lX7NfFJseGzbiJYTOQ+kVxvCmUqKMfq1vLvkgEfTpK53pTy
Z8h8oIZLTJo4MPwFbQAWNcKBGh43fMLWVWCED64N1S/2qNVv1R90OCerKLaX8WdY
txOSq3pgn5BD2tHhZ7ZmxTsCAwEAAQ==
-----END PUBLIC KEY-----
)";

// Generated with
// $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign \
//     -inkey rsa-private.pem \
//     -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | base64
constexpr absl::string_view kRsaPkcs1Signature = R"(
NI2jo+WIrKjoyIR/jtlSBT0BJJJ0aDgIi86rXVOqPq35DyULjT1JwtKvgtqocNaeeKDQ4HRQhNKn
ZYeDzQO6nHD6SgngAv0v9FBGTph4VUNZ0To1Bzlk8LP+P/0PWWy59aAHzAFULCiU7/6nP2KSInbR
vg7UmMRXcfw956D3skFZn2dbu/xCRhYuZCiej72s6sNVRC1dHpIBz2+/f7ux4/gJgiYJGC9bvmkR
DzZIy7e3zf1Be7ZT/zAreAbL+Zk8BEvoWItV0YkDUs33MkFY1MCR44grai6fGGOJAxgahlcgvkue
O3tnao5epghHnwamS9I2h8zcBe984Z0MR+NXfw==
)";

// Generated with
// $ echo -n "data" | openssl dgst -sha256 -binary | openssl pkeyutl -sign \
//     -inkey rsa-private-4096.pem  \
//     -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pkcs1 | base64
constexpr absl::string_view kRsa4096Sha256Pkcs1Signature = R"(
cqJsTB70moE9s+3OElRbmLFFXkRIYU0TKuhL+y8UMr/XUOqcXdrynnionthm6DJm681TJ88eHN29
eeZiyTt1UtQZBbMjAUOdrhcndHNdoxfQuVPJ8a4HuMOWXTT6B2ewxNDrWjhJZ2PARPBnl3OR1JWe
x8ynj7gIPFcsW6+pVDilMmxRkHHxj3xKplQ+uYRlY9ifggcs/ujx+UxZcScicfZWTbNuGlmddN6+
IV6q++gW7VoU+OZSaLBttFU93ohkLNnFYjRF1JxdKXNzOciJ7/AHtDd/XJ2zqnJsJCm0G/GkK+UB
W3lTkFcWjaqEqQEFKxVygIWIQsKF760BoZDkTgeSFeSo0aUAFG3WlKFoDQKQUVVgoKq0cU+VMqin
vfAunEHJAmq4An9IcxX3As8gyGByHO5xfoXwRrQfrJunRGWPvp5MXFm+i53FkfkDs1+DtypSKkX0
BrCSu1uRmIZxt0MhgJWgvQdXtglH3y4b7bmFOG/dvyGhMoSSpfRdjulPL/P5jW+zlDdwpr8WtrnY
RC0m4X8YpiBhXojYd1rtne5Q+A8t8EKNt2SXPadhSsRPoNF5wgD9tkoTvE0SbbdUm59c+cp9Hdj+
oJTWhYtpAcC+p6WebsZ9ILE180j44RRMF9GRk34AiDhr5bOwR+EEi8ScMj7LQhb+lcfQKwYr0EU=
)";

// Generated with
// $ echo -n "data" | openssl dgst -sha512 -binary | openssl pkeyutl -sign \
//     -inkey rsa-private-4096.pem  \
//     -pkeyopt digest:sha512 -pkeyopt rsa_padding_mode:pkcs1 | base64
constexpr absl::string_view kRsa4096Sha512Pkcs1Signature = R"(
lq3wThF4Xa99ICz0vsTSBMa+uUclsECaUetUmLDvB/zjmHBIzeFrf6l0b/OtF9gnqq35nbvnJlaC
8vCZJMYfiGahkUfi7Vqw4sxxCfmBTbN+F8bl4n0dV+Na00pNHgRNKLaOcstyvBC74DD4e3mM799T
3nOELe8ASUCa0jGlVDhrSIQVt1wnfNZktrLWRjWm+cCz9w5RXira2fqz3/sDQbG6AcpJ8SzsfBd4
/52sQTRtrIDs2T+0BEku77rFozXMhO0ttkVsFijNsUr0R+FG3/gkPVBbMJl5ClCJw7qifsTsdw0M
iCunp6lvAm9CAz5AZMjA+iFgFSILaPLTFHy8Z5kFLcTqhgHcQAgqGGlhiucuuXruO+b907GyQ4tx
qWtWVuWmNWVgC9HAh3ra1tN7SgLj7cKFABq1GqNzkp6bDMtjutr8GfXMmIG/at4Uj9pmlpe+1ob1
dEFU8Oq/xdnrATTIzagqHrHqMSLqZ4/vXwwaDoIDDlR3tULV9/pPhh+60F4z8c4SbDSPOHTMxT3f
RtxO+ko9JZmka5PaGnjtNQVc16XYTR+23asReB6gcIu2xvvIhxtxASANdg5Nk+L/M6IZeFx0hnGO
B4AVQ2YF8IJ58A1rr9tT41MtyaPhGjOTNuFPlnyAJ5V/CalwuAtGFq5fMokC+AzcL4p9KruIodE=
)";

// Generated with
// $ echo -n "data" | openssl pkeyutl -sign -inkey rsa-private-4096.pem
//     openssl pkeyutl -sign -inkey rsa-private.pem -pkeyopt digest:sha256 \
//     -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:32 | base64
constexpr absl::string_view kRsaPssSignature = R"(
FhypcoCQT2X/9tn3qo7s9GSFjPew41hV2OveWlAwElYzke4dlfVIrpgnfpjOMHJuD2BIJc7ePKi2
XPTS+QS3LmWx8Qv4wKUgdluDK0ZD+Dm2MAHfYaLq3J3LqJhjOkcnM2KuYJcUFj40edYkhwg1oYUc
4EEKrSIh72Px6GGJa0nbRuCYx9vm7eH5zx/M4wIpOF+ScczoL6LkOyX8hFB2Ub9LxBh3OPahe/zT
QKy0+gMjUGqjwTxq3EBlkngY0LWh2fE+COhoq6mAddViyVfJjHCApY1KZXPWgg5tzbpttmDf6yKT
StTyAxt686GkeWL0kUzsmkGDQB1Ld6WJ+5KNlQ==
)";

// echo -n "data" | openssl dgst -sha256 -binary |
//      openssl pkeyutl -sign -inkey rsa-private-4096.pem
//      -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss
//      -pkeyopt rsa_pss_saltlen:32 | base64
constexpr absl::string_view kRsaPss4096Sha256Signature = R"(
WMEq0q7+U24gx2SOwzWRI0M7aoYAvpQnz5kPMKRA4Ortn0bcJIsKXy4g4facoLygo+hJ4KiMmCQP
sbNoz/3hgfQcTc5XfPAVbkBkT3nnYcY77wib1f/VSQpdObcAs4bE7EyQrXUB4fkIdQlj96GvreP6
Vak0xjpSEdv0mA2rXuPWKsXUObsX1Wkto3Kz5DNplzxO2ofroo3VL8Lu3jv3OHH+c/fc9mKO5LRW
4nIaf6n8IkNq7zR2OioN3461+Uhc+5PpFBy9SCpdWJmlCYstN13Z8OLRi5zYhq8J8JBtJh1RkFDo
mNrEbkGKDd+VIgbuYpS7zRtJRFuBcHBrOorTLy84YWOW5xIn1HeWax/mPneUs+gJk4Eu7wGaFDyh
pJiLhw99AFn7b+Q2hCaQm+6/SW1YjBqKPX7Sd9JTjadsTO+t/3kEI31TN/2MTTAkTuRYswgm8dBs
RXmKMGJmzC7SIMxg0+tmuVkwbz2CPnv5CLSH9F6MuN1uynSWCzurOkyQUAy6J/A49EO/EPm+HY1W
F29Oz+3Hn++CDnBoB9fKorFWgqD0j6qwK6JDzT9e7Dn0Cp+EhbffU0BBYM0F6YgmbGN7Kf7XnrsY
ywVS6k6dmdkTzFWyRWszkfBNW3iTaOraGuEvQ8qi/93vNUFefGqDg0Mn7pm2bVL0Dukpc5RpRjg=
)";

// Generated with
// echo -n "data" | openssl dgst -sha512 -binary |
//      openssl pkeyutl -sign -inkey rsa-private-4096.pem
//      -pkeyopt digest:sha512 -pkeyopt rsa_padding_mode:pss
//      -pkeyopt rsa_pss_saltlen:64 | base64
constexpr absl::string_view kRsaPss4096Sha512Signature = R"(
zMztdsH/VYhGe32DCt3aSn9gUhzPREQhkMUi6bCHTzdV9wrN2yuAPCWRmBPymXh2tB7chB/gbJWU
YQeXYZtBgRnJKaPHhtQpeDFJwzbJt2eIiFA9RthLbo9kg1U9VuiXqfjKmkbj8Z5qbyJXVdl4f6hh
Ai2aGXaEpliRPLRUyuJRIIOU4O8clTQAoHqHCOLNtfpYU2LSABL6nM9awf/OGD98SFJ7sLwBDtB0
b7imZxBYayf0E1h1pza8XdHVYmTxQ+jdc5nYk+G27AzU0SZUviB5tdAt62xtFZiRi6vkk7FgfY+m
1jqv9FmklOiBuuZDPjdfQ1zlYTLdQHrGVCgO9jenC+OkeVyKOPmVgvETBsSEkr/W7kf2OM84mksy
mO10c0xqTCOi/cJd6zUYmi5IksU8DXQ1y8ZABzSoqIlRsOmyRQiW0CH+HmFl8HgtwZ9cSiKYtzag
I5QnFhvzpt3/fI52HeAebUFsd9x4xNmvcDkdXTO/cHCJXSRRO88LKBtuKZHgiXEfyQubEcTKMJxe
Q1sM0efzF/Br3aylzgzd+a5KvMq/0WGoVmHgvrH41lVxIlL2K1MHopfWz1Qi9sFVyB3MmIXIpcSL
GGYPgxL+zvqtZL+01ury1ASUw28414i4LU7OUO3C1oQc/tR4eETXYZ++qSsS6XmT7Br8k7h1VpQ=
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
constexpr absl::string_view kKeyNameRsa4096Sha256Pkcs1 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/8";
constexpr absl::string_view kKeyNameRsa4096Sha512Pkcs1 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/9";
constexpr absl::string_view kKeyNameRsaPss4096Sha256 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/10";
constexpr absl::string_view kKeyNameRsaPss4096Sha512 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/11";
constexpr absl::string_view kKeyNameEcdsa384 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/12";

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
          } else if (request.name() == kKeyNameEcdsa384) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kEcdsa384PublicKey);
          } else if (request.name() == kKeyNameRsaPkcs1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsaPublicKey);
          } else if (request.name() == kKeyNameRsa4096Sha256Pkcs1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsa4096PublicKey);
          } else if (request.name() == kKeyNameRsa4096Sha512Pkcs1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsa4096PublicKey);
          } else if (request.name() == kKeyNameRsaPss) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsaPublicKey);
          } else if (request.name() == kKeyNameRsaPss4096Sha256) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsa4096PublicKey);
          } else if (request.name() == kKeyNameRsaPss4096Sha512) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.set_pem(kRsa4096PublicKey);
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
  // The `kms_client` parameter is annotated nonnull, but we want to test the
  // defensive null check. Use a variable instead of passing nullptr directly
  // to avoid a `-Wnonnull` warning.
  std::shared_ptr<KeyManagementServiceClient> null_kms_client = nullptr;
  EXPECT_THAT(
      CreateGcpKmsPublicKeyVerify(kKeyNameEcdsa, std::move(null_kms_client))
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

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsa4096Sha256Pkcs1Success) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameRsa4096Sha256Pkcs1, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsa4096Sha256Pkcs1Signature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsa4096Sha512Pkcs1Success) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameRsa4096Sha512Pkcs1, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsa4096Sha512Pkcs1Signature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsaPssSuccess) {
  ExpectGetPublicKey(1);
  auto kms_verifier = CreateGcpKmsPublicKeyVerify(kKeyNameRsaPss, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPssSignature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsaPss4096Sha256Success) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameRsaPss4096Sha256, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPss4096Sha256Signature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

TEST_F(TestGcpKmsPublicKeyVerify, PublicKeyVerifyRsaPss4096Sha512Success) {
  ExpectGetPublicKey(1);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(kKeyNameRsaPss4096Sha512, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPss4096Sha512Signature, &signature));
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

TEST_F(TestGcpKmsPublicKeyVerify, GetSignaturePublicKeyEcdsa256Success) {
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

TEST_F(TestGcpKmsPublicKeyVerify, GetSignaturePublicKeyEcdsa384Success) {
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameEcdsa384, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());

  // Verify a signature with the key.
  auto tink_keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              tink_key.value(), crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();
  EXPECT_THAT(tink_keyset_handle->Validate(), IsOk());

  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kEcdsa384Signature, &signature));

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


TEST_F(TestGcpKmsPublicKeyVerify,
       GetSignaturePublicKeyRsa4096Sha256Pkcs1Success) {
  ExpectGetPublicKey(1);
  auto tink_key =
      GetSignaturePublicKey(kKeyNameRsa4096Sha256Pkcs1, kms_client_);
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
  ASSERT_TRUE(absl::Base64Unescape(kRsa4096Sha256Pkcs1Signature, &signature));

  auto verifier = tink_keyset_handle->GetPrimitive<PublicKeyVerify>(
      crypto::tink::ConfigSignatureV0());
  EXPECT_THAT(verifier, IsOk());
  EXPECT_THAT(verifier.value()->Verify(signature, kData), IsOk());
}


TEST_F(TestGcpKmsPublicKeyVerify,
       GetSignaturePublicKeyRsa4096Sha512Pkcs1Success) {
  ExpectGetPublicKey(1);
  auto tink_key =
      GetSignaturePublicKey(kKeyNameRsa4096Sha512Pkcs1, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());

  // Verify a signature with the key.
  auto tink_keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              std::move(tink_key.value()), ::crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();

  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsa4096Sha512Pkcs1Signature, &signature));

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

TEST_F(TestGcpKmsPublicKeyVerify,
       GetSignaturePublicKeyRsaPss4096Sha256Success) {
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameRsaPss4096Sha256, kms_client_);
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
  ASSERT_TRUE(absl::Base64Unescape(kRsaPss4096Sha256Signature, &signature));

  auto verifier = tink_keyset_handle->GetPrimitive<PublicKeyVerify>(
      crypto::tink::ConfigSignatureV0());
  EXPECT_THAT(verifier, IsOk());
  EXPECT_THAT(verifier.value()->Verify(signature, kData), IsOk());
}


TEST_F(TestGcpKmsPublicKeyVerify,
       GetSignaturePublicKeyRsaPss4096Sha512Success) {
  ExpectGetPublicKey(1);
  auto tink_key = GetSignaturePublicKey(kKeyNameRsaPss4096Sha512, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());

  // Verify a signature with the key.
  auto tink_keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              std::move(tink_key.value()), ::crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();

  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kRsaPss4096Sha512Signature, &signature));

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
