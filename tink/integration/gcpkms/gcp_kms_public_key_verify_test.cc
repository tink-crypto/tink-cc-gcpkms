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
#include "tink/partial_key_access.h"
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
using ::google::cloud::kms::v1::CryptoKeyVersion;
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

// Generated the private key with Cloud KMS and exported public key.
constexpr absl::string_view kMlDsaPublicKey = R"(
abjXrycN1wWlu3j2h0aNpeUKoZ44pbopLr5MJ7tIf0aDVH/+1M3n1LgyjoBZqi0Vs7an4V64Yb4bHISx
refVdCOVKlOoMf56TM3eGfGo1C+c+8Bu3uNzAJKtIq1VONOi+vrMCjeEbFG1EqONbhIraj8m4XzWExQ/
iNeB+mHd5tvgUvKtRR369xSYtW28HbrWE3kCjS07mLOpilm7EgAS+02rkUhI9i9/FqAGhhj456A4Mg4/
kcoiaLqrUISsrBCmIJgWe8wAiukJ9g3+RMnXNM77qJJ9Jy4xWNA/L7FdQuBynWihn/yyxNJOs3iKVR2y
GDlV6ah6vQxc9mkcK7QmcpRiIHJybk1vwNuOzAdkn9RJ4EVcBFLf1c4DAVeeBJSU8olvWMlIwXen7MrP
GLLXTEuXI3hiRqhOscC2IKdxesdV9IOwIxdeiiAWRK9mQTY5wMzdHiwCctT7tXjOLTN5FW9beJrUYX9d
jTfDrBnwhYGrpgVOzk3fgnwyfUNIv116NhHSVCa9DSD4pfGgJAKFsdis681oE77gC2ESD6/bRYaLn3Vv
rD5Ms3VxI6egzYezh9sjrPGx1aBwu3fiAmotlrt7c2g4wbQCf3pg3mI8mtgXeflV60Z9o13PpOimbLd/
NA0GKkoUCbxj8gQc7dOqXlQCWz2asgoE4OWKz99nisX0yJshPNa2YfBFyXgJb7UsgU8/As8YcBydNoFW
Y7CsQvFo5FSLB+nm0Suj0SyXBvckZcdDxci3tsCW0kv1uxnnZEGagMdAY53FbLLAA5kUYZJPDcduW45C
2cg2MDB4c10mG7chF5i8T9aRUpq8D6J9ISOSK4zHCFd5GrsnMvF0LELLLv987OntiJ58/hyl2FQYnPui
J0jFU7dftCdskU/Ryi72skPe0qYmdE7Ze5zSVB+koRhl+moVgqSYr+nHMrDt8Q7gV7QccAch28hAU/aG
/7uPGbWPKYO31ZoG+/c4vd49KjWV4HP7mWIl1bCRkHmcXNvB+esOhHKC9pB5gXsrQPl++FQGKtrKFyVG
4w485M08UJoK5ptMTxiKahaTqE4f9lJYNPeMfJR32CiTFqZ7QldNZtEHTRbpOvIULegy3w9vxLECQWTn
TsCwArpSemLP7f1IPVvIfsQND4AJ6nnUR2n2pvsZz/vhufeSzgZ7lNPcQuTt+Mf/IuhGSmlS3aLLaU9K
qxHxPQnXRXPDMNnJ8QC0ZiOkcDAJxhU/+6qHl4z/52qYUV2qiVvDn+ns9yHnFfPnxBhKwpsDefj67toP
+nqNfDP3sEvhAm3cxEQtLEdDbvz1nebu1rMHBm4zQ3oCz5ZpC1VB5hq2I6nHGsjbcx0eLSaa+wiPJd04
UoXzXHswBaaOM0EO82ijh4xhOT1aOyz5FwXOxAOO27rArCAtMgwt/nVDV6NLQOYrCXaljwR3crcytaVV
LpMpVs9Q82OkBfv8zhR0OEfbZYOvMWg7REC79UCrmZZp5kd92eOqLBtx9GvNliK/wW666gFJjOJiLiZj
Kv8EZfaV4cVygoFFmr7FQIMtDGhs3OJXbQXpxHETMUsEmxFRHolRSCeojylP/8tMivEXzdhLM3YL5TBr
RrJPPCFrfQsxq+N/INjYatIwzCSJJsBVSP5bfQE6WK5eCggnfJGgtdf5BEMviRaPo5ZjYbqBzl6CBrbh
ouaJnqe0QyUqoawYknhSl3fDMdZPBUcYnCK8c36mPSqXfXk5g+tRPU+hoCj2Dp5f+aigaP+o3gd0xGbQ
GJKXp+PqpM3YN25eIbGnMOEko35XG4z2eDb1+G+08Tm0MF/wVKBGuDZWfqErDqqVldFRJJyLzNLBUZB9
A4TFzAtuJi+3ttvn3BT93M8ktprbuBpRO/iypF39Xoe5wgQH4eSdG607oogBRixBy8ylUhQh9t7RArrK
4BZguMRlF/ZyEIKKVmRDle4TePWeMvU3MyiKmrFxPjj4XPf3HgVYVIFOE2EKmUqGvDwAR0RGn+Of/qJV
sDSZbPwfA7gbtbIzkGUfzOCkCCRZG+BPdBRslGxlVK7NkKB6VN9Dow/q7vbXW0RpMi67nv96ZySS0oRW
jhNbVQ60KaesPSfjLMhiKWtmakMUtlqRasRejHb5dQ5JJys/WHvKgVm3PYVHcH5/Ivk7ZKRCH2vz8W3v
st3q2qY1utJEAcL3KZuVGDCdQnjIDKhSA1dTot3TlJ3JHCO48oVtvNgoaV1OJeAB1EMLtg7UNdeXAlk1
Lj5Uf3ZAsKWsudKPYnNxK46rbLY05fcNmGpUQbssKoWoEKD3XiORZ3A/75WqPU9UZzTLK4C01dPbZXp2
2NcWZjuMXwMOZPQELEzEzTmATyrssJs7Fj982320KR6WeZ34iBFUCuKUSW7S0px5RGvo8qDoXNP6KZSf
Fz+L10zj5dzppjkQdTp+UJY1OWb3xEv52S2dU7BRTWkY/Nh5279j04ZkInJNwAygl09ey5LRK7pY4UFE
URv3Pku6EattpAFLW5dhwB9BWlioNqhpHpQsgR2PJdVulmnHe2KDWeu1IelO6KFOBpoJhrZxX83ZvtHw
fNUvTg/rhd8Tov9bfXylOMzhP6hfdtqZug4zT5/nX2w=)";

// Generated with Cloud KMS through AsymmetricSign.
constexpr absl::string_view kMlDsaSignature = R"(
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
AAAACA0QGSAn)";

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
constexpr absl::string_view kKeyNameMlDsa =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/13";

struct GcpPublicKeyParams {
  absl::string_view key_name;
  absl::string_view signature;
  int expected_calls;
};

std::vector<GcpPublicKeyParams> GcpPublicKeyParamsValidCombinations() {
  return {
      {kKeyNameEcdsa, kEcdsaSignature, 1},
      {kKeyNameEcdsa384, kEcdsa384Signature, 1},
      {kKeyNameRsaPkcs1, kRsaPkcs1Signature, 1},
      {kKeyNameRsaPss, kRsaPssSignature, 1},
      {kKeyNameRsa4096Sha256Pkcs1, kRsa4096Sha256Pkcs1Signature, 1},
      {kKeyNameRsa4096Sha512Pkcs1, kRsa4096Sha512Pkcs1Signature, 1},
      {kKeyNameRsaPss4096Sha256, kRsaPss4096Sha256Signature, 1},
      {kKeyNameRsaPss4096Sha512, kRsaPss4096Sha512Signature, 1},
      {kKeyNameMlDsa, kMlDsaSignature, 2},
  };
}

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
            response.mutable_public_key()->set_data(kEcdsaPublicKey);
          } else if (request.name() == kKeyNameEcdsa384) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_P384_SHA384);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->set_data(kEcdsa384PublicKey);
          } else if (request.name() == kKeyNameRsaPkcs1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->set_data(kRsaPublicKey);
          } else if (request.name() == kKeyNameRsa4096Sha256Pkcs1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->set_data(kRsa4096PublicKey);
          } else if (request.name() == kKeyNameRsa4096Sha512Pkcs1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->set_data(kRsa4096PublicKey);
          } else if (request.name() == kKeyNameRsaPss) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->set_data(kRsaPublicKey);
          } else if (request.name() == kKeyNameRsaPss4096Sha256) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->set_data(kRsa4096PublicKey);
          } else if (request.name() == kKeyNameRsaPss4096Sha512) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            response.mutable_public_key()->set_data(kRsa4096PublicKey);
          } else if (request.name() == kKeyNameMlDsa) {
            if (request.public_key_format() != kmsV1::PublicKey::NIST_PQC) {
              return Status(google::cloud::StatusCode::kInvalidArgument,
                            "Only NIST_PQC format is supported");
            }
            response.set_algorithm(kmsV1::CryptoKeyVersion::PQ_SIGN_ML_DSA_65);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
            std::string raw_public_key;
            absl::Base64Unescape(kMlDsaPublicKey, &raw_public_key);
            response.mutable_public_key()->set_data(raw_public_key);
          } else if (request.name() == kKeyNameEcdsaSecp256k1) {
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::EC_SIGN_SECP256K1_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::HSM);
            response.mutable_public_key()->set_data(kSecp256k1PublicKey);
          } else if (request.name() == kKeyNameErrorGetPublicKey) {
            return Status(google::cloud::StatusCode::kInternal,
                          "Internal error");
          }

          response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
              static_cast<uint32_t>(
                  absl::ComputeCrc32c(response.public_key().data())));
          if (request.name() == kKeyNameCrcPemError) {
            response.mutable_public_key()->mutable_crc32c_checksum()->set_value(
                1773);
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

class GcpPublicKeyVerifyTest
    : public testing::WithParamInterface<GcpPublicKeyParams>,
      public TestGcpKmsPublicKeyVerify {};

TEST_P(GcpPublicKeyVerifyTest, Success) {
  GcpPublicKeyParams test_params = GetParam();
  ExpectGetPublicKey(test_params.expected_calls);
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerify(test_params.key_name, kms_client_);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(test_params.signature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    GcpPublicKeyVerifyTests, GcpPublicKeyVerifyTest,
    testing::ValuesIn(GcpPublicKeyParamsValidCombinations()));

class GetSignaturePublicKeyTest
    : public testing::WithParamInterface<GcpPublicKeyParams>,
      public TestGcpKmsPublicKeyVerify {};

TEST_P(GetSignaturePublicKeyTest, Success) {
  GcpPublicKeyParams test_params = GetParam();
  ExpectGetPublicKey(test_params.expected_calls);
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>> tink_key =
      CreateSignaturePublicKey(test_params.key_name, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());

  // Verify a signature with the key.
  auto tink_keyset_handle =
      KeysetHandleBuilder()
          .AddEntry(KeysetHandleBuilder::Entry::CreateFromKey(
              std::move(tink_key.value()), crypto::tink::KeyStatus::kEnabled,
              /*is_primary=*/true))
          .Build();

  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(test_params.signature, &signature));

  EXPECT_THAT(tink_keyset_handle->Validate(), IsOk());
  auto verifier = tink_keyset_handle->GetPrimitive<PublicKeyVerify>(
      crypto::tink::ConfigSignatureV0());
  EXPECT_THAT(verifier, IsOk());
  EXPECT_THAT(verifier.value()->Verify(signature, kData), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    GetSignaturePublicKeyTests, GetSignaturePublicKeyTest,
    testing::ValuesIn(GcpPublicKeyParamsValidCombinations()));

TEST_F(TestGcpKmsPublicKeyVerify, GetSignaturePublicKeyEcdsaSecp256k1Fails) {
  ExpectGetPublicKey(1);
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>> tink_key =
      CreateSignaturePublicKey(kKeyNameEcdsaSecp256k1, kms_client_);
  EXPECT_THAT(tink_key.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                          HasSubstr("Unsupported algorithm")));
}

TEST_F(TestGcpKmsPublicKeyVerify, CallRegisterTwiceOk) {
  ASSERT_THAT(SignatureConfig::Register(), IsOk());
  ExpectGetPublicKey(1);
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>> tink_key =
      CreateSignaturePublicKey(kKeyNameEcdsa, kms_client_);
  EXPECT_THAT(tink_key.status(), IsOk());
}

/*** OFFLINE VERSION TESTS ***/

TEST_F(TestGcpKmsPublicKeyVerify, InvalidSignaturePublicKeyOfflineVerifyFails) {
  ExpectGetPublicKey(1);
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>> key =
      CreateSignaturePublicKey(kKeyNameEcdsa, kms_client_);
  EXPECT_THAT(key.status(), IsOk());

  // The signature public key is not a GcpSignaturePublicKey.
  auto kms_verifier = CreateGcpKmsPublicKeyVerifyWithNoRpcs(**key);
  EXPECT_THAT(kms_verifier.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid SignaturePublicKey")));
}

TEST(TestCreateSignaturePublicKeyWithNoRpcs, PublicKeyFromEcdsaSecp256k1Fails) {
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>>
      kms_signature_public_key = CreateSignaturePublicKeyWithNoRpcs(
          kSecp256k1PublicKey, CryptoKeyVersion::EC_SIGN_SECP256K1_SHA256,
          GetPartialKeyAccess());
  EXPECT_THAT(kms_signature_public_key.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unsupported algorithm")));
}

TEST(TestCreateSignaturePublicKeyWithNoRpcs, PublicKeyFromEcdsaSuccess) {
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>>
      kms_signature_public_key = CreateSignaturePublicKeyWithNoRpcs(
          kEcdsaPublicKey, CryptoKeyVersion::EC_SIGN_P256_SHA256,
          GetPartialKeyAccess());
  EXPECT_THAT(kms_signature_public_key.status(), IsOk());
}

TEST(TestPublicKeyVerifyWithNoRpcs, InvalidSignatureFails) {
  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>>
      kms_signature_public_key = CreateSignaturePublicKeyWithNoRpcs(
          kEcdsaPublicKey, CryptoKeyVersion::EC_SIGN_P256_SHA256,
          GetPartialKeyAccess());
  EXPECT_THAT(kms_signature_public_key.status(), IsOk());
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerifyWithNoRpcs(**kms_signature_public_key);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(kEcdsaSignature, &signature));
  signature[0] ^= 0x01;
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Invalid signature")));
}

struct OfflinePemVerificationParams {
  absl::string_view public_key;
  absl::string_view signature;
  CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm;
};

std::vector<OfflinePemVerificationParams>
GetOfflinePemVerificationValidCombinations() {
  return {
      {kEcdsaPublicKey, kEcdsaSignature, CryptoKeyVersion::EC_SIGN_P256_SHA256},
      {kEcdsa384PublicKey, kEcdsa384Signature,
       CryptoKeyVersion::EC_SIGN_P384_SHA384},
      {kRsaPublicKey, kRsaPkcs1Signature,
       CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256},
      {kRsaPublicKey, kRsaPssSignature,
       CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256},
      {kRsa4096PublicKey, kRsa4096Sha256Pkcs1Signature,
       CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256},
      {kRsa4096PublicKey, kRsa4096Sha512Pkcs1Signature,
       CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512},
      {kRsa4096PublicKey, kRsaPss4096Sha256Signature,
       CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256},
      {kRsa4096PublicKey, kRsaPss4096Sha512Signature,
       CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512},
      {kMlDsaPublicKey, kMlDsaSignature, CryptoKeyVersion::PQ_SIGN_ML_DSA_65},
  };
}

using GcpKmsPublicKeyVerifyOfflineTest =
    testing::TestWithParam<OfflinePemVerificationParams>;

TEST_P(GcpKmsPublicKeyVerifyOfflineTest, PublicKeyVerifySuccess) {
  OfflinePemVerificationParams test_params = GetParam();
  std::string raw_public_key(test_params.public_key);
  if (test_params.algorithm == CryptoKeyVersion::PQ_SIGN_ML_DSA_65) {
    EXPECT_TRUE(absl::Base64Unescape(test_params.public_key, &raw_public_key));
  }

  absl::StatusOr<std::shared_ptr<const SignaturePublicKey>>
      kms_signature_public_key = CreateSignaturePublicKeyWithNoRpcs(
          raw_public_key, test_params.algorithm, GetPartialKeyAccess());
  EXPECT_THAT(kms_signature_public_key.status(), IsOk());
  auto kms_verifier =
      CreateGcpKmsPublicKeyVerifyWithNoRpcs(**kms_signature_public_key);
  EXPECT_THAT(kms_verifier.status(), IsOk());
  std::string signature;
  ASSERT_TRUE(absl::Base64Unescape(test_params.signature, &signature));
  EXPECT_THAT((*kms_verifier)->Verify(signature, kData), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    GcpKmsPublicKeyVerifyOfflineTests, GcpKmsPublicKeyVerifyOfflineTest,
    testing::ValuesIn(GetOfflinePemVerificationValidCombinations()));

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
