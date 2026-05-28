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

#include "tink/integration/gcpkms/gcp_kms_util.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "google/cloud/status.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::google::cloud::StatusCode;

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

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
