// Copyright 2025 Google LLC
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

#ifndef TINK_INTEGRATION_GCPKMS_INTERNAL_TEST_FILE_UTIL_H_
#define TINK_INTEGRATION_GCPKMS_INTERNAL_TEST_FILE_UTIL_H_

#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace internal {

// Returns the path of `path` in the runfiles tree, where `path` is relative to
// the root of this repository, e.g. "testdata/gcp/credential.json".
absl::StatusOr<std::string> RunfilesPath(absl::string_view path);

// Returns the path of `path` in the runfiles tree, where `path` is relative to
// the root of the runfiles tree and therefore starts with the name of the
// repository that provides the file, e.g. "google_root_pem/file/downloaded".
// Use this for files that come from an external repository; files in this
// repository are not reachable this way, use RunfilesPath() for those.
absl::StatusOr<std::string> ExternalRunfilesPath(absl::string_view path);

absl::StatusOr<std::string> ReadFile(absl::string_view filename);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_GCPKMS_INTERNAL_TEST_FILE_UTIL_H_
