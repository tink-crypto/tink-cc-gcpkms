// Copyright 2025 Google LLC
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

#include "tink/integration/gcpkms/internal/test_file_util.h"

#include <cstdlib>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace crypto {
namespace tink {
namespace internal {

using ::bazel::tools::cpp::runfiles::Runfiles;

absl::StatusOr<std::string> RunfilesPath(absl::string_view path) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest(&error));
  if (runfiles == nullptr) {
    return absl::InvalidArgumentError(
        absl::StrCat("Unable to determine runfile path: ", error));
  }

  const char* workspace_dir = getenv("TEST_WORKSPACE");
  if (workspace_dir == nullptr || workspace_dir[0] == '\0') {
    return absl::InternalError("Unable to determine workspace name.");
  }

  return runfiles->Rlocation(absl::StrCat(workspace_dir, "/", path));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
