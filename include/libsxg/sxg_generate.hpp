// Copyright 2019 Google Inc.
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

#ifndef LIBSXG_SXG_GENERATE_HPP_
#define LIBSXG_SXG_GENERATE_HPP_

#include <stdbool.h>

#include "sxg_encoded_response.hpp"
#include "sxg_signer_list.hpp"

namespace sxg {

// Return SXG payload.
std::string Generate(const std::string& fallback_url, const SignerList& signers,
                     const EncodedResponse& resp);

}  // namespace sxg

#endif  // LIBSXG_SXG_GENERATE_HPP_
