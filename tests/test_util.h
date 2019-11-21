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

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <string>

#include "libsxg/sxg_buffer.h"

namespace sxg_test {

std::string BufferToString(const sxg_buffer_t& buf);

sxg_buffer_t StringToBuffer(const char* src);

X509* LoadX509Cert(const std::string& filepath);

EVP_PKEY* LoadPrivateKey(const std::string& filepath);

EVP_PKEY* LoadPublicKey(const std::string& filepath);

EVP_PKEY* LoadEd25519Pubkey(const std::string& filepath);

}  // namespace sxg_test
