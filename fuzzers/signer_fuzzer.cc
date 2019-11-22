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

#include <assert.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <time.h>

#include <cstdint>

#include "libsxg.h"

namespace {

sxg_signer_list_t MakeSignerList() {
  char passwd[] = "";
  FILE* keyfile = fopen("testdata/priv256.key", "r");
  assert(keyfile != nullptr);

  EVP_PKEY* priv_key = PEM_read_PrivateKey(keyfile, nullptr, nullptr, nullptr);
  fclose(keyfile);

  FILE* certfile = fopen("testdata/cert256.pem", "r");
  assert(certfile != nullptr);
  X509* cert = PEM_read_X509(certfile, 0, 0, passwd);
  fclose(certfile);

  const time_t now = 1234567890;
  sxg_signer_list_t signers = sxg_empty_signer_list();
  bool success = sxg_add_ecdsa_signer(
      "my_signer", now, now + 60 * 60 * 24,
      "https://original.example.com/resource.validity.msg", priv_key, cert,
      "https://yourcdn.example.test/cert.cbor", &signers);
  assert(success);
  return signers;
}

bool MakeSxg(std::uint8_t const* data, std::size_t size) {
  static const sxg_signer_list_t signers = MakeSignerList();
  sxg_raw_response_t content = sxg_empty_raw_response();
  sxg_encoded_response_t encoded = sxg_empty_encoded_response();
  sxg_buffer_t result = sxg_empty_buffer();
  bool success = sxg_write_bytes(data, size, &content.payload);
  success = success && sxg_encode_response(4096, &content, &encoded);

  success = success && sxg_generate("https://original.example.com/index.html",
                                    &signers, &encoded, &result);
  sxg_raw_response_release(&content);
  sxg_encoded_response_release(&encoded);
  sxg_buffer_release(&result);
  return success;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(std::uint8_t const* data,
                                      std::size_t size) {
  if (!MakeSxg(data, size)) {
    fprintf(stderr, "Failed to generate sxg.\n");
    abort();
  }
  return 0;
}
