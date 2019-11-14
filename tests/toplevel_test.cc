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

#include <stdbool.h>
#include <time.h>

#include "gtest/gtest.h"
#include "libsxg.h"
#include "test_util.h"

// Almost similar to README.md test.
TEST(LibSXG, TopLevel) {
  // Load keys.
  EVP_PKEY* priv_key = sxg_test::LoadPrivateKey("testdata/priv256.key");
  X509* cert = sxg_test::LoadX509Cert("testdata/cert256.pem");

  // Initialize signers.
  time_t now = time(nullptr);
  sxg_signer_list_t signers = sxg_empty_signer_list();
  ASSERT_TRUE(sxg_add_ecdsa_signer(
      "my_signer", now, now + 60 * 60 * 24,
      "https://original.example.com/resource.validity.msg", priv_key, cert,
      "https://yourcdn.example.test/cert.cbor", &signers))
      << "Failed to append signer.";

  // Prepare contents.
  sxg_raw_response_t content = sxg_empty_raw_response();
  ASSERT_TRUE(sxg_header_append_string(
      "content-type", "text/html; charset=utf-8", &content.header))
      << "Failed to append content-type header.";

  ASSERT_TRUE(
      sxg_write_string("<!DOCTYPE html><html><body>Hello Sxg!</body></html>\n",
                       &content.payload))
      << "Failed to set payload.";

  // Encode contents.
  sxg_encoded_response_t encoded = sxg_empty_encoded_response();
  ASSERT_TRUE(sxg_encode_response(4096, &content, &encoded))
      << "Failed to encode content.";

  // Generate SXG.
  sxg_buffer_t result = sxg_empty_buffer();
  ASSERT_TRUE(sxg_generate("https://original.example.com/index.html", &signers,
                           &encoded, &result))
      << "Failed to generate SXG.";

  // Save SXG as a file.
  FILE* fp = fopen("hello.sxg", "w");
  ASSERT_NE(nullptr, fp);
  size_t wrote = fwrite(result.data, result.size, 1, fp);
  ASSERT_EQ(1u, wrote);
  fclose(fp);

  // Release resouces.
  EVP_PKEY_free(priv_key);
  X509_free(cert);
  sxg_signer_list_release(&signers);
  sxg_raw_response_release(&content);
  sxg_encoded_response_release(&encoded);
  sxg_buffer_release(&result);
}
