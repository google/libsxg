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

#include <openssl/ssl.h>
#include <stdbool.h>
#include <time.h>

#include "gtest/gtest.h"
#include "libsxg.h"
#include "test_util.h"

namespace {

int64_t allocations_before_fail;

void* NFailMalloc(size_t size, const char*, int) {
  if (allocations_before_fail-- <= 0) {
    return nullptr;
  }
  return malloc(size);
}

void* NFailRealloc(void* ptr, size_t size, const char*, int) {
  if (allocations_before_fail-- <= 0) {
    return nullptr;
  }
  return realloc(ptr, size);
}

void NFailFree(void* ptr, const char*, int) { free(ptr); }

class FailAtNTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // See https://www.openssl.org/docs/man1.1.1/man3/OPENSSL_malloc.html
    // CRYPTO_set_mem_functions() should be called before any allocations.
    ASSERT_EQ(1,
              CRYPTO_set_mem_functions(NFailMalloc, NFailRealloc, NFailFree));
  }

  void SetFailAt(int64_t n) { allocations_before_fail = n; }

  void RunWithoutAllocationLimit(std::function<void()> func) {
    SetFailAt(std::numeric_limits<int64_t>::max());
    func();
  }

  void RunWithLimitedAllocations(std::function<bool()> func) {
    // Run with sufficient malloc successing count, it eliminates all RUN_ONCE
    // related concerns.
    SetFailAt(std::numeric_limits<int64_t>::max());
    ASSERT_TRUE(func());
    int64_t fail_at = 0;
    do {
      // Call function repeatedly with malloc fails at 0 ~ n times.
      SetFailAt(fail_at++);
      bool success = func();
      if (allocations_before_fail < 0) {
        EXPECT_FALSE(success);
      }
    } while (allocations_before_fail < 0);
  }
};

}  // namespace

TEST_F(FailAtNTest, GenerateSxg) {
  EVP_PKEY* priv_key = nullptr;
  X509* cert = nullptr;

  RunWithoutAllocationLimit([&]() {
    // Prepare keys.
    priv_key = sxg_test::LoadPrivateKey("testdata/priv256.key");
    ASSERT_NE(nullptr, priv_key);

    cert = sxg_test::LoadX509Cert("testdata/cert256.pem");
    ASSERT_NE(nullptr, cert);
  });

  RunWithLimitedAllocations([&]() {
    // Initialize signers.
    time_t now = 1234567890;
    sxg_signer_list_t signers = sxg_empty_signer_list();
    bool success = sxg_add_ecdsa_signer(
        "my_signer", now, now + 60 * 60 * 24,
        "https://original.example.com/resource.validity.msg", priv_key, cert,
        "https://yourcdn.example.test/cert.cbor", &signers);

    // Prepare contents.
    sxg_raw_response_t content = sxg_empty_raw_response();
    success = success &&
              sxg_header_append_string(
                  "content-type", "text/html; charset=utf-8", &content.header);

    success =
        success && sxg_write_string(
                       "<!DOCTYPE html><html><body>Hello Sxg!</body></html>\n",
                       &content.payload);

    // Encode contents.
    sxg_encoded_response_t encoded = sxg_empty_encoded_response();
    success = success && sxg_encode_response(4096, &content, &encoded);

    // Generate SXG.
    sxg_buffer_t result = sxg_empty_buffer();
    success = success && sxg_generate("https://original.example.com/index.html",
                                      &signers, &encoded, &result);

    // Release resouces.
    sxg_signer_list_release(&signers);
    sxg_raw_response_release(&content);
    sxg_encoded_response_release(&encoded);
    sxg_buffer_release(&result);

    return success;
  });

  EVP_PKEY_free(priv_key);
  X509_free(cert);
}

TEST_F(FailAtNTest, CalcIntegrity) {
  RunWithLimitedAllocations([&]() {
    sxg_raw_response_t content = sxg_empty_raw_response();
    bool success =
        sxg_header_append_string("content-type", "text/html; charset=utf-8",
                                 &content.header) &&
        sxg_write_string(
            "<!DOCTYPE html><html><body>Hello Sxg!</body></html>\n",
            &content.payload);

    sxg_encoded_response_t encoded = sxg_empty_encoded_response();
    success = success && sxg_encode_response(4096, &content, &encoded);

    sxg_buffer_t integrity = sxg_empty_buffer();
    success = success && sxg_write_header_integrity(&encoded, &integrity);

    sxg_raw_response_release(&content);
    sxg_encoded_response_release(&encoded);
    sxg_buffer_release(&integrity);
    return success;
  });
}
