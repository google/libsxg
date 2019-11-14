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

#include "libsxg/internal/sxg_codec.h"

#include <openssl/pem.h>

#include <string>

#include "gtest/gtest.h"
#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/sxg_buffer.h"
#include "test_util.h"

namespace {

using ::sxg_test::BufferToString;
using ::sxg_test::StringToBuffer;

TEST(SxgCodecTest, Sha256) {
  sxg_buffer_t in = StringToBuffer("foo");
  sxg_buffer_t out = sxg_empty_buffer();
  static const std::string expected(
      "\x2c\x26\xb4\x6b\x68\xff\xc6\x8f\xf9\x9b\x45\x3c\x1d\x30\x41\x34\x13\x42"
      "\x2d\x70\x64\x83\xbf\xa0\xf9\x8a\x5e\x88\x62\x66\xe7\xae");

  EXPECT_TRUE(sxg_calc_sha256(&in, &out));
  EXPECT_EQ(expected, BufferToString(out));

  sxg_buffer_release(&in);
  sxg_buffer_release(&out);
}

TEST(SxgCodecTest, Sha384) {
  sxg_buffer_t in = StringToBuffer("foo");
  sxg_buffer_t out = sxg_empty_buffer();
  static const std::string expected(
      "\x98\xc1\x1f\xfd\xfd\xd5\x40\x67\x6b\x1a\x13\x7c\xb1\xa2\x2b\x2a\x70\x35"
      "\x0c\x9a\x44\x17\x1d\x6b\x11\x80\xc6\xbe\x5c\xbb\x2e\xe3\xf7\x9d\x53\x2c"
      "\x8a\x1d\xd9\xef\x2e\x8e\x08\xe7\x52\xa3\xba\xbb");

  EXPECT_TRUE(sxg_calc_sha384(&in, &out));
  EXPECT_EQ(expected, BufferToString(out));

  sxg_buffer_release(&in);
  sxg_buffer_release(&out);
}

TEST(SxgCodecTest, Base64) {
  sxg_buffer_t input = StringToBuffer("hello");
  sxg_buffer_t base64 = sxg_empty_buffer();
  sxg_base64encode(&input, &base64);

  EXPECT_EQ("aGVsbG8=", BufferToString(base64));

  sxg_buffer_release(&base64);
  sxg_buffer_release(&input);
}

TEST(SxgCodecTest, Base64BreakLine) {
  sxg_buffer_t input = StringToBuffer("\n");
  sxg_buffer_t base64 = sxg_empty_buffer();
  sxg_base64encode(&input, &base64);

  EXPECT_EQ("Cg==", BufferToString(base64));

  sxg_buffer_release(&base64);
  sxg_buffer_release(&input);
}

TEST(SxgCodecTest, SHA256Base64) {
  // Example from
  // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-4.1
  sxg_buffer_t input =
      StringToBuffer("When I grow up, I want to be a watermelon");
  sxg_buffer_t digest = sxg_empty_buffer();
  sxg_buffer_t base64_digest = sxg_empty_buffer();
  sxg_write_int(0, 1, &input);
  std::string expected("dcRDgR2GM35DluAV13PzgnG6+pvQwPywfFvAu1UeFrs=");

  EXPECT_TRUE(sxg_calc_sha256(&input, &digest));
  EXPECT_TRUE(sxg_base64encode(&digest, &base64_digest));
  EXPECT_EQ(expected, BufferToString(base64_digest));

  sxg_buffer_release(&digest);
  sxg_buffer_release(&input);
  sxg_buffer_release(&base64_digest);
}

TEST(SxgCodecTest, mi_sha_zero_length) {
  // Example from
  // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-2.2
  sxg_buffer_t input = sxg_empty_buffer();
  sxg_buffer_t encoded = sxg_empty_buffer();
  uint8_t digest[SHA256_DIGEST_LENGTH];
  sxg_buffer_t base64 = sxg_empty_buffer();
  const std::string expected("bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=");

  EXPECT_TRUE(sxg_encode_mi_sha256(&input, 256, &encoded, digest));
  EXPECT_EQ(0u, encoded.size);  // Must be 0-length.
  EXPECT_TRUE(sxg_base64encode_bytes(digest, SHA256_DIGEST_LENGTH, &base64));
  EXPECT_EQ(expected, BufferToString(base64));

  sxg_buffer_release(&base64);
  sxg_buffer_release(&encoded);
  sxg_buffer_release(&input);
}

TEST(SxgCodecTest, MiceOneChunk) {
  // Example from
  // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-4.1
  sxg_buffer_t input =
      StringToBuffer("When I grow up, I want to be a watermelon");
  sxg_buffer_t encoded = sxg_empty_buffer();
  sxg_buffer_t base64 = sxg_empty_buffer();
  uint8_t digest[SHA256_DIGEST_LENGTH];
  const std::string expected_digest(
      "dcRDgR2GM35DluAV13PzgnG6+pvQwPywfFvAu1UeFrs=");
  const std::string expected_payload(
      "\x00\x00\x00\x00\x00\x00\x00\xff"  // RecordSize
      "When I grow up, I want to be a watermelon",
      49);

  EXPECT_TRUE(sxg_encode_mi_sha256(&input, 255, &encoded, digest));
  EXPECT_TRUE(sxg_base64encode_bytes(digest, SHA256_DIGEST_LENGTH, &base64));
  EXPECT_EQ(expected_digest, BufferToString(base64));
  EXPECT_EQ(expected_payload, BufferToString(encoded));

  sxg_buffer_release(&base64);
  sxg_buffer_release(&encoded);
  sxg_buffer_release(&input);
}

TEST(SxgCodecTest, MiceMultiChunks) {
  // Example from
  // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-4.2
  const char origin[] = "When I grow up, I want to be a watermelon";
  sxg_buffer_t input = StringToBuffer(origin);
  sxg_buffer_t encoded = sxg_empty_buffer();
  sxg_buffer_t base64 = sxg_empty_buffer();
  uint8_t digest[SHA256_DIGEST_LENGTH];
  const std::string expected_digest(
      "IVa9shfs0nyKEhHqtB3WVNANJ2Njm5KjQLjRtnbkYJ4=");
  const std::string expected_payload(
      "\x00\x00\x00\x00\x00\x00\x00\x10"  // RecordSize
      "When I grow up, "
      "\x38\x49\x5b\xa6\x52\x65\x3c\xaf\x91\xbf\xa2\x4d\x2b\xaa\x79\xff"
      "\x9d\x79\x21\xaa\x0f\xa1\x9a\x3e\xd9\xe9\x56\x2f\xb3\x90\xeb\x40"
      "I want to be a w"
      "\x88\xf3\x29\x9a\x01\x31\x1c\xfa\xdb\x11\x7d\xff\x46\xfc\x0f\xe1"
      "\xdd\x7a\x7d\x69\x4a\xe2\x5f\xbe\xa7\xbe\x4f\x52\xef\xca\xc8\xdd"
      "atermelon",
      113);

  EXPECT_TRUE(sxg_encode_mi_sha256(&input, 16, &encoded, digest));
  EXPECT_TRUE(sxg_base64encode_bytes(digest, SHA256_DIGEST_LENGTH, &base64));
  EXPECT_EQ(expected_digest, BufferToString(base64));
  EXPECT_EQ(expected_payload, BufferToString(encoded));

  sxg_buffer_release(&base64);
  sxg_buffer_release(&encoded);
  sxg_buffer_release(&input);
}

TEST(SxgCodecTest, EvpSign) {
  EVP_PKEY* private_key = sxg_test::LoadPrivateKey("testdata/priv256.key");
  EVP_PKEY* public_key = sxg_test::LoadPublicKey("testdata/cert256.pem");
  sxg_buffer_t input = StringToBuffer("aaaa");
  sxg_buffer_t output = sxg_empty_buffer();

  EXPECT_TRUE(sxg_evp_sign(private_key, &input, &output));

  EVP_MD_CTX* const mdctx = EVP_MD_CTX_new();
  ASSERT_NE(nullptr, mdctx);
  EXPECT_EQ(1,
            EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, public_key));
  EXPECT_EQ(1, EVP_DigestVerifyUpdate(mdctx, input.data, input.size));
  EXPECT_EQ(1, EVP_DigestVerifyFinal(mdctx, output.data, output.size));

  EVP_PKEY_free(private_key);
  EVP_PKEY_free(public_key);
  sxg_buffer_release(&input);
  sxg_buffer_release(&output);
  EVP_MD_CTX_free(mdctx);
}

}  // namespace
