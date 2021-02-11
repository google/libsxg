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

#include "libsxg/internal/sxg_sig.h"

#include <openssl/x509.h>

#include <cstdio>
#include <string>

#include "gtest/gtest.h"
#include "libsxg/internal/sxg_codec.h"
#include "libsxg/sxg_buffer.h"
#include "test_util.h"

namespace {

// Splices sig value out of buffer and into signature.
void ExtractSignature(sxg_buffer_t* buffer, sxg_buffer_t* signature) {
  static const char sigKey[] = "sig=";
  uint8_t* begin =
      (uint8_t*)strstr((char*)buffer->data, sigKey) + sizeof(sigKey);
  EXPECT_EQ('*', *(begin - 1));

  uint8_t* end = begin;
  while (*++end != '*')
    ;
  EXPECT_EQ('*', *end);

  EXPECT_TRUE(sxg_buffer_resize(end - begin, signature));
  memcpy(signature->data, begin, end - begin);

  memmove(begin, end, (buffer->data + buffer->size) - end);
  EXPECT_TRUE(sxg_buffer_resize(buffer->size - (end - begin), buffer));
}

// On failure, this leaks a EVP_ENCODE_CTX. Do not use this in production or in
// a loop in test.
void sxg_base64decode(const sxg_buffer_t* src, sxg_buffer_t* dst) {
  const size_t offset = dst->size;
  // 4-byte blocks to 3-byte, assuming none are padding chars; we'll adjust at
  // the end.
  const EVP_ENCODE_BLOCK_T estimated_out_length = 3 * (src->size / 4);
  ASSERT_TRUE(sxg_buffer_resize(offset + estimated_out_length, dst));

#ifdef OPENSSL_IS_BORINGSSL
  size_t out_length;
  ASSERT_EQ(EVP_DecodeBase64(dst->data + offset, &out_length,
                             estimated_out_length, src->data, src->size),
            1);
  ASSERT_TRUE(sxg_buffer_resize(offset + out_length, dst));
#else
  // EVP_DecodeBlock doesn't support padding chars, so we use the long form.
  EVP_ENCODE_CTX* ctx = EVP_ENCODE_CTX_new();
  EVP_DecodeInit(ctx);
  int out_length;
  ASSERT_NE(EVP_DecodeUpdate(ctx, dst->data + offset, &out_length, src->data,
                             src->size),
            -1);
  int out_length2;
  ASSERT_NE(EVP_DecodeFinal(ctx, dst->data + offset + out_length, &out_length2),
            -1);
  ASSERT_TRUE(sxg_buffer_resize(offset + out_length + out_length2, dst));
  EVP_ENCODE_CTX_free(ctx);
#endif
}

// On failure, this leaks a EVP_MD_CTX. Do not use this in production or in a
// loop in test.
void sxg_evp_verify(EVP_PKEY* private_key, const sxg_buffer_t& message,
                    const sxg_buffer_t& signature) {
  EVP_MD_CTX* const ctx = EVP_MD_CTX_new();
  const EVP_MD* digest_func = EVP_sha256();

  // EVP_DigestVerify functions return 1 on success; any other value indicates
  // failure.
  // https://www.openssl.org/docs/manmaster/man3/EVP_DigestVerifyInit.html
  ASSERT_TRUE(ctx != NULL);
  ASSERT_EQ(EVP_DigestVerifyInit(ctx, NULL, digest_func, NULL, private_key), 1);
  ASSERT_EQ(EVP_DigestVerify(ctx, signature.data, signature.size, message.data,
                             message.size),
            1);

  EVP_MD_CTX_free(ctx);
}

TEST(SxgSig, ConstructAndRelease) {
  sxg_sig_t sig = sxg_empty_sig();
  sxg_sig_release(&sig);  // This is no-op.
}

TEST(SxgSig, MakeSignature) {
  sxg_sig_t sig = sxg_empty_sig();
  X509* cert = sxg_test::LoadX509Cert("testdata/cert256.pem");
  sxg_buffer_t header = sxg_empty_buffer();
  sxg_write_string("dummy_header", &header);
  EVP_PKEY* pkey = sxg_test::LoadPrivateKey("testdata/priv256.key");
  sxg_buffer_t output = sxg_empty_buffer();
  const std::string expected(
      "testname;cert-sha256=*WrpTHrnR9I9Cj+cizXTozEZB+BnjQKkRe8kKgme4iLU=*;"
      "cert-url=\"https://cert.test/"
      "cert.cbor\";date=0;expires=0;integrity=\"digest/"
      "mi-sha256-03\";sig=**;validity-url=\"https://cert.test/validity.msg\"");

  EXPECT_TRUE(sxg_sig_set_name("testname", &sig));
  EXPECT_TRUE(sxg_sig_set_cert_sha256(cert, &sig));
  EXPECT_TRUE(sxg_sig_set_cert_url("https://cert.test/cert.cbor", &sig));
  EXPECT_TRUE(sxg_sig_set_integrity("digest/mi-sha256-03", &sig));
  EXPECT_TRUE(sxg_sig_set_validity_url("https://cert.test/validity.msg", &sig));
  EXPECT_TRUE(sxg_sig_generate_sig("https://sxg.test/", &header, pkey, &sig));
  EXPECT_TRUE(sxg_write_signature(&sig, &output));

  sxg_buffer_t signature = sxg_empty_buffer();
  ExtractSignature(&output, &signature);
  EXPECT_EQ(expected, sxg_test::BufferToString(output));

  // https://wicg.github.io/webpackage/draft-yasskin-httpbis-origin-signed-exchanges-impl.html#name-signature-validity
  sxg_buffer_t expected_message = sxg_empty_buffer();
  const uint8_t expected_message_buf[] =
      "                                "
      "                                "
      "HTTP Exchange 1 b3\0 "  // preamble
      "\x5a\xba\x53\x1e\xb9\xd1\xf4\x8f\x42\x8f\xe7\x22\xcd\x74\xe8"
      "\xcc\x46\x41\xf8\x19\xe3\x40\xa9\x11\x7b\xc9\x0a\x82\x67\xb8"
      "\x88\xb5"                                          // cert-sha256
      "\0\0\0\0\0\0\0\x1ehttps://cert.test/validity.msg"  // validity-url
      "\0\0\0\0\0\0\0\0"                                  // date
      "\0\0\0\0\0\0\0\0"                                  // expires
      "\0\0\0\0\0\0\0\x11https://sxg.test/"               // requestUrl
      "\0\0\0\0\0\0\0\x0c"
      "dummy_header";  // responseHeaders
  sxg_write_bytes(expected_message_buf,
                  sizeof(expected_message_buf) - 1 /* terminating NUL */,
                  &expected_message);

  {
    SCOPED_TRACE("signature: " + sxg_test::BufferToString(signature));
    sxg_buffer_t signature_decoded = sxg_empty_buffer();
    EXPECT_NO_FATAL_FAILURE(sxg_base64decode(&signature, &signature_decoded));
    EXPECT_NO_FATAL_FAILURE(
        sxg_evp_verify(pkey, expected_message, signature_decoded));
  }

  EVP_PKEY_free(pkey);
  X509_free(cert);
  sxg_buffer_release(&header);
  sxg_buffer_release(&output);
  sxg_sig_release(&sig);
}

}  // namespace
