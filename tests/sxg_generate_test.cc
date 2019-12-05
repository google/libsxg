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

#include "libsxg/sxg_generate.h"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fstream>
#include <string>

#include "gtest/gtest.h"
#include "test_util.h"

namespace {

class GenerateTest : public ::testing::Test {
 protected:
  void SetEcdsa256() {
    const size_t now = 1234567890;
    EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/priv256.key");
    X509* pubkey = sxg_test::LoadX509Cert("testdata/cert256.pem");
    EXPECT_TRUE(sxg_add_ecdsa_signer(
        "ecdsa256signer", now, now + 60 * 60 * 24,
        "https://original.example.com/resource.validity.msg", privkey, pubkey,
        "https://yourcdn.example.net/cert.cbor", &signers_));
    EVP_PKEY_free(privkey);
    X509_free(pubkey);
  }

  void SetEcdsa384() {
    const size_t now = 1234567890;
    EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/priv384.key");
    X509* pubkey = sxg_test::LoadX509Cert("testdata/cert384.pem");
    EXPECT_TRUE(sxg_add_ecdsa_signer(
        "ecdsa384signer", now, now + 60 * 60 * 24,
        "https://original.example.com/resource.validity.msg", privkey, pubkey,
        "https://yourcdn.example.net/cert.cbor", &signers_));
    EVP_PKEY_free(privkey);
    X509_free(pubkey);
  }

  void SetEd25519() {
    const size_t now = 1234567890;
    EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/ed25519.key");
    EVP_PKEY* pubkey = sxg_test::LoadEd25519Pubkey("testdata/ed25519.pubkey");
    EXPECT_TRUE(sxg_add_ed25519_signer(
        "ed25519signer", now, now + 60 * 60 * 24,
        "https://original.example.com/resource.validity.msg", privkey, pubkey,
        &signers_));
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
  }

  void SetSomeContent() {
    sxg_write_string("<html><body>Hello Sxg</body></html>\n",
                     &content_.payload);
    sxg_header_append_string("content-type", "text/html; charset=utf-8",
                             &content_.header);
    sxg_header_append_string("foo", "bar", &content_.header);
  }

  void SetUp() override {
    signers_ = sxg_empty_signer_list();
    content_ = sxg_empty_raw_response();
    encoded_ = sxg_empty_encoded_response();
    result_ = sxg_empty_buffer();
  }

  void TearDown() override {
    sxg_signer_list_release(&signers_);
    sxg_raw_response_release(&content_);
    sxg_encoded_response_release(&encoded_);
    sxg_buffer_release(&result_);
  }

  void DumpResult(const std::string& filename) {
    std::ofstream of(filename.c_str(),
                     std::ios_base::out | std::ios_base::binary);
    of.write((const char*)result_.data, result_.size);
    of.close();
  }

  sxg_signer_list_t signers_;
  sxg_raw_response_t content_;
  sxg_encoded_response_t encoded_;
  sxg_buffer_t result_;
};

TEST_F(GenerateTest, SetUpAndTearDown) {
  // Do nothing.
}

TEST_F(GenerateTest, GenerateEcdsa256) {
  SetEcdsa256();
  SetSomeContent();
  sxg_encode_response(4096, &content_, &encoded_);

  EXPECT_TRUE(sxg_generate("https://original.example.com/index.html", &signers_,
                           &encoded_, &result_));

  DumpResult("Ecdsa256.sxg");
}

TEST_F(GenerateTest, WithEmptyHeaderAndPayload) {
  SetEcdsa256();
  sxg_encode_response(4096, &content_, &encoded_);

  EXPECT_TRUE(sxg_generate("https://original.example.com/index.html", &signers_,
                           &encoded_, &result_));

  DumpResult("WithEMptyHeaderAndPayload.sxg");
}

TEST_F(GenerateTest, GenerateEcdsa384) {
  SetEcdsa384();
  SetSomeContent();
  sxg_encode_response(4096, &content_, &encoded_);

  EXPECT_TRUE(sxg_generate("https://original.example.com/index.html", &signers_,
                           &encoded_, &result_));

  DumpResult("Ecdsa384.sxg");
}

TEST_F(GenerateTest, GenerateEd25519) {
  SetEd25519();
  SetSomeContent();
  sxg_encode_response(4096, &content_, &encoded_);

  EXPECT_TRUE(sxg_generate("https://original.example.com/index.html", &signers_,
                           &encoded_, &result_));

  DumpResult("Ed25519.sxg");
}

TEST_F(GenerateTest, GenerateMultiSig) {
  SetEcdsa256();
  SetEcdsa384();
  SetEd25519();
  SetSomeContent();
  sxg_encode_response(4096, &content_, &encoded_);

  EXPECT_TRUE(sxg_generate("https://original.example.com/index.html", &signers_,
                           &encoded_, &result_));

  DumpResult("MultiSig.sxg");
}

}  // namespace
