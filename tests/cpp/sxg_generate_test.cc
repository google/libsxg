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

#include "libsxg/sxg_generate.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>

#include <fstream>
#include <string>

#include "../test_util.h"
#include "gtest/gtest.h"

namespace {

class GenerateTest : public ::testing::Test {
 protected:
  void SetEcdsa256() {
    const size_t now = 1234567890;
    EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/priv256.key");
    X509* pubkey = sxg_test::LoadX509Cert("testdata/cert256.pem");
    signers_.AddEcdsaSigner(
        "ecdsa256signer", now, now + 60 * 60 * 24,
        "https://original.example.com/resource.validity.msg", privkey, pubkey,
        "https://yourcdn.example.net/cert.cbor");
    EVP_PKEY_free(privkey);
    X509_free(pubkey);
  }

  void SetEcdsa384() {
    const size_t now = 1234567890;
    EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/priv384.key");
    X509* pubkey = sxg_test::LoadX509Cert("testdata/cert384.pem");
    signers_.AddEcdsaSigner(
        "ecdsa384signer", now, now + 60 * 60 * 24,
        "https://original.example.com/resource.validity.msg", privkey, pubkey,
        "https://yourcdn.example.net/cert.cbor");
    EVP_PKEY_free(privkey);
    X509_free(pubkey);
  }

  void SetEd25519() {
    const size_t now = 1234567890;
    EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/ed25519.key");
    EVP_PKEY* pubkey = sxg_test::LoadEd25519Pubkey("testdata/ed25519.pubkey");
    signers_.AddEd25519Signer(
        "ed25519signer", now, now + 60 * 60 * 24,
        "https://original.example.com/resource.validity.msg", privkey, pubkey);
    EVP_PKEY_free(privkey);
    EVP_PKEY_free(pubkey);
  }

  void SetSomeContent() {
    content_.payload = "<html><body>Hello Sxg</body></html>\n";
    content_.header.Append("content-type", "text/html; charset=utf-8");
    content_.header.Append("foo", "bar");
  }

  void DumpResult(std::string result, const std::string& filename) {
    std::ofstream of(filename.c_str(),
                     std::ios_base::out | std::ios_base::binary);
    of.write(result.data(), result.size());
    of.close();
  }

  sxg::SignerList signers_;
  sxg::RawResponse content_;
};

TEST_F(GenerateTest, SetUpAndTearDown) {
  // Do nothing.
}

TEST_F(GenerateTest, GenerateEcdsa256) {
  SetEcdsa256();
  SetSomeContent();

  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(4096, content_);
  std::string result = sxg::Generate("https://original.example.com/index.html",
                                     signers_, encoded);

  DumpResult(result, "Ecdsa256.sxg");
}

TEST_F(GenerateTest, WithEmptyHeaderAndPayload) {
  SetEcdsa256();

  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(4096, content_);
  std::string result = sxg::Generate("https://original.example.com/index.html",
                                     signers_, encoded);

  DumpResult(result, "WithEMptyHeaderAndPayload.sxg");
}

TEST_F(GenerateTest, GenerateEcdsa384) {
  SetEcdsa384();
  SetSomeContent();

  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(4096, content_);
  std::string result = sxg::Generate("https://original.example.com/index.html",
                                     signers_, encoded);

  DumpResult(result, "Ecdsa384.sxg");
}

TEST_F(GenerateTest, GenerateEd25519) {
  SetEd25519();
  SetSomeContent();

  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(4096, content_);
  std::string result = sxg::Generate("https://original.example.com/index.html",
                                     signers_, encoded);

  DumpResult(result, "Ed25519.sxg");
}

TEST_F(GenerateTest, GenerateMultiSig) {
  SetEcdsa256();
  SetEcdsa384();
  SetEd25519();
  SetSomeContent();

  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(4096, content_);
  std::string result = sxg::Generate("https://original.example.com/index.html",
                                     signers_, encoded);

  DumpResult(result, "MultiSig.sxg");
}

}  // namespace
