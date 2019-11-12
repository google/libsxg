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

#include "libsxg/sxg_signer_list.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <string>

#include "gtest/gtest.h"
#include "test_util.h"

namespace {

TEST(SingersList, EmptyRelease) {
  sxg_signer_list_t signers = sxg_empty_signer_list();
  sxg_signer_list_release(&signers);
}

TEST(SingersList, LoadEcdsa256) {
  sxg_signer_list_t signers = sxg_empty_signer_list();
  const time_t now = time(nullptr);
  EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/priv256.key");
  X509* pubkey = sxg_test::LoadX509Cert("testdata/cert256.pem");

  EXPECT_TRUE(sxg_add_ecdsa_signer(
      "ecdsa256signer", now, now + 60 * 60 * 24,
      "https://original.example.com/resource.validity.msg", privkey, pubkey,
      "https://yourcdn.example.net/cert.cbor", &signers));
  EXPECT_EQ(1u, signers.size);

  EVP_PKEY_free(privkey);
  X509_free(pubkey);
  sxg_signer_list_release(&signers);
}

TEST(SingersList, LoadEd25519) {
  sxg_signer_list_t signers = sxg_empty_signer_list();
  const size_t now = time(nullptr);
  EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/ed25519.key");
  EVP_PKEY* pubkey = sxg_test::LoadEd25519Pubkey("testdata/ed25519.pubkey");

  EXPECT_TRUE(sxg_add_ed25519_signer(
      "ed25519signer", now, now + 60 * 60 * 24,
      "https://original.example.com/resource.validity.msg", privkey, pubkey,
      &signers));
  EXPECT_EQ(1u, signers.size);

  EVP_PKEY_free(privkey);
  EVP_PKEY_free(pubkey);
  sxg_signer_list_release(&signers);
}

}  // namespace
