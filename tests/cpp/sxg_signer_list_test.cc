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

#include "libsxg/sxg_signer_list.hpp"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdio>
#include <string>

#include "../test_util.h"
#include "gtest/gtest.h"

namespace {

TEST(SingersList, Empty) { sxg::SignerList signers; }

TEST(SingersList, LoadEcdsa256) {
  sxg::SignerList signers;
  const time_t now = time(nullptr);
  EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/priv256.key");
  X509* pubkey = sxg_test::LoadX509Cert("testdata/cert256.pem");

  signers.AddEcdsaSigner("ecdsa256signer", now, now + 60 * 60 * 24,
                         "https://original.example.com/resource.validity.msg",
                         privkey, pubkey,
                         "https://yourcdn.example.net/cert.cbor");
  EXPECT_EQ(1u, signers.Size());

  EVP_PKEY_free(privkey);
  X509_free(pubkey);
}

TEST(SingersList, LoadEd25519) {
  sxg::SignerList signers;
  const size_t now = time(nullptr);
  EVP_PKEY* privkey = sxg_test::LoadPrivateKey("testdata/ed25519.key");
  EVP_PKEY* pubkey = sxg_test::LoadEd25519Pubkey("testdata/ed25519.pubkey");

  signers.AddEd25519Signer("ed25519signer", now, now + 60 * 60 * 24,
                           "https://original.example.com/resource.validity.msg",
                           privkey, pubkey);
  EXPECT_EQ(1u, signers.Size());

  EVP_PKEY_free(privkey);
  EVP_PKEY_free(pubkey);
}

}  // namespace
