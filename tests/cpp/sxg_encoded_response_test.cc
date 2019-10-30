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

#include "libsxg/sxg_encoded_response.hpp"

#include <string>

#include "gtest/gtest.h"
#include "libsxg/sxg_raw_response.hpp"

namespace {

TEST(SxgEncodedResponse, InitializeAndReleaseEmptyRawResponse) {
  sxg::RawResponse raw;
}

TEST(SxgEncodedResponse, InitializeAndReleaseEmptyEncodedResponse) {
  sxg::EncodedResponse encoded;
}

TEST(SxgEncodedResponse, EncodeMinimum) {
  // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-2.2
  // If 0 octets are available, and "top-proof" is SHA-256("\0") (whose base64
  // encoding is "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0="), then return a
  // 0-length decoded payload.
  sxg::RawResponse raw;
  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(16, raw);
  std::string expected_digest =
      "mi-sha256-03=bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=";

  EXPECT_EQ(3u, encoded.HeaderSize());
  EXPECT_EQ(1u, encoded.GetHeader().Get(":status").size());
  EXPECT_EQ("200", encoded.GetHeader().Get(":status")[0]);
  EXPECT_EQ(1u, encoded.GetHeader().Get("content-encoding").size());
  EXPECT_EQ("mi-sha256-03", encoded.GetHeader().Get("content-encoding")[0]);
  EXPECT_EQ(1u, encoded.GetHeader().Get("digest").size());
  EXPECT_EQ(expected_digest, encoded.GetHeader().Get("digest")[0]);
  EXPECT_EQ(0u, encoded.GetPayload().size());
}

TEST(SxgEncodedResponse, IntegrityMinimum) {
  sxg::RawResponse raw;
  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(4096, raw);
  std::string expected_digest =
      "sha256-4zGVTZ38P1nbTw6MnJfVF21L7qg0pJsfXjIOOfcXIgo=";

  EXPECT_EQ(expected_digest, encoded.GetHeaderIntegrity());
}

TEST(SxgEncodedResponse, SomeHeaderIntegrity) {
  sxg::RawResponse raw;
  raw.header.Append("foo", "bar");
  sxg::EncodedResponse encoded = sxg::EncodedResponse::Encode(4096, raw);
  std::string expected_digest =
      "sha256-CUivwFQMaYG/EfLfL4l4dbde7Xp/+jIzdP6GqttQNTw=";

  EXPECT_EQ(4u, encoded.HeaderSize());
  EXPECT_EQ(expected_digest, encoded.GetHeaderIntegrity());
}

}  // namespace
