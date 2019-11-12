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

#include "libsxg/sxg_encoded_response.h"

#include <string>

#include "gtest/gtest.h"
#include "test_util.h"

namespace {

using ::sxg_test::BufferToString;

TEST(SxgEncodedResponse, InitializeAndReleaseEmptyRawResponse) {
  sxg_raw_response_t resp = sxg_empty_raw_response();
  sxg_raw_response_release(&resp);
}

TEST(SxgEncodedResponse, InitializeAndReleaseEmptyEncodedResponse) {
  sxg_encoded_response_t resp = sxg_empty_encoded_response();
  sxg_encoded_response_release(&resp);
}

std::string HeaderFindKey(const sxg_header_t& header, const char* key) {
  for (size_t i = 0; i < header.size; ++i) {
    if (strcasecmp(header.entries[i].key, key) == 0) {
      return BufferToString(header.entries[i].value);
    }
  }
  return "";
}

TEST(SxgEncodedResponse, EncodeMinimum) {
  // https://tools.ietf.org/html/draft-thomson-http-mice-03#section-2.2
  // If 0 octets are available, and "top-proof" is SHA-256("\0") (whose base64
  // encoding is "bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0="), then return a
  // 0-length decoded payload.
  sxg_raw_response_t resp = sxg_empty_raw_response();
  sxg_encoded_response_t output = sxg_empty_encoded_response();
  std::string expected_digest =
      "mi-sha256-03=bjQLnP+zepicpUTmu3gKLHiQHT+zNzh2hRGjBhevoB0=";

  EXPECT_TRUE(sxg_encode_response(16, &resp, &output));
  EXPECT_EQ(3u, output.header.size);
  EXPECT_EQ("200", HeaderFindKey(output.header, ":status"));
  EXPECT_EQ("mi-sha256-03", HeaderFindKey(output.header, "content-encoding"));
  EXPECT_EQ(expected_digest, HeaderFindKey(output.header, "digest"));
  EXPECT_EQ(0u, output.payload.size);

  sxg_raw_response_release(&resp);
  sxg_encoded_response_release(&output);
}

TEST(SxgEncodedResponse, IntegrityMinimum) {
  sxg_raw_response_t resp = sxg_empty_raw_response();
  sxg_encoded_response_t enc = sxg_empty_encoded_response();
  sxg_buffer_t output = sxg_empty_buffer();
  std::string expected = "sha256-4zGVTZ38P1nbTw6MnJfVF21L7qg0pJsfXjIOOfcXIgo=";

  EXPECT_TRUE(sxg_encode_response(4096, &resp, &enc));
  EXPECT_TRUE(sxg_write_header_integrity(&enc, &output));
  EXPECT_EQ(expected, BufferToString(output));

  sxg_raw_response_release(&resp);
  sxg_encoded_response_release(&enc);
  sxg_buffer_release(&output);
}

TEST(SxgEncodedResponse, SomeHeader) {
  sxg_raw_response_t resp = sxg_empty_raw_response();
  sxg_encoded_response_t enc = sxg_empty_encoded_response();
  sxg_encode_response(16, &resp, &enc);
  sxg_buffer_t output = sxg_empty_buffer();
  sxg_header_append_string("foo", "bar", &resp.header);
  std::string expected = "sha256-CUivwFQMaYG/EfLfL4l4dbde7Xp/+jIzdP6GqttQNTw=";

  EXPECT_TRUE(sxg_encode_response(4096, &resp, &enc));
  EXPECT_EQ(4u, enc.header.size);
  EXPECT_TRUE(sxg_write_header_integrity(&enc, &output));
  EXPECT_EQ(expected, BufferToString(output));

  sxg_raw_response_release(&resp);
  sxg_encoded_response_release(&enc);
  sxg_buffer_release(&output);
}

}  // namespace
