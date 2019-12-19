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
#include "libsxg/internal/sxg_cbor.h"

#include <string>

#include "gtest/gtest.h"
#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/internal/sxg_cbor.h"
#include "test_util.h"

namespace {

using ::sxg_test::BufferToString;

static std::string HeaderToString(size_t length) {
  sxg_buffer_t buf = sxg_empty_buffer();
  if (!sxg_write_bytes_cbor_header(length, &buf)) {
    return "";
  }
  const std::string header = BufferToString(buf);
  sxg_buffer_release(&buf);
  return header;
}

TEST(SxgCborTest, WriteBytesCborHeader) {
  EXPECT_EQ("\x40", HeaderToString(0));
  EXPECT_EQ("\x43", HeaderToString(3));

  // 0x17 is the biggest number represented in 1 byte.
  EXPECT_EQ("\x57", HeaderToString(0x17));

  // 0x18 is the smallest number represented in 2 bytes.
  EXPECT_EQ("\x58\x18", HeaderToString(0x18));
  EXPECT_EQ("\x58\xff", HeaderToString(0xff));

  // 0x0100 is represented in 3 bytes.
  EXPECT_EQ(std::string("\x59\x01\x00", 3), HeaderToString(0x100));
  EXPECT_EQ("\x59\xd3\xd7", HeaderToString(0xd3d7));
  EXPECT_EQ("\x59\xff\xff", HeaderToString(0xffff));

  // 0x010000 is represented in 5 bytes.
  EXPECT_EQ(std::string("\x5a\x00\x01\x00\x00", 5), HeaderToString(0x10000));
  EXPECT_EQ("\x5a\x12\x34\x56\x78", HeaderToString(0x12345678));
  EXPECT_EQ("\x5a\xff\xff\xff\xff", HeaderToString(0xffffffffULL));

  // 0x0100000000 is represented in 9 bytes.
  EXPECT_EQ(std::string("\x5b\x00\x00\x00\x01\x00\x00\x00\x00", 9),
            HeaderToString(0x100000000));
  EXPECT_EQ("\x5b\xff\xff\xff\xff\xff\xff\xff\xff",
            HeaderToString(0xffffffffffffffffULL));
}

std::string GetMapHeader(size_t length) {
  sxg_buffer_t buf = sxg_empty_buffer();
  EXPECT_TRUE(sxg_write_map_cbor_header(length, &buf));
  const std::string header = BufferToString(buf);
  sxg_buffer_release(&buf);
  return header;
}

TEST(SxgCborTest, CborMapHeader) {
  EXPECT_EQ("\xa0", GetMapHeader(0));
  EXPECT_EQ("\xa3", GetMapHeader(3));

  // 0xb7 is the biggest number represented in 1 byte.
  EXPECT_EQ("\xb7", GetMapHeader(0x17));

  // 0xb8 is the smallest number represented in 2 bytes.
  EXPECT_EQ("\xb8\x18", GetMapHeader(0x18));
  EXPECT_EQ("\xb8\xff", GetMapHeader(0xff));

  // 0x0100 is represented in 3 bytes.
  EXPECT_EQ(std::string("\xb9\x01\x00", 3), GetMapHeader(0x100));
  EXPECT_EQ("\xb9\xd3\xd7", GetMapHeader(0xd3d7));
  EXPECT_EQ("\xb9\xff\xff", GetMapHeader(0xffff));

  // 0x010000 is represented in 5 bytes.
  EXPECT_EQ(std::string("\xba\x00\x01\x00\x00", 5), GetMapHeader(0x10000));
  EXPECT_EQ("\xba\x12\x34\x56\x78", GetMapHeader(0x12345678));
  EXPECT_EQ("\xba\xff\xff\xff\xff", GetMapHeader(0xffffffffULL));

  // 0x0100000000 is represented in 9 bytes.
  EXPECT_EQ(std::string("\xbb\x00\x00\x00\x01\x00\x00\x00\x00", 9),
            GetMapHeader(0x100000000));
  EXPECT_EQ("\xbb\xff\xff\xff\xff\xff\xff\xff\xff",
            GetMapHeader(0xffffffffffffffffULL));
}

TEST(SxgCborTest, WriteBytesCbor) {
  sxg_buffer_t buf = sxg_empty_buffer();
  const uint8_t bytes[4] = {'t', 'e', 's', 't'};

  EXPECT_TRUE(sxg_write_bytes_cbor(bytes, 4, &buf));
  // "\x44test" means encoded "test".
  EXPECT_EQ("\x44test", BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgCborTest, WriteUtf8Cbor) {
  sxg_buffer_t buf = sxg_empty_buffer();
  const char utf8string[] = u8"📜";

  EXPECT_TRUE(sxg_write_utf8string_cbor(utf8string, &buf));
  // "\x64\xF0\x9F\x93\x9C" means utf8 encoded "📜".
  EXPECT_EQ("\x64\xF0\x9F\x93\x9C", BufferToString(buf));

  sxg_buffer_release(&buf);
}

}  // namespace
