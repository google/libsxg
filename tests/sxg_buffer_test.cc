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
#include "libsxg/sxg_buffer.h"

#include <string>

#include "gtest/gtest.h"
#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/internal/sxg_cbor.h"
#include "test_util.h"

namespace {

using ::sxg_test::BufferToString;

TEST(SxgBufferTest, InitializeEmpty) {
  sxg_buffer_t buf = sxg_empty_buffer();

  EXPECT_EQ(0u, buf.size);
  EXPECT_EQ(NULL, buf.data);

  sxg_buffer_release(&buf);  // This is a no-op.
}

TEST(SxgBufferTest, Resize) {
  sxg_buffer_t buf = sxg_empty_buffer();

  EXPECT_TRUE(sxg_buffer_resize(10, &buf));
  EXPECT_EQ(10u, buf.size);
  // Ensure accessing to data does not cause any violation.
  for (int i = 0; i < 10; ++i) {
    buf.data[i] = 'a';
  }
  EXPECT_EQ("aaaaaaaaaa", BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, AllocateLargeMemory) {
  sxg_buffer_t buf = sxg_empty_buffer();

  EXPECT_TRUE(sxg_buffer_resize(8000u, &buf));
  EXPECT_EQ(8000u, buf.size);
  EXPECT_LT(8000u, buf.capacity);

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, MultipleResizesNotLeakingMemory) {
  sxg_buffer_t buf = sxg_empty_buffer();

  EXPECT_TRUE(sxg_buffer_resize(10, &buf));
  // 8000 and 16000 is large enough to cause expansion.
  // We ensure that expansion does not leak memory.
  EXPECT_TRUE(sxg_buffer_resize(8000, &buf));
  EXPECT_TRUE(sxg_buffer_resize(16000, &buf));
  EXPECT_TRUE(sxg_buffer_resize(0, &buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, WriteString) {
  sxg_buffer_t buf = sxg_empty_buffer();

  EXPECT_TRUE(sxg_write_string("123", &buf));
  EXPECT_TRUE(sxg_write_string("456", &buf));
  EXPECT_EQ("123456", BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, WriteUtf8String) {
  sxg_buffer_t buf = sxg_empty_buffer();
  const char str[] = u8"こんにちは";

  EXPECT_TRUE(sxg_write_string(str, &buf));
  EXPECT_EQ(str, BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, WriteByte) {
  sxg_buffer_t buf = sxg_empty_buffer();

  EXPECT_TRUE(sxg_write_byte('a', &buf));
  EXPECT_EQ("a", BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, WriteBytes) {
  sxg_buffer_t buf = sxg_empty_buffer();
  const char str[] = "123";
  sxg_write_string(str, &buf);
  const uint8_t bytes[3] = {'4', '5', '6'};

  EXPECT_TRUE(sxg_write_bytes(bytes, 3, &buf));
  EXPECT_EQ("123456", BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, MemoryExpansion) {
  sxg_buffer_t buf = sxg_empty_buffer();

  for (int i = 0; i < 1025; ++i) {  // 1025 will cause memory expansion.
    EXPECT_TRUE(sxg_write_byte('a', &buf));
  }
  EXPECT_EQ(std::string(1025, 'a'), BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, WriteBuffer) {
  sxg_buffer_t buf1 = sxg_empty_buffer();
  sxg_write_string("123", &buf1);
  sxg_buffer_t buf2 = sxg_empty_buffer();
  sxg_write_string("456", &buf2);

  EXPECT_TRUE(sxg_write_buffer(&buf2, &buf1));
  EXPECT_EQ("123456", BufferToString(buf1));
  EXPECT_EQ("456", BufferToString(buf2));  // buf2 should be untouched.

  sxg_buffer_release(&buf1);
  sxg_buffer_release(&buf2);
}

static std::string IntToString(size_t value, int length) {
  sxg_buffer_t buf = sxg_empty_buffer();
  if (!sxg_write_int(value, length, &buf)) {
    return "";
  }
  const std::string str = BufferToString(buf);
  sxg_buffer_release(&buf);
  return str;
}

TEST(SxgBufferTest, WriteBigEndianInt) {
  EXPECT_EQ(std::string("\x00", 1), IntToString(0, 1));

  EXPECT_EQ(std::string("\x00\x00\x10", 3), IntToString(16, 3));

  EXPECT_EQ("\xff\xff", IntToString(0xffff, 2));

  EXPECT_EQ(std::string("\x00\x00\x00\x2a", 4), IntToString(42, 4));
  EXPECT_EQ("\xff\xff\xff\xff", IntToString(0xffffffffULL, 4));

  EXPECT_EQ("\xff\xff\xff\xff\xff\xff\xff\xff",
            IntToString(0xffffffffffffffffULL, 8));
}

static std::string HeaderToString(size_t length) {
  sxg_buffer_t buf = sxg_empty_buffer();
  if (!sxg_write_bytes_cbor_header(length, &buf)) {
    return "";
  }
  const std::string header = BufferToString(buf);
  sxg_buffer_release(&buf);
  return header;
}

TEST(SxgBufferTest, WriteCborHeader) {
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

TEST(SxgBufferTest, WriteStringCbor) {
  sxg_buffer_t buf = sxg_empty_buffer();
  const uint8_t bytes[4] = {'t', 'e', 's', 't'};

  EXPECT_TRUE(sxg_write_bytes_cbor(bytes, 4, &buf));
  // "\x44test" means encoded "test".
  EXPECT_EQ("\x44test", BufferToString(buf));

  sxg_buffer_release(&buf);
}

TEST(SxgBufferTest, BufferCopy) {
  sxg_buffer_t buf1 = sxg_empty_buffer();
  sxg_write_string("hello", &buf1);
  sxg_buffer_t buf2 = sxg_empty_buffer();

  EXPECT_TRUE(sxg_buffer_copy(&buf1, &buf2));
  sxg_write_string(" world.", &buf1);
  EXPECT_EQ("hello world.", BufferToString(buf1));
  EXPECT_EQ("hello", BufferToString(buf2));  // buf2 has been deeply copied.

  sxg_buffer_release(&buf1);
  sxg_buffer_release(&buf2);
}

}  // namespace
