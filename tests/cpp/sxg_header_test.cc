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

#include "libsxg/sxg_header.hpp"

#include "gtest/gtest.h"

namespace {

TEST(HeaderTest, ConstructDestruct) { sxg::Header header; }

TEST(HeaderTest, AppendString) {
  sxg::Header header;
  header.Append("foo", "bar");
  EXPECT_EQ(1u, header.Size());
}

TEST(HeaderTest, AppendNumber) {
  sxg::Header header;
  header.Append("foo", 1);
  EXPECT_EQ(1u, header.Size());
}

TEST(HeaderTest, Merge) {
  sxg::Header header1;
  sxg::Header header2;
  header1.Append("foo", "bar");
  header2.Append("baz", 1);
  header1.Merge(header2);
  EXPECT_EQ(2u, header1.Size());
  EXPECT_EQ(1u, header2.Size());
}

TEST(HeaderTest, WriteInteger) {
  sxg::Header header;
  header.Append("num", 12345);
  EXPECT_EQ(1u, header.Size());
  EXPECT_EQ(std::vector<std::string>({std::string("12345")}),
            header.Get("num"));
}

TEST(HeaderTest, WriteBigInteger) {
  sxg::Header header;

  header.Append("num", 0xffffffffffffffff);
  EXPECT_EQ(1u, header.Size());
  EXPECT_EQ(std::vector<std::string>{std::string("18446744073709551615")},
            header.Get("num"));
}

TEST(HeaderTest, Copy) {
  sxg::Header header1;
  sxg::Header header2;
  header1.Append("foo", "bar");

  header2 = header1;
  EXPECT_EQ(header1, header2);
}

TEST(HeaderTest, SerializeInCbor) {
  sxg::Header header;
  header.Append("foo", "bar");

  std::string expected(
      "\xa1"
      "CfooCbar");

  EXPECT_EQ(expected, header.SerializeInCbor());
}

TEST(HeaderTest, SerializeCborIsCanonical) {
  sxg::Header header;
  header.Append("looong", "value");
  header.Append("short", "value");
  std::string expected(
      "\xA2"
      "EshortEvalueFlooongEvalue");  // "short" must come to the beginning.

  EXPECT_EQ(expected, header.SerializeInCbor());
}

TEST(HeaderTest, CborCanonicalLexicographic) {
  sxg::Header header;
  header.Append("BbB", "v1");
  header.Append("aAa", "v2");
  std::string expected(
      "\xa2"
      "CaaaBv2CbbbBv1");  // "aaa" must come to the beginning.

  EXPECT_EQ(expected, header.SerializeInCbor());
}

TEST(HeaderTest, DuplicatedKeyMustBeConcatenated) {
  sxg::Header header;
  header.Append("bbB", "v1");
  header.Append("aaA", "v2");
  header.Append("Aaa", "v3");
  header.Append("BbB", "v4");
  std::string expected(
      "\xA2"
      "CaaaEv2,v3CbbbEv1,v4");

  EXPECT_EQ(expected, header.SerializeInCbor());
}

}  // namespace
