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

#include "libsxg/internal/sxg_header.h"

#include <algorithm>
#include <cstring>

#include "libsxg/internal/sxg_buffer.h"
#include "libsxg/sxg_header.h"
#include "libsxg/sxg_header.hpp"

namespace sxg {

void Header::Append(std::string key, std::string value) {
  std::transform(key.begin(), key.end(), key.begin(), ::tolower);
  auto it = header_.find(key);
  if (it != header_.end()) {
    it->second.emplace_back(value);
  } else {
    header_.insert(std::make_pair(key, std::vector<std::string>{value}));
  }
}

void Header::Append(std::string key, uint64_t num) {
  std::transform(key.begin(), key.end(), key.begin(), ::tolower);
  auto it = header_.find(key);
  std::string value = std::to_string(num);
  if (it != header_.end()) {
    it->second.emplace_back(value);
  } else {
    header_.insert(std::make_pair(key, std::vector<std::string>{value}));
  }
}

void Header::Merge(const Header& from) {
  // Not efficient way, we should not repeat find() and use
  // std::vector::reserve to precise expantion.
  for (const auto& it : from.header_) {
    for (const auto& value : it.second) {
      Append(it.first, value);
    }
  }
}

static size_t ConcatValuesLength(const std::vector<std::string>& values) {
  size_t size = 0;
  for (const auto& value : values) {
    size += value.size();
  }
  if (values.size() > 0) {
    size += values.size() - 1;  // size of comma.
  }
  return size;
}

static std::string ConcatValues(const std::vector<std::string>& values) {
  std::string result;
  result.reserve(ConcatValuesLength(values));
  for (size_t i = 0; i < values.size(); ++i) {
    if (i > 0) {
      result.append(",");
    }
    result.append(values[i]);
  }
  return result;
}

size_t Header::GetCborSerializedSize() const {
  const size_t header_size =
      sxg_cbor_map_header_serialized_size(header_.size());
  size_t body_size = 0;
  for (const auto& it : header_) {
    const size_t key_size = it.first.size();
    body_size += sxg_cbor_bytes_header_serialized_size(key_size) + key_size;
    const size_t value_size = ConcatValuesLength(it.second);
    body_size += sxg_cbor_bytes_header_serialized_size(value_size) + value_size;
  }
  return header_size + body_size;
}

size_t SerializeString(const std::string& str, uint8_t* target) {
  const size_t header_size = sxg_cbor_bytes_header_serialized_size(str.size());
  const size_t prefix = sxg_cbor_bytes_header_prefix(str.size());
  sxg_serialize_int(prefix, 1, target);
  sxg_serialize_int(str.size(), header_size - 1, target + 1);
  memcpy(target + header_size, str.data(), str.size());
  return header_size + str.size();
}

std::string Header::SerializeInCbor() const {
  std::vector<std::string> keys;
  keys.reserve(header_.size());
  for (const auto& it : header_) {
    keys.emplace_back(it.first);
  }
  std::sort(keys.begin(), keys.end(),
            [](const std::string& a, const std::string& b) {
              if (a.size() < b.size()) {
                return true;
              } else if (a.size() > b.size()) {
                return false;
              } else {
                return std::strcmp(a.c_str(), b.c_str()) < 0;
              }
            });

  std::string serialized;
  serialized.resize(GetCborSerializedSize());

  const size_t header_byte_size =
      sxg_cbor_map_header_serialized_size(keys.size());
  const uint8_t prefix = sxg_cbor_map_header_prefix(keys.size());

  uint8_t* buffer = reinterpret_cast<uint8_t*>(&serialized[0]);
  sxg_serialize_int(prefix, 1, buffer);
  sxg_serialize_int(keys.size(), header_byte_size - 1, buffer + 1);
  buffer += header_byte_size;

  for (const auto& key : keys) {
    buffer += SerializeString(key, buffer);
    buffer += SerializeString(ConcatValues(header_.find(key)->second), buffer);
  }
  return serialized;
}

}  // namespace sxg
