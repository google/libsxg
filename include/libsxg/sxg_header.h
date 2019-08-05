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

#ifndef LIBSXG_SXG_HEADER_H_
#define LIBSXG_SXG_HEADER_H_

#include <stdbool.h>

#include "sxg_buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

// A header element.
typedef struct {
  char* key;
  sxg_buffer_t value;
} sxg_kvp_t;

// Innner HTTP headers of SXG.
typedef struct {
  sxg_kvp_t* entries;
  size_t size;
  size_t capacity;
} sxg_header_t;

// Initializes header. Never fails.
sxg_header_t sxg_empty_header();

// Releases memory entire contents of sxg_header.
void sxg_header_release(sxg_header_t* target);

// Adds new key-value pair to the header. Returns true on success.
bool sxg_header_append_buffer(const char* key, const sxg_buffer_t* value,
                              sxg_header_t* target);

// Adds new key-value pair with null-terminated string value. Returns true on
// success.
bool sxg_header_append_string(const char* key, const char* value,
                              sxg_header_t* target);

// Adds new key-value pair with integer value with string format. Returns true
// on success.
bool sxg_header_append_integer(const char* key, uint64_t num,
                               sxg_header_t* target);

// Duplicates sxg_header with deep copy. Previous content of `dst` will be
// released. Returns true on success.
bool sxg_header_copy(const sxg_header_t* src, sxg_header_t* dst);

// Appends all elements of `src` into `target`.
bool sxg_header_merge(const sxg_header_t* src, sxg_header_t* target);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_SXG_HEADER_H_
