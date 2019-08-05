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

#ifndef LIBSXG_SXG_BUFFER_H_
#define LIBSXG_SXG_BUFFER_H_

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if CHAR_BIT != 8
#error "libsxg assumes CHAR_BIT to be 8."
#endif

// A general buffer of variable size.
//
// A new sxg_buffer_t variable should be initialized with sxg_empty_buffer().
// The memory space is not initially allocated. It is allocated on the first
// resize or write operation and expanded automatically as needed.
//
// The caller is responsible to release the buffer with sxg_buffer_release()
// after the use.
typedef struct {
  // A memory fragment allocated for this buffer.
  uint8_t* data;

  // Size of buffer actually used.
  size_t size;

  // Size of buffer already allocated.
  // Should not be touched from outside of this library.
  size_t capacity;
} sxg_buffer_t;

// Creates buffer with zero length. It never fails.
sxg_buffer_t sxg_empty_buffer();

// Releases memory of the buffer.
void sxg_buffer_release(sxg_buffer_t* target);

// Resizes a buffer with specified length, contents are not initialized.
// Returns true on success.
bool sxg_buffer_resize(size_t size, sxg_buffer_t* target);

// Appends string to the buffer. `string` must be null terminated.
// Returns true on success.
bool sxg_write_string(const char* string, sxg_buffer_t* target);

// Appends one byte to the buffer. Returns true on success.
bool sxg_write_byte(uint8_t byte, sxg_buffer_t* target);

// Appends the specified bytes to the buffer. Returns true on success.
bool sxg_write_bytes(const uint8_t* bytes, size_t size, sxg_buffer_t* target);

// Appends the content of `follower` to the buffer. Returns true on success.
bool sxg_write_buffer(const sxg_buffer_t* follower, sxg_buffer_t* target);

// Copies the content of the buffer to another buffer. `dst` will be expanded as
// needed and overwritten with the copied content. Returns true on success.
bool sxg_buffer_copy(const sxg_buffer_t* src, sxg_buffer_t* dst);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // LIBSXG_SXG_BUFFER_H_
