/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !defined(AVB_INSIDE_LIBAVB_H) && !defined(AVB_COMPILATION)
#error "Never include this file directly, include libavb.h instead."
#endif

#ifndef AVB_UTIL_H_
#define AVB_UTIL_H_

#include "avb_sysdeps.h"

#ifdef __cplusplus
extern "C" {
#endif

#define AVB_STRINGIFY(x) #x
#define AVB_TO_STRING(x) AVB_STRINGIFY(x)

#ifdef AVB_ENABLE_DEBUG
/* Aborts the program if |expr| is false.
 *
 * This has no effect unless AVB_ENABLE_DEBUG is defined.
 */
#define avb_assert(expr)                     \
  do {                                       \
    if (!(expr)) {                           \
      avb_fatal("assert fail: " #expr "\n"); \
    }                                        \
  } while (0)
#else
#define avb_assert(expr)
#endif

/* Aborts the program if reached.
 *
 * This has no effect unless AVB_ENABLE_DEBUG is defined.
 */
#ifdef AVB_ENABLE_DEBUG
#define avb_assert_not_reached()         \
  do {                                   \
    avb_fatal("assert_not_reached()\n"); \
  } while (0)
#else
#define avb_assert_not_reached()
#endif

/* Aborts the program if |addr| is not word-aligned.
 *
 * This has no effect unless AVB_ENABLE_DEBUG is defined.
 */
#define avb_assert_word_aligned(addr) \
  avb_assert((((uintptr_t)addr) & (AVB_WORD_ALIGNMENT_SIZE - 1)) == 0)

#ifdef AVB_ENABLE_DEBUG
/* Print functions, used for diagnostics.
 *
 * These have no effect unless AVB_ENABLE_DEBUG is defined.
 */
#define avb_debug(message)                                       \
  do {                                                           \
    avb_print(__FILE__ ":" AVB_TO_STRING(__LINE__) ": DEBUG: "); \
    avb_print(message);                                          \
  } while (0)
#define avb_debugv(message, ...)                                 \
  do {                                                           \
    avb_print(__FILE__ ":" AVB_TO_STRING(__LINE__) ": DEBUG: "); \
    avb_printv(message, ##__VA_ARGS__);                          \
  } while (0)
#else
#define avb_debug(message)
#define avb_debugv(message, ...)
#endif

/* Prints out a message. This is typically used if a runtime-error
 * occurs.
 */
#define avb_error(message)                                       \
  do {                                                           \
    avb_print(__FILE__ ":" AVB_TO_STRING(__LINE__) ": ERROR: "); \
    avb_print(message);                                          \
  } while (0)
#define avb_errorv(message, ...)                                 \
  do {                                                           \
    avb_print(__FILE__ ":" AVB_TO_STRING(__LINE__) ": ERROR: "); \
    avb_printv(message, ##__VA_ARGS__);                          \
  } while (0)

/* Prints out a message and calls avb_abort().
 */
#define avb_fatal(message)                                       \
  do {                                                           \
    avb_print(__FILE__ ":" AVB_TO_STRING(__LINE__) ": FATAL: "); \
    avb_print(message);                                          \
    avb_abort();                                                 \
  } while (0)
#define avb_fatalv(message, ...)                                 \
  do {                                                           \
    avb_print(__FILE__ ":" AVB_TO_STRING(__LINE__) ": FATAL: "); \
    avb_printv(message, ##__VA_ARGS__);                          \
    avb_abort();                                                 \
  } while (0)

/* Converts a 32-bit unsigned integer from big-endian to host byte order. */
uint32_t avb_be32toh(uint32_t in) AVB_ATTR_WARN_UNUSED_RESULT;

/* Converts a 64-bit unsigned integer from big-endian to host byte order. */
uint64_t avb_be64toh(uint64_t in) AVB_ATTR_WARN_UNUSED_RESULT;

/* Compare |n| bytes starting at |s1| with |s2| and return 0 if they
 * match, 1 if they don't.  Returns 0 if |n|==0, since no bytes
 * mismatched.
 *
 * Time taken to perform the comparison is only dependent on |n| and
 * not on the relationship of the match between |s1| and |s2|.
 *
 * Note that unlike avb_memcmp(), this only indicates inequality, not
 * whether |s1| is less than or greater than |s2|.
 */
int avb_safe_memcmp(const void* s1, const void* s2,
                    size_t n) AVB_ATTR_WARN_UNUSED_RESULT;

/* Adds |value_to_add| to |value| with overflow protection.
 *
 * Returns false if the addition overflows, true otherwise. In either
 * case, |value| is always modified.
 */
bool avb_safe_add_to(uint64_t* value,
                     uint64_t value_to_add) AVB_ATTR_WARN_UNUSED_RESULT;

/* Adds |a| and |b| with overflow protection, returning the value in
 * |out_result|.
 *
 * It's permissible to pass NULL for |out_result| if you just want to
 * check that the addition would not overflow.
 *
 * Returns false if the addition overflows, true otherwise.
 */
bool avb_safe_add(uint64_t* out_result, uint64_t a,
                  uint64_t b) AVB_ATTR_WARN_UNUSED_RESULT;

/* Checks if |num_bytes| data at |data| is a valid UTF-8
 * string. Returns true if valid UTF-8, false otherwise.
 */
bool avb_validate_utf8(const uint8_t* data,
                       size_t num_bytes) AVB_ATTR_WARN_UNUSED_RESULT;

/* Concatenates |str1| (of |str1_len| bytes) and |str2| (of |str2_len|
 * bytes) and puts the result in |buf| which holds |buf_size|
 * bytes. The result is also guaranteed to be NUL terminated. Fail if
 * there is not enough room in |buf| for the resulting string plus
 * terminating NUL byte.
 *
 * Returns true if the operation succeeds, false otherwise.
 */
bool avb_str_concat(char* buf, size_t buf_size, const char* str1,
                    size_t str1_len, const char* str2, size_t str2_len);

/* Like avb_malloc_() but prints a error using avb_error() if memory
 * allocation fails.
 */
void* avb_malloc(size_t size) AVB_ATTR_WARN_UNUSED_RESULT;

/* Like avb_malloc() but sets the memory with zeroes. */
void* avb_calloc(size_t size) AVB_ATTR_WARN_UNUSED_RESULT;

/* Duplicates a NUL-terminated string. Returns NULL on OOM. */
char* avb_strdup(const char* str) AVB_ATTR_WARN_UNUSED_RESULT;

/* Finds the first occurrence of |needle| in the string |haystack|
 * where both strings are NUL-terminated strings. The terminating NUL
 * bytes are not compared.
 *
 * Returns NULL if not found, otherwise points into |haystack| for the
 * first occurrence of |needle|.
 */
const char* avb_strstr(const char* haystack,
                       const char* needle) AVB_ATTR_WARN_UNUSED_RESULT;

/* Replaces all occurrences of |search| with |replace| in |str|.
 *
 * Returns a newly allocated string or NULL if out of memory.
 */
char* avb_replace(const char* str, const char* search,
                  const char* replace) AVB_ATTR_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* AVB_UTIL_H_ */
