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

#ifndef AVB_SYSDEPS_H_
#define AVB_SYSDEPS_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Change these includes to match your platform to bring in the
 * equivalent types available in a normal C runtime. At least things
 * like uint8_t, uint64_t, and bool (with |false|, |true| keywords)
 * must be present.
 */
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* If you don't have gcc or clang, these attribute macros may need to
 * be adjusted.
 */
#define AVB_ATTR_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#define AVB_ATTR_PACKED __attribute__((packed))
#define AVB_ATTR_NO_RETURN __attribute__((noreturn))
#define AVB_ATTR_SENTINEL __attribute__((__sentinel__));

/* Size in bytes used for word-alignment.
 *
 * Change this to match your architecture - must be a power of two.
 */
#define AVB_WORD_ALIGNMENT_SIZE 8

/* Compare |n| bytes in |src1| and |src2|.
 *
 * Returns an integer less than, equal to, or greater than zero if the
 * first |n| bytes of |src1| is found, respectively, to be less than,
 * to match, or be greater than the first |n| bytes of |src2|. */
int avb_memcmp(const void* src1, const void* src2,
               size_t n) AVB_ATTR_WARN_UNUSED_RESULT;

/* Compare two strings.
 *
 * Return an integer less than, equal to, or greater than zero if |s1|
 * is found, respectively, to be less than, to match, or be greater
 * than |s2|.
 */
int avb_strcmp(const char* s1, const char* s2);

/* Copy |n| bytes from |src| to |dest|. */
void* avb_memcpy(void* dest, const void* src, size_t n);

/* Set |n| bytes starting at |s| to |c|.  Returns |dest|. */
void* avb_memset(void* dest, const int c, size_t n);

/* Prints out a message. The string passed must be a NUL-terminated
 * UTF-8 string.
 */
void avb_print(const char* message);

/* Prints out a vector of strings. Each argument must point to a
 * NUL-terminated UTF-8 string and NULL should be the last argument.
 */
void avb_printv(const char* message, ...) AVB_ATTR_SENTINEL;

/* Aborts the program or reboots the device. */
void avb_abort(void) AVB_ATTR_NO_RETURN;

/* Allocates |size| bytes. Returns NULL if no memory is available,
 * otherwise a pointer to the allocated memory.
 *
 * The memory is not initialized.
 *
 * The pointer returned is guaranteed to be word-aligned.
 *
 * The memory should be freed with avb_free() when you are done with it.
 */
void* avb_malloc_(size_t size) AVB_ATTR_WARN_UNUSED_RESULT;

/* Frees memory previously allocated with avb_malloc(). */
void avb_free(void* ptr);

/* Returns the lenght of |str|, excluding the terminating NUL-byte. */
size_t avb_strlen(const char* str) AVB_ATTR_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* AVB_SYSDEPS_H_ */
