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

#ifndef AVB_KERNEL_CMDLINE_DESCRIPTOR_H_
#define AVB_KERNEL_CMDLINE_DESCRIPTOR_H_

#include "avb_descriptor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A descriptor containing information to be appended to the kernel
 * command-line.
 *
 * Following this struct are |kernel_cmdline_len| bytes with the
 * kernel command-line (UTF-8 encoded).
 */
typedef struct AvbKernelCmdlineDescriptor {
  AvbDescriptor parent_descriptor;
  uint32_t kernel_cmdline_length;
} AVB_ATTR_PACKED AvbKernelCmdlineDescriptor;

/* Copies |src| to |dest| and validates, byte-swapping fields in the
 * process if needed. Returns true if valid, false if invalid.
 *
 * Data following the struct is not validated nor copied.
 */
bool avb_kernel_cmdline_descriptor_validate_and_byteswap(
    const AvbKernelCmdlineDescriptor* src,
    AvbKernelCmdlineDescriptor* dest) AVB_ATTR_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* AVB_KERNEL_CMDLINE_DESCRIPTOR_H_ */
