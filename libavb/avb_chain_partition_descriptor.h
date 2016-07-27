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

#ifndef AVB_CHAIN_PARTITION_DESCRIPTOR_H_
#define AVB_CHAIN_PARTITION_DESCRIPTOR_H_

#include "avb_descriptor.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A descriptor containing a pointer to signed integrity data stored
 * on another partition. The descriptor contains the partition name in
 * question (without the A/B suffix), the public key used to sign the
 * integrity data, and rollback index slot to use for rollback
 * protection.
 *
 * Following this struct are |partition_name_len| bytes of the
 * partition name (UTF-8 encoded) and |public_key_len| bytes of the
 * public key.
 */
typedef struct AvbChainPartitionDescriptor {
  AvbDescriptor parent_descriptor;
  uint32_t rollback_index_slot;
  uint32_t partition_name_len;
  uint32_t public_key_len;
} AVB_ATTR_PACKED AvbChainPartitionDescriptor;

/* Copies |src| to |dest| and validates, byte-swapping fields in the
 * process if needed. Returns true if valid, false if invalid.
 *
 * Data following the struct is not validated nor copied.
 */
bool avb_chain_partition_descriptor_validate_and_byteswap(
    const AvbChainPartitionDescriptor* src,
    AvbChainPartitionDescriptor* dest) AVB_ATTR_WARN_UNUSED_RESULT;

#ifdef __cplusplus
}
#endif

#endif /* AVB_CHAIN_PARTITION_DESCRIPTOR_H_ */
