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

#ifndef LIBAVB_H_
#define LIBAVB_H_

/* The AVB_INSIDE_LIBAVB_H preprocessor symbol is used to enforce
 * library users to include only this file. All public interfaces, and
 * only public interfaces, must be included here.
 */

#define AVB_INSIDE_LIBAVB_H
#include "avb_chain_partition_descriptor.h"
#include "avb_crypto.h"
#include "avb_descriptor.h"
#include "avb_footer.h"
#include "avb_hash_descriptor.h"
#include "avb_hashtree_descriptor.h"
#include "avb_kernel_cmdline_descriptor.h"
#include "avb_ops.h"
#include "avb_property_descriptor.h"
#include "avb_slot_verify.h"
#include "avb_sysdeps.h"
#include "avb_util.h"
#include "avb_vbmeta_image.h"
#undef AVB_INSIDE_LIBAVB_H

#endif /* LIBAVB_H_ */
