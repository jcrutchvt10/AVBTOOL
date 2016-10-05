#
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

LOCAL_PATH := $(my-dir)

avb_common_cflags := \
    -D_FILE_OFFSET_BITS=64 \
    -D_POSIX_C_SOURCE=199309L \
    -Wa,--noexecstack \
    -Werror \
    -Wall \
    -Wextra \
    -Wformat=2 \
    -Wno-psabi \
    -Wno-unused-parameter \
    -ffunction-sections \
    -fstack-protector-strong \
    -fvisibility=hidden
avb_common_cppflags := \
    -Wnon-virtual-dtor \
    -fno-strict-aliasing
avb_common_ldflags := \
    -Wl,--gc-sections

include $(CLEAR_VARS)
LOCAL_SRC_FILES := avbtool
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE := avbtool
include $(BUILD_PREBUILT)

# Build for the target (for e.g. fs_mgr usage).
include $(CLEAR_VARS)
LOCAL_MODULE := libavb
LOCAL_MODULE_HOST_OS := linux
LOCAL_EXPORT_C_INDLUDE_DIRS := $(LOCAL_PATH)/libavb
LOCAL_CLANG := true
LOCAL_CFLAGS := $(avb_common_cflags) -fno-stack-protector -DAVB_ENABLE_DEBUG -DAVB_COMPILATION
LOCAL_LDFLAGS := $(avb_common_ldflags)
LOCAL_C_INCLUDES :=
LOCAL_SRC_FILES := \
    libavb/avb_chain_partition_descriptor.c \
    libavb/avb_crypto.c \
    libavb/avb_descriptor.c \
    libavb/avb_footer.c \
    libavb/avb_hash_descriptor.c \
    libavb/avb_hashtree_descriptor.c \
    libavb/avb_kernel_cmdline_descriptor.c \
    libavb/avb_property_descriptor.c \
    libavb/avb_rsa.c \
    libavb/avb_sha256.c \
    libavb/avb_sha512.c \
    libavb/avb_slot_verify.c \
    libavb/avb_sysdeps_posix.c \
    libavb/avb_util.c \
    libavb/avb_vbmeta_image.c
include $(BUILD_SHARED_LIBRARY)

# Build for the host (for unit tests).
include $(CLEAR_VARS)
LOCAL_MODULE := libavb_host
LOCAL_MODULE_HOST_OS := linux
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_CLANG := true
LOCAL_CFLAGS := $(avb_common_cflags) -fno-stack-protector -DAVB_ENABLE_DEBUG -DAVB_COMPILATION
LOCAL_LDFLAGS := $(avb_common_ldflags)
LOCAL_C_INCLUDES :=
LOCAL_SRC_FILES := \
    libavb/avb_chain_partition_descriptor.c \
    libavb/avb_crypto.c \
    libavb/avb_descriptor.c \
    libavb/avb_footer.c \
    libavb/avb_hash_descriptor.c \
    libavb/avb_hashtree_descriptor.c \
    libavb/avb_kernel_cmdline_descriptor.c \
    libavb/avb_property_descriptor.c \
    libavb/avb_rsa.c \
    libavb/avb_sha256.c \
    libavb/avb_sha512.c \
    libavb/avb_slot_verify.c \
    libavb/avb_util.c \
    libavb/avb_vbmeta_image.c
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libavb_host_sysdeps
LOCAL_MODULE_HOST_OS := linux
LOCAL_MODULE_CLASS := STATIC_LIBRARIES
LOCAL_CLANG := true
LOCAL_CFLAGS := $(avb_common_cflags) -DAVB_ENABLE_DEBUG -DAVB_COMPILATION
LOCAL_LDFLAGS := $(avb_common_ldflags)
LOCAL_C_INCLUDES :=
LOCAL_SRC_FILES := \
    libavb/avb_sysdeps_posix.c
include $(BUILD_HOST_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := libavb_host_unittest
LOCAL_MODULE_HOST_OS := linux
LOCAL_CPP_EXTENSION := .cc
LOCAL_CLANG := true
LOCAL_CFLAGS := $(avb_common_cflags) -DAVB_ENABLE_DEBUG -DAVB_COMPILATION
LOCAL_CPPFLAGS := $(avb_common_cppflags)
LOCAL_LDFLAGS := $(avb_common_ldflags)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libavb external/gtest/include
LOCAL_STATIC_LIBRARIES := \
    libavb_host \
    libavb_host_sysdeps \
    libgmock_host \
    libgtest_host
LOCAL_SHARED_LIBRARIES := \
    libchrome
LOCAL_SRC_FILES := \
    test/avb_slot_verify_unittest.cc \
    test/avb_util_unittest.cc \
    test/avb_vbmeta_image_unittest.cc \
    test/avbtool_unittest.cc
LOCAL_LDLIBS_linux := -lrt
include $(BUILD_HOST_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := libavb_host_symbols_test
LOCAL_MODULE_TAGS := debug
LOCAL_ADDITIONAL_DEPENDENCIES := libavb_host
include $(BUILD_HOST_PREBUILT)
