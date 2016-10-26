#
# Copyright 2016, The Android Open Source Project
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use, copy,
# modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
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
    -fstack-protector-strong
avb_common_cppflags := \
    -Wnon-virtual-dtor \
    -fno-strict-aliasing
avb_common_ldflags := \
    -Wl,--gc-sections

include $(CLEAR_VARS)
LOCAL_SRC_FILES := avbtool
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_REQUIRED_MODULES := fec
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE := avbtool
include $(BUILD_PREBUILT)

# Build for the target (for e.g. fs_mgr usage).
include $(CLEAR_VARS)
LOCAL_MODULE := libavb
LOCAL_MODULE_HOST_OS := linux
LOCAL_EXPORT_C_INDLUDE_DIRS := $(LOCAL_PATH)/libavb
LOCAL_CLANG := true
LOCAL_CFLAGS := $(avb_common_cflags) -DAVB_ENABLE_DEBUG -DAVB_COMPILATION
LOCAL_LDFLAGS := $(avb_common_ldflags)
LOCAL_C_INCLUDES :=
LOCAL_SRC_FILES := \
    libavb/avb_ab_flow.c \
    libavb/avb_chain_partition_descriptor.c \
    libavb/avb_crc32.c \
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
    libavb/avb_ab_flow.c \
    libavb/avb_chain_partition_descriptor.c \
    libavb/avb_crc32.c \
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
LOCAL_REQUIRED_MODULES := simg2img img2simg
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
    test/avb_ab_flow_unittest.cc \
    test/avb_slot_verify_unittest.cc \
    test/avb_util_unittest.cc \
    test/avb_vbmeta_image_unittest.cc \
    test/avbtool_unittest.cc \
    test/fake_avb_ops.cc
LOCAL_LDLIBS_linux := -lrt
include $(BUILD_HOST_NATIVE_TEST)

include $(CLEAR_VARS)
LOCAL_MODULE := bootctrl.avb
LOCAL_MODULE_RELATIVE_PATH := hw
LOCAL_REQUIRED_MODULES := libavb
LOCAL_SRC_FILES := \
    boot_control/boot_control_avb.c \
    boot_control/avb_ops_device.c \
    libavb/avb_sysdeps_posix.c
LOCAL_CLANG := true
LOCAL_CFLAGS := $(avb_common_cflags) -DAVB_COMPILATION
LOCAL_LDFLAGS := $(avb_common_ldflags)
LOCAL_C_INCLUDES := $(LOCAL_PATH)/libavb
LOCAL_SHARED_LIBRARIES := libcutils libavb
LOCAL_STATIC_LIBRARIES := libfs_mgr
LOCAL_POST_INSTALL_CMD := \
	$(hide) mkdir -p $(TARGET_OUT_SHARED_LIBRARIES)/hw && \
	ln -sf bootctrl.avb.so $(TARGET_OUT_SHARED_LIBRARIES)/hw/bootctrl.default.so
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_SRC_FILES := libavb_host_symbols_test
LOCAL_MODULE_TAGS := debug
LOCAL_ADDITIONAL_DEPENDENCIES := libavb_host
include $(BUILD_HOST_PREBUILT)
