/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <iostream>

#include <endian.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <openssl/sha.h>

#include "fake_avb_ops.h"

namespace avb {

AvbIOResult FakeAvbOps::read_from_partition(const char* partition,
                                            int64_t offset,
                                            size_t num_bytes,
                                            void* buffer,
                                            size_t* out_num_read) {
  base::FilePath path =
      partition_dir_.Append(std::string(partition)).AddExtension("img");

  if (offset < 0) {
    int64_t file_size;
    if (!base::GetFileSize(path, &file_size)) {
      fprintf(
          stderr, "Error getting size of file '%s'\n", path.value().c_str());
      return AVB_IO_RESULT_ERROR_IO;
    }
    offset = file_size - (-offset);
  }

  int fd = open(path.value().c_str(), O_RDONLY);
  if (fd < 0) {
    fprintf(stderr,
            "Error opening file '%s': %s\n",
            path.value().c_str(),
            strerror(errno));
    if (errno == ENOENT) {
      return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    } else {
      return AVB_IO_RESULT_ERROR_IO;
    }
  }
  if (lseek(fd, offset, SEEK_SET) != offset) {
    fprintf(stderr,
            "Error seeking to pos %zd in file %s: %s\n",
            offset,
            path.value().c_str(),
            strerror(errno));
    close(fd);
    return AVB_IO_RESULT_ERROR_IO;
  }
  ssize_t num_read = read(fd, buffer, num_bytes);
  if (num_read < 0) {
    fprintf(stderr,
            "Error reading %zd bytes from pos %" PRId64 " in file %s: %s\n",
            num_bytes,
            offset,
            path.value().c_str(),
            strerror(errno));
    close(fd);
    return AVB_IO_RESULT_ERROR_IO;
  }
  close(fd);

  if (out_num_read != NULL) {
    *out_num_read = num_read;
  }

  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::write_to_partition(const char* partition,
                                           int64_t offset,
                                           size_t num_bytes,
                                           const void* buffer) {
  base::FilePath path =
      partition_dir_.Append(std::string(partition)).AddExtension("img");

  if (offset < 0) {
    int64_t file_size;
    if (!base::GetFileSize(path, &file_size)) {
      fprintf(
          stderr, "Error getting size of file '%s'\n", path.value().c_str());
      return AVB_IO_RESULT_ERROR_IO;
    }
    offset = file_size - (-offset);
  }

  int fd = open(path.value().c_str(), O_WRONLY);
  if (fd < 0) {
    fprintf(stderr,
            "Error opening file '%s': %s\n",
            path.value().c_str(),
            strerror(errno));
    if (errno == ENOENT) {
      return AVB_IO_RESULT_ERROR_NO_SUCH_PARTITION;
    } else {
      return AVB_IO_RESULT_ERROR_IO;
    }
  }
  if (lseek(fd, offset, SEEK_SET) != offset) {
    fprintf(stderr,
            "Error seeking to pos %zd in file %s: %s\n",
            offset,
            path.value().c_str(),
            strerror(errno));
    close(fd);
    return AVB_IO_RESULT_ERROR_IO;
  }
  ssize_t num_written = write(fd, buffer, num_bytes);
  if (num_written < 0) {
    fprintf(stderr,
            "Error writing %zd bytes at pos %" PRId64 " in file %s: %s\n",
            num_bytes,
            offset,
            path.value().c_str(),
            strerror(errno));
    close(fd);
    return AVB_IO_RESULT_ERROR_IO;
  }
  close(fd);

  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::validate_vbmeta_public_key(
    AvbOps* ops,
    const uint8_t* public_key_data,
    size_t public_key_length,
    const uint8_t* public_key_metadata,
    size_t public_key_metadata_length,
    bool* out_key_is_trusted) {
  if (out_key_is_trusted != NULL) {
    bool pk_matches = (public_key_length == expected_public_key_.size() &&
                       (memcmp(expected_public_key_.c_str(),
                               public_key_data,
                               public_key_length) == 0));
    bool pkmd_matches =
        (public_key_metadata_length == expected_public_key_metadata_.size() &&
         (memcmp(expected_public_key_metadata_.c_str(),
                 public_key_metadata,
                 public_key_metadata_length) == 0));
    *out_key_is_trusted = pk_matches && pkmd_matches;
  }
  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::read_rollback_index(AvbOps* ops,
                                            size_t rollback_index_location,
                                            uint64_t* out_rollback_index) {
  if (stored_rollback_indexes_.count(rollback_index_location) == 0) {
    fprintf(stderr,
            "No rollback index for location %zd (has %zd locations).\n",
            rollback_index_location,
            stored_rollback_indexes_.size());
    return AVB_IO_RESULT_ERROR_IO;
  }
  *out_rollback_index = stored_rollback_indexes_[rollback_index_location];
  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::write_rollback_index(AvbOps* ops,
                                             size_t rollback_index_location,
                                             uint64_t rollback_index) {
  if (stored_rollback_indexes_.count(rollback_index_location) == 0) {
    fprintf(stderr,
            "No rollback index for location %zd (has %zd locations).\n",
            rollback_index_location,
            stored_rollback_indexes_.size());
    return AVB_IO_RESULT_ERROR_IO;
  }
  stored_rollback_indexes_[rollback_index_location] = rollback_index;
  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::read_is_device_unlocked(AvbOps* ops,
                                                bool* out_is_device_unlocked) {
  *out_is_device_unlocked = stored_is_device_unlocked_ ? 1 : 0;
  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::get_unique_guid_for_partition(AvbOps* ops,
                                                      const char* partition,
                                                      char* guid_buf,
                                                      size_t guid_buf_size) {
  // This is faking it a bit but makes testing easy. It works
  // because avb_slot_verify.c doesn't check that the returned GUID
  // is wellformed.
  snprintf(guid_buf, guid_buf_size, "1234-fake-guid-for:%s", partition);
  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::read_permanent_attributes(
    AvbAtxPermanentAttributes* attributes) {
  *attributes = permanent_attributes_;
  return AVB_IO_RESULT_OK;
}

AvbIOResult FakeAvbOps::read_permanent_attributes_hash(
    uint8_t hash[AVB_SHA256_DIGEST_SIZE]) {
  if (permanent_attributes_hash_.empty()) {
    SHA256(reinterpret_cast<const unsigned char*>(&permanent_attributes_),
           sizeof(AvbAtxPermanentAttributes),
           hash);
    return AVB_IO_RESULT_OK;
  }
  memset(hash, 0, AVB_SHA256_DIGEST_SIZE);
  permanent_attributes_hash_.copy(reinterpret_cast<char*>(hash),
                                  AVB_SHA256_DIGEST_SIZE);
  return AVB_IO_RESULT_OK;
}

static AvbIOResult my_ops_read_from_partition(AvbOps* ops,
                                              const char* partition,
                                              int64_t offset,
                                              size_t num_bytes,
                                              void* buffer,
                                              size_t* out_num_read) {
  return FakeAvbOps::GetInstanceFromAvbOps(ops)
      ->delegate()
      ->read_from_partition(partition, offset, num_bytes, buffer, out_num_read);
}

static AvbIOResult my_ops_write_to_partition(AvbOps* ops,
                                             const char* partition,
                                             int64_t offset,
                                             size_t num_bytes,
                                             const void* buffer) {
  return FakeAvbOps::GetInstanceFromAvbOps(ops)->delegate()->write_to_partition(
      partition, offset, num_bytes, buffer);
}

static AvbIOResult my_ops_validate_vbmeta_public_key(
    AvbOps* ops,
    const uint8_t* public_key_data,
    size_t public_key_length,
    const uint8_t* public_key_metadata,
    size_t public_key_metadata_length,
    bool* out_key_is_trusted) {
  return FakeAvbOps::GetInstanceFromAvbOps(ops)
      ->delegate()
      ->validate_vbmeta_public_key(ops,
                                   public_key_data,
                                   public_key_length,
                                   public_key_metadata,
                                   public_key_metadata_length,
                                   out_key_is_trusted);
}

static AvbIOResult my_ops_read_rollback_index(AvbOps* ops,
                                              size_t rollback_index_location,
                                              uint64_t* out_rollback_index) {
  return FakeAvbOps::GetInstanceFromAvbOps(ops)
      ->delegate()
      ->read_rollback_index(ops, rollback_index_location, out_rollback_index);
}

static AvbIOResult my_ops_write_rollback_index(AvbOps* ops,
                                               size_t rollback_index_location,
                                               uint64_t rollback_index) {
  return FakeAvbOps::GetInstanceFromAvbOps(ops)
      ->delegate()
      ->write_rollback_index(ops, rollback_index_location, rollback_index);
}

static AvbIOResult my_ops_read_is_device_unlocked(
    AvbOps* ops, bool* out_is_device_unlocked) {
  return FakeAvbOps::GetInstanceFromAvbOps(ops)
      ->delegate()
      ->read_is_device_unlocked(ops, out_is_device_unlocked);
}

static AvbIOResult my_ops_get_unique_guid_for_partition(AvbOps* ops,
                                                        const char* partition,
                                                        char* guid_buf,
                                                        size_t guid_buf_size) {
  return FakeAvbOps::GetInstanceFromAvbOps(ops)
      ->delegate()
      ->get_unique_guid_for_partition(ops, partition, guid_buf, guid_buf_size);
}

static AvbIOResult my_ops_read_permanent_attributes(
    AvbAtxOps* atx_ops, AvbAtxPermanentAttributes* attributes) {
  return FakeAvbOps::GetInstanceFromAvbOps(atx_ops->ops)
      ->delegate()
      ->read_permanent_attributes(attributes);
}

static AvbIOResult my_ops_read_permanent_attributes_hash(
    AvbAtxOps* atx_ops, uint8_t hash[AVB_SHA256_DIGEST_SIZE]) {
  return FakeAvbOps::GetInstanceFromAvbOps(atx_ops->ops)
      ->delegate()
      ->read_permanent_attributes_hash(hash);
}

FakeAvbOps::FakeAvbOps() {
  avb_ops_.ab_ops = &avb_ab_ops_;
  avb_ops_.atx_ops = &avb_atx_ops_;
  avb_ops_.user_data = this;
  avb_ops_.read_from_partition = my_ops_read_from_partition;
  avb_ops_.write_to_partition = my_ops_write_to_partition;
  avb_ops_.validate_vbmeta_public_key = my_ops_validate_vbmeta_public_key;
  avb_ops_.read_rollback_index = my_ops_read_rollback_index;
  avb_ops_.write_rollback_index = my_ops_write_rollback_index;
  avb_ops_.read_is_device_unlocked = my_ops_read_is_device_unlocked;
  avb_ops_.get_unique_guid_for_partition = my_ops_get_unique_guid_for_partition;

  // Just use the built-in A/B metadata read/write routines.
  avb_ab_ops_.ops = &avb_ops_;
  avb_ab_ops_.read_ab_metadata = avb_ab_data_read;
  avb_ab_ops_.write_ab_metadata = avb_ab_data_write;

  avb_atx_ops_.ops = &avb_ops_;
  avb_atx_ops_.read_permanent_attributes = my_ops_read_permanent_attributes;
  avb_atx_ops_.read_permanent_attributes_hash =
      my_ops_read_permanent_attributes_hash;

  delegate_ = this;
}

FakeAvbOps::~FakeAvbOps() {}

}  // namespace avb
