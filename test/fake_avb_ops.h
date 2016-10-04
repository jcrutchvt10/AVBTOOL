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

#ifndef FAKE_AVB_OPS_H_
#define FAKE_AVB_OPS_H_

#include <base/files/file_util.h>
#include <string>
#include <vector>

#include "libavb.h"

struct FakeAvbOpsC;
typedef struct FakeAvbOpsC FakeAvbOpsC;

class FakeAvbOps {
 public:
  FakeAvbOps();
  ~FakeAvbOps();

  AvbOps* avb_ops() { return (AvbOps*)avb_ops_; }

  void set_partition_dir(const base::FilePath& partition_dir) {
    partition_dir_ = partition_dir;
  }

  void set_expected_public_key(const std::string& expected_public_key) {
    expected_public_key_ = expected_public_key;
  }

  void set_stored_rollback_indexes(
      const std::vector<uint64_t>& stored_rollback_indexes) {
    stored_rollback_indexes_ = stored_rollback_indexes;
  }

  std::vector<uint64_t> get_stored_rollback_indexes() {
    return stored_rollback_indexes_;
  }

  void set_stored_is_device_unlocked(bool stored_is_device_unlocked) {
    stored_is_device_unlocked_ = stored_is_device_unlocked;
  }

  AvbIOResult read_from_partition(const char* partition, int64_t offset,
                                  size_t num_bytes, void* buffer,
                                  size_t* out_num_read);

  AvbIOResult write_to_partition(const char* partition, int64_t offset,
                                 size_t num_bytes, const void* buffer);

  AvbIOResult validate_vbmeta_public_key(AvbOps* ops,
                                         const uint8_t* public_key_data,
                                         size_t public_key_length,
                                         bool* out_key_is_trusted);

  AvbIOResult read_rollback_index(AvbOps* ops, size_t rollback_index_slot,
                                  uint64_t* out_rollback_index);

  AvbIOResult write_rollback_index(AvbOps* ops, size_t rollback_index_slot,
                                   uint64_t rollback_index);

  AvbIOResult read_is_device_unlocked(AvbOps* ops,
                                      bool* out_is_device_unlocked);

  AvbIOResult get_unique_guid_for_partition(AvbOps* ops, const char* partition,
                                            char* guid_buf,
                                            size_t guid_buf_size);

 private:
  FakeAvbOpsC* avb_ops_;

  base::FilePath partition_dir_;

  std::string expected_public_key_;

  std::vector<uint64_t> stored_rollback_indexes_;

  bool stored_is_device_unlocked_;
};

#endif /* FAKE_AVB_OPS_H_ */
