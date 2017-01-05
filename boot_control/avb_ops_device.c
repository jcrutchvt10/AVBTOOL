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

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cutils/properties.h>
#include <fs_mgr.h>

#include "avb_ops_device.h"

/* Open the appropriate fstab file and fallback to /fstab.device if
 * that's what's being used.
 */
static struct fstab* open_fstab(void) {
  char propbuf[PROPERTY_VALUE_MAX];
  char fstab_name[PROPERTY_VALUE_MAX + 32];
  struct fstab* fstab;

  property_get("ro.hardware", propbuf, "");
  snprintf(fstab_name, sizeof(fstab_name), "/fstab.%s", propbuf);
  fstab = fs_mgr_read_fstab(fstab_name);
  if (fstab != NULL) {
    return fstab;
  }

  fstab = fs_mgr_read_fstab("/fstab.device");
  return fstab;
}

static int open_partition(const char* name, int flags) {
  char* path;
  int fd;
  struct fstab* fstab;
  struct fstab_rec* record;

  /* We can't use fs_mgr to look up |name| because fstab doesn't list
   * every slot partition (it uses the slotselect option to mask the
   * suffix) and |slot| is expected to be of that form, e.g. boot_a.
   *
   * We can however assume that there's an entry for the /misc mount
   * point and use that to get the device file for the misc
   * partition. From there we'll assume that a by-name scheme is used
   * so we can just replace the trailing "misc" by the given |name|,
   * e.g.
   *
   *   /dev/block/platform/soc.0/7824900.sdhci/by-name/misc ->
   *   /dev/block/platform/soc.0/7824900.sdhci/by-name/boot_a
   *
   * If needed, it's possible to relax this assumption in the future
   * by trawling /sys/block looking for the appropriate sibling of
   * misc and then finding an entry in /dev matching the sysfs entry.
   */

  fstab = open_fstab();
  if (fstab == NULL) {
    return -1;
  }
  record = fs_mgr_get_entry_for_mount_point(fstab, "/misc");
  if (record == NULL) {
    fs_mgr_free_fstab(fstab);
    return -1;
  }
  if (strcmp(name, "misc") == 0) {
    path = strdup(record->blk_device);
  } else {
    size_t trimmed_len, name_len;
    const char* end_slash = strrchr(record->blk_device, '/');
    if (end_slash == NULL) {
      fs_mgr_free_fstab(fstab);
      return -1;
    }
    trimmed_len = end_slash - record->blk_device + 1;
    name_len = strlen(name);
    path = calloc(trimmed_len + name_len + 1, 1);
    strncpy(path, record->blk_device, trimmed_len);
    strncpy(path + trimmed_len, name, name_len);
  }
  fs_mgr_free_fstab(fstab);

  fd = open(path, flags);
  free(path);

  return fd;
}

static AvbIOResult read_from_partition(AvbOps* ops,
                                       const char* partition,
                                       int64_t offset,
                                       size_t num_bytes,
                                       void* buffer,
                                       size_t* out_num_read) {
  int fd;
  off_t where;
  ssize_t num_read;
  AvbIOResult ret;

  fd = open_partition(partition, O_RDONLY);
  if (fd == -1) {
    avb_errorv("Error opening \"", partition, "\" partition.\n", NULL);
    ret = AVB_IO_RESULT_ERROR_IO;
    goto out;
  }

  where = lseek(fd, offset, SEEK_SET);
  if (where == -1) {
    avb_error("Error seeking to offset.\n");
    ret = AVB_IO_RESULT_ERROR_IO;
    goto out;
  }
  if (where != offset) {
    avb_error("Error seeking to offset.\n");
    ret = AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
    goto out;
  }

  /* On Linux, we never get partial reads from block devices (except
   * for EOF).
   */
  num_read = read(fd, buffer, num_bytes);
  if (num_read == -1) {
    avb_error("Error reading data.\n");
    ret = AVB_IO_RESULT_ERROR_IO;
    goto out;
  }
  if (out_num_read != NULL) {
    *out_num_read = num_read;
  }

  ret = AVB_IO_RESULT_OK;

out:
  if (fd != -1) {
    if (close(fd) != 0) {
      avb_error("Error closing file descriptor.\n");
    }
  }
  return ret;
}

static AvbIOResult write_to_partition(AvbOps* ops,
                                      const char* partition,
                                      int64_t offset,
                                      size_t num_bytes,
                                      const void* buffer) {
  int fd;
  off_t where;
  ssize_t num_written;
  AvbIOResult ret;

  fd = open_partition(partition, O_WRONLY);
  if (fd == -1) {
    avb_errorv("Error opening \"", partition, "\" partition.\n", NULL);
    ret = AVB_IO_RESULT_ERROR_IO;
    goto out;
  }

  where = lseek(fd, offset, SEEK_SET);
  if (where == -1) {
    avb_error("Error seeking to offset.\n");
    ret = AVB_IO_RESULT_ERROR_IO;
    goto out;
  }
  if (where != offset) {
    avb_error("Error seeking to offset.\n");
    ret = AVB_IO_RESULT_ERROR_RANGE_OUTSIDE_PARTITION;
    goto out;
  }

  /* On Linux, we never get partial writes on block devices. */
  num_written = write(fd, buffer, num_bytes);
  if (num_written == -1) {
    avb_error("Error writing data.\n");
    ret = AVB_IO_RESULT_ERROR_IO;
    goto out;
  }

  ret = AVB_IO_RESULT_OK;

out:
  if (fd != -1) {
    if (close(fd) != 0) {
      avb_error("Error closing file descriptor.\n");
    }
  }
  return ret;
}

AvbABOps* avb_ops_device_new(void) {
  AvbABOps* ab_ops;

  ab_ops = calloc(1, sizeof(AvbABOps));
  if (ab_ops == NULL) {
    avb_error("Error allocating memory for AvbOps.\n");
    goto out;
  }

  /* We only need these operations since that's all what is being used
   * by the A/B routines.
   */
  ab_ops->ops.read_from_partition = read_from_partition;
  ab_ops->ops.write_to_partition = write_to_partition;
  ab_ops->read_ab_metadata = avb_ab_data_read;
  ab_ops->write_ab_metadata = avb_ab_data_write;

out:
  return ab_ops;
}

void avb_ops_device_free(AvbABOps* ab_ops) {
  free(ab_ops);
}
