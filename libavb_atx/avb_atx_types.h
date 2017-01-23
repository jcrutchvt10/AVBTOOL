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

#if !defined(AVB_INSIDE_LIBAVB_ATX_H) && !defined(AVB_COMPILATION)
#error \
    "Never include this file directly, include libavb_atx/libavb_atx.h instead."
#endif

#ifndef AVB_ATX_TYPES_H_
#define AVB_ATX_TYPES_H_

#include <libavb/libavb.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Size in bytes of an Android Things product ID. */
#define AVB_ATX_PRODUCT_ID_SIZE 16

/* Size in bytes of a serialized public key with a 2048-bit modulus. */
#define AVB_ATX_PUBLIC_KEY_SIZE_2048 (sizeof(AvbRSAPublicKeyHeader) + 512)

/* Size in bytes of a serialized public key with a 4096-bit modulus. */
#define AVB_ATX_PUBLIC_KEY_SIZE_4096 (sizeof(AvbRSAPublicKeyHeader) + 1024)

/* Data structure of Android Things permanent attributes. */
typedef struct AvbAtxPermanentAttributes {
  uint32_t version;
  uint8_t product_root_public_key[AVB_ATX_PUBLIC_KEY_SIZE_4096];
  uint8_t product_id[AVB_ATX_PRODUCT_ID_SIZE];
} AVB_ATTR_PACKED AvbAtxPermanentAttributes;

/* Data structure of signed fields in an Android Things certificate. */
typedef struct AvbAtxCertificateSignedData {
  uint32_t version;
  uint8_t public_key[AVB_ATX_PUBLIC_KEY_SIZE_2048];
  uint8_t subject[AVB_SHA256_DIGEST_SIZE];
  uint8_t usage[AVB_SHA256_DIGEST_SIZE];
  uint64_t key_version;
} AVB_ATTR_PACKED AvbAtxCertificateSignedData;

/* Data structure of a certificate signed by a 4096-bit key. */
typedef struct AvbAtxCertificate4096 {
  AvbAtxCertificateSignedData signed_data;
  uint8_t signature[AVB_RSA4096_NUM_BYTES];
} AVB_ATTR_PACKED AvbAtxCertificate4096;

/* Data structure of a certificate signed by a 2048-bit key. */
typedef struct AvbAtxCertificate2048 {
  AvbAtxCertificateSignedData signed_data;
  uint8_t signature[AVB_RSA2048_NUM_BYTES];
} AVB_ATTR_PACKED AvbAtxCertificate2048;

/* Data structure of Android Things public key metadata in vbmeta. */
typedef struct AvbAtxPublicKeyMetadata {
  uint32_t version;
  AvbAtxCertificate4096 product_intermediate_key_certificate;
  AvbAtxCertificate2048 product_signing_key_certificate;
  uint64_t google_signing_key_version;
} AVB_ATTR_PACKED AvbAtxPublicKeyMetadata;

#ifdef __cplusplus
}
#endif

#endif /* AVB_ATX_TYPES_H_ */
