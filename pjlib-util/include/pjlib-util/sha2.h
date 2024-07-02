#ifndef __PJLIB_UTIL_SHA2_H__
#define __PJLIB_UTIL_SHA2_H__

#include <pj/types.h>

PJ_BEGIN_DECL

typedef struct
{
  pj_uint32_t state[8];
  pj_uint64_t bits;
  pj_uint32_t len;
  pj_uint8_t buffer[64];
} pj_sha256_context;

void pj_sha256_init(pj_sha256_context *ctx);
void pj_sha256_update(pj_sha256_context *ctx, const pj_uint8_t *data, pj_size_t len);
void pj_sha256_final(pj_sha256_context *ctx, pj_uint8_t digest[32]);
void pj_hmac_sha256(pj_uint8_t dst[32], pj_uint8_t *key, pj_size_t keysz, pj_uint8_t *data,
                    pj_size_t datasz);

PJ_END_DECL

#endif /* __PJLIB_UTIL_SHA2_H__ */
