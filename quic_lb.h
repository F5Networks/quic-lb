/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
#ifndef _QUIC_LB_H_
#define _QUIC_LB_H_

#ifdef NOBIGIP
#include "quic_lb_types.h"
#else
#include <local/sys/types.h>
#endif

#define QUIC_LB_MAX_CID_LEN 20

/* QUIC-LB context functions */
/*
 * Initialize the QUIC-LB context. One version for load balancers, one for
 * servers.
 *
 * There is one context for each config rotation codepoint. The calling
 * application must map the resulting contexts to config rotation bits.
 *
 * If the algorithm is Plaintext CID (QUIC_LB_PCID), the key argument is
 * ignored. If the algorithm is *not* Stream Cipher CID (QUIC_LB_SCID), the
 * nonce_len field is ignored.
 *
 * Returns NULL on a number of errors, including invalid parameters.
 */
void *quic_lb_lb_ctx_init(BOOL encode_len, size_t sidl, UINT8 *key,
        size_t nonce_len);
/*
 * Include the config rotation bits, so the server doesn't have to manually
 * add them. The server includes the number of bytes it wants to use for
 * other * purposes, and the function will compute the result CID length.
 */
void *quic_lb_server_ctx_init(UINT8 cr, BOOL encode_len, size_t sidl,
        UINT8 *key, size_t nonce_len, UINT8 *sid);
/* Free the context */
void quic_lb_lb_ctx_free(void *ctx);
void quic_lb_server_ctx_free(void *ctx);

/*
 * Encrypt functions, to be called by the server. The "server use" field can
 * contain bits that encode opaque information for the server. In this API,
 * the first octet is *always* random or length-encoding, and never uses the
 * server_use argument.
 */
void quic_lb_encrypt_cid(void *ctx, void *cid);

/*
 * Decrypt function to be used by the load balancer. Returns the length of
 * the server ID. If 0, disregard the server ID in 'sid' and revert to 5-
 * tuple * routing. The cid_len field is only filled if self-encoding; it's
 * not modified otherwise.
 */
int quic_lb_decrypt_cid(void *ctx, void *cid, void *sid, size_t *cid_len);
#endif /* _QUIC_LB_H */
