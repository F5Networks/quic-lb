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

#define QUIC_LB_TOKEN_LEN 16
#define QUIC_LB_MAX_CID_LEN 20
/* Maximum Server ID Lengths */
#define QUIC_LB_PCID_SIDL_MAX 19
#define QUIC_LB_SCID_SIDL_MAX 11
#define QUIC_LB_BCID_SIDL_MAX 11

void quic_lb_encrypt_cid(void *cid, void *config, size_t cid_len,
        void *server_use);
/*
 * This wrapper calles quic_lb_encrypt_cid and generates random bits for
 * the server use octets.
 */
void quic_lb_encrypt_cid_random(void *cid, void *config, size_t cid_len);
err_t quic_lb_decrypt_cid(void *cid, void *config, size_t *cid_len,
        void *result);
/* Temporary functions */
void *quic_lb_load_pcid_config(UINT8 cr, BOOL encode_len, UINT8 sidl,
        UINT8 *sid);
void *quic_lb_load_scid_config(UINT8 cr, BOOL encode_len, UINT8 *key,
        UINT8 cidl, UINT8 nonce_len, UINT8 *sid);
void *quic_lb_load_bcid_config(UINT8 cr, BOOL encode_len, UINT8 *key,
        UINT8 sidl, UINT8 zp_len, UINT8 *sid, BOOL encrypt);
void quic_lb_free_config(void *config);

#endif /* _QUIC_LB_H */
