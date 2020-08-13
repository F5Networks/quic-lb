/*
 * Copyright (c) 2020 F5 Networks Inc.
 * This source code is subject to the terms of the Apache License,
 * version 2.0 (https://www.apache.org/licenses/LICENSE-2.0)
 */
#ifdef NOBIGIP
#include <openssl/evp.h>
#include "quic_lb.h"
#else
#include <openssl/evp.h>
#include <local/sys/cpu.h>
#include <local/sys/debug.h>
#include <local/sys/def.h>
#include <local/sys/err.h>
#include <local/sys/lib.h>
#include <local/sys/rnd.h>
#include <local/sys/umem.h>
#endif

#define QUIC_LB_TUPLE_ROUTE 0xc0
#define QUIC_LB_USABLE_BYTES (QUIC_LB_MAX_CID_LEN - 1)

enum quic_lb_alg {
    QUIC_LB_PCID,
    QUIC_LB_SCID,
    QUIC_LB_BCID,
};

struct quic_lb_generic_config {
    UINT8  cr : 2;
    UINT8  encode_length : 1;
    enum quic_lb_alg alg : 5;
};

struct quic_lb_scid_config {
    UINT8            cr : 2;
    UINT8  encode_length : 1;
    enum quic_lb_alg alg : 5;
    UINT8            nonce_len;
    UINT8            sidl;
    UINT8            sid[QUIC_LB_SCID_SIDL_MAX];
    UINT128          nonce_ctr;
    EVP_CIPHER_CTX  *ctx;
};

struct quic_lb_bcid_config {
    UINT8            cr : 2;
    UINT8  encode_length : 1;
    enum quic_lb_alg alg : 5;
    UINT8            zp_len;
    UINT8            sidl;
    UINT8            sid[QUIC_LB_BCID_SIDL_MAX];
    UINT8            key[16];
    EVP_CIPHER_CTX  *ctx;
};

static inline err_t
quic_lb_encrypt_apply_nonce(struct quic_lb_scid_config *cfg, UINT8 *nonce,
        UINT8 nonce_len, UINT8 *target, UINT8 target_len)
{
    UINT8 pt[16];
    UINT8 ct[16];
    int ct_len, i;

    memset(pt, 0, sizeof(pt));
    memcpy(pt, nonce, nonce_len);
    if (EVP_EncryptUpdate(cfg->ctx, ct, &ct_len, pt, sizeof(pt)) !=
            1) {
        goto err;
    }
    if (ct_len != sizeof(pt)) {
        goto err;
    }
    for (i = 0; i < target_len; i++) {
        *(target + i) = ct[i] ^ target[i];
    }
    return ERR_OK;
err:
    return ERR_OTHER;
}

static void
quic_lb_scid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_scid_config *cfg = config;
    UINT8  *nonce = cid + 1, *sid = nonce + cfg->nonce_len,
           *extra = sid + cfg->sidl, *svr_use_ptr = server_use;

    if (cfg->nonce_ctr > ((1 << (cfg->nonce_len * 8)) - 1)) {
        /* Nonce is not big enough for unique CIDs */
        goto err;
    }
    if (cfg->encode_length) {
        *(UINT8 *)cid = cid_len - 1;
    } else {
        memcpy(cid, server_use, 1);
    }
    *(UINT8 *)cid &= 0x3f;
    *(UINT8 *)cid |= (cfg->cr << 6);
    svr_use_ptr++;
    memcpy(nonce, &cfg->nonce_ctr, cfg->nonce_len); /* Host order! */
    memcpy(sid, cfg->sid, cfg->sidl);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    cfg->nonce_ctr++;
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    if ((UINT8 *)cid + cid_len > extra) {
        memcpy(extra, server_use + 1, cid_len -
                (1 + cfg->nonce_len + cfg->sidl));
    }
    return;
err:
    /* Go to 5-tuple routing*/
    rndset(cid, RND_PSEUDO, cid_len);
    *(UINT8 *)cid &= 0xc0;
    return;
}

static err_t
quic_lb_scid_decrypt(void *cid, void *config, size_t *cid_len, UINT8 *sid)
{
    struct quic_lb_scid_config *cfg = config;
    UINT8 nonce[cfg->nonce_len];

    if (cfg->encode_length) {
        *cid_len = (*(UINT8 *)cid & 0x3f) + 1;
    }
    memcpy(nonce, cid + 1, cfg->nonce_len);
    memset(sid, 0, sizeof(sid));
    memcpy(sid, cid + 1 + cfg->nonce_len, cfg->sidl);
    /* 1st Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    /* 2nd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, sid, cfg->sidl, nonce,
            cfg->nonce_len) != ERR_OK) {
        goto err;
    }
    /* 3rd Pass */
    if (quic_lb_encrypt_apply_nonce(cfg, nonce, cfg->nonce_len, sid,
            cfg->sidl) != ERR_OK) {
        goto err;
    }
    return ERR_OK;
err:
    return ERR_OTHER;
}

static void
quic_lb_bcid_encrypt(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_bcid_config *cfg = config;
    UINT8 *ptr = cid, *svr_use_ptr = server_use;
    UINT8 block[16];
    int ct_len, i;

    *ptr = (cfg->cr << 6) | (cfg->encode_length ? (cid_len - 1) :
            ((*svr_use_ptr) & 0x3f));
    memcpy(&block[0], cfg->sid, cfg->sidl);
    memset(&block[cfg->sidl], 0, cfg->zp_len);
    svr_use_ptr++;
    for (i = cfg->sidl + cfg->zp_len; i < sizeof(block); i++) {
       block[i] = *svr_use_ptr;
       svr_use_ptr++;
    }
    if ((EVP_EncryptUpdate(cfg->ctx, ptr + 1, &ct_len, block, sizeof(block))
            != 1) || (ct_len != sizeof(block))) {
        goto err;
    }

    for (i = ct_len + 1; i < cid_len; i++) {
        *(ptr + i) = *svr_use_ptr;
        svr_use_ptr++;
    }
    return;
err:
    /* Go to 5-tuple routing*/
    *(UINT8 *)cid &= 0xc0;
    return;
}

static err_t
quic_lb_bcid_decrypt(void *cid, void *config, size_t *cid_len, UINT8 *sid)
{
    struct quic_lb_bcid_config *cfg = config;
    UINT8 *ptr = cid;
    UINT8 block[16];
    UINT8 zeroes[cfg->zp_len];
    int pt_len;

    if (cfg->encode_length) {
        *cid_len = (*(UINT8 *)cid & 0x3f) + 1;
    }
    memset(block, 0, sizeof(block)); // mhd;
    if ((EVP_DecryptUpdate(cfg->ctx, &block[0], &pt_len, ptr + 1,
            sizeof(block)) != 1) || (pt_len != sizeof(block))) {
        goto err;
    }
    memcpy(sid, block, cfg->sidl);
    memset(zeroes, 0, sizeof(zeroes));
    if (memcmp(&block[cfg->sidl], zeroes, cfg->zp_len) != 0) {
        goto err;
    }
    return ERR_OK;
err:
    return ERR_OTHER;
}

/* server_use MUST be of length cid_len */
void
quic_lb_encrypt_cid(void *cid, void *config, size_t cid_len, void *server_use)
{
    struct quic_lb_generic_config *generic;

    if (config == NULL) {
        rndset(cid, RND_PSEUDO, cid_len);
        *(UINT8 *)cid |= QUIC_LB_TUPLE_ROUTE;
        goto out;
    }
    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_SCID:
        quic_lb_scid_encrypt(cid, config, cid_len, server_use);
        break;
    case QUIC_LB_BCID:
        quic_lb_bcid_encrypt(cid, config, cid_len, server_use);
        break;
    }
out:
    return;
}

void
quic_lb_encrypt_cid_random(void *cid, void *config, size_t cid_len)
{
    UINT8 server_use[cid_len];

    rndset(server_use, RND_PSEUDO, sizeof(server_use));
    quic_lb_encrypt_cid(cid, config, cid_len, server_use);
}

err_t
quic_lb_decrypt_cid(void *cid, void *config, size_t *cid_len, void *sid)
{
    struct quic_lb_generic_config *generic;
    err_t  err = ERR_OTHER;

    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_SCID:
        err = quic_lb_scid_decrypt(cid, config, cid_len, sid);
        break;
    case QUIC_LB_BCID:
        err = quic_lb_bcid_decrypt(cid, config, cid_len, sid);
        break;
    }
    return err;
}

void *
quic_lb_load_scid_config(UINT8 cr, BOOL encode_len, UINT8 *key, UINT8 sidl,
        UINT8 nonce_len, UINT8 *sid)
{
    struct quic_lb_scid_config *cfg = umalloc(
            sizeof(struct quic_lb_scid_config), M_FILTER, UM_ZERO);

    if (cfg == NULL) {
        goto out;
    }
    if ((cr > 0x3) || (nonce_len < 8) || (nonce_len > 16) ||
            (nonce_len + sidl > QUIC_LB_USABLE_BYTES)) {
        ufree(cfg);
        cfg = NULL;
        goto out;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_SCID;
    cfg->nonce_len = nonce_len;
    cfg->sidl = sidl;
    memcpy(cfg->sid, sid, sidl);
    cfg->nonce_ctr = 0;
    cfg->ctx = EVP_CIPHER_CTX_new();
    /*
     * CTR mode just encrypts the nonce using AES-ECB and XORs it with
     * the plaintext or ciphertext. So for encrypt or decrypt, in this
     * case we're technically encrypting.
     */
    if (cfg->ctx == NULL) {
        ufree(cfg);
        cfg = NULL;
        goto out;
    }
    if (EVP_CipherInit_ex(cfg->ctx, EVP_aes_128_ecb(), NULL, key, NULL, 1)
            == 0) {
        EVP_CIPHER_CTX_free(cfg->ctx);
        ufree(cfg);
        cfg = NULL;
    }
out:
    return cfg;
}

void *
quic_lb_load_bcid_config(UINT8 cr, BOOL encode_len, UINT8 *key, UINT8 sidl,
        UINT8 zp_len, UINT8 *sid, BOOL encrypt)
{
    struct quic_lb_bcid_config *cfg = umalloc(
            sizeof(struct quic_lb_bcid_config), M_FILTER, UM_ZERO);

    if (cfg == NULL) {
        goto out;
    }
    cfg->ctx = NULL;
    if ((cr > 0x3) || (zp_len < 4) || (zp_len + sidl > 12)) {
        goto fail;
    }
    cfg->cr = cr;
    cfg->encode_length = encode_len;
    cfg->alg = QUIC_LB_BCID;
    cfg->zp_len = zp_len;
    cfg->sidl = sidl;
    memcpy(cfg->sid, sid, sidl);
    memcpy(cfg->key, key, sizeof(cfg->key));
    cfg->ctx = EVP_CIPHER_CTX_new();
    if (cfg->ctx == NULL) {
        goto fail;
    }
    if (EVP_CipherInit_ex(cfg->ctx, EVP_aes_128_ecb(), NULL, key, NULL,
            encrypt ? 1 : 0) == 0) {
        goto fail;
    }
    if (EVP_CIPHER_CTX_set_padding(cfg->ctx, 0) == 0) {
        goto fail;
    }
out:
    return cfg;
fail:
    if (cfg->ctx != NULL) {
        EVP_CIPHER_CTX_free(cfg->ctx);
    }
    ufree(cfg);
    return NULL;
}

void
quic_lb_free_config(void *config)
{
    struct quic_lb_generic_config *generic;
    EVP_CIPHER_CTX  *ctx;

    generic = (struct quic_lb_generic_config *)config;
    switch(generic->alg) {
    case QUIC_LB_SCID:
        ctx = ((struct quic_lb_scid_config *)config)->ctx;
        break;
    case QUIC_LB_BCID:
        ctx = ((struct quic_lb_bcid_config *)config)->ctx;
        break;
    }
    if (ctx != NULL) {
        EVP_CIPHER_CTX_free(ctx);
    }
out:
    return;
}
